import os
import re
import json
import uuid
import base64
import hashlib
import email
from email import policy
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid
import ipaddress
import threading
import html
from urllib.parse import urlencode, quote
import time
import requests
import dns.resolver
from flask import Flask, render_template, request, jsonify, redirect, session

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "").strip() or os.urandom(32).hex()

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "474486731193-h4beukvlb1l3ca5napbtnb2nvcti3bq0.apps.googleusercontent.com").strip()
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "").strip()
REDIRECT_URI = "https://aiemailthreat.onrender.com/auth/callback"

if not GOOGLE_CLIENT_SECRET:
    print("[CONFIG WARNING] GOOGLE_CLIENT_SECRET is not set. Add it to Render Environment Variables.")

CASES_FILE = "cases_cache.json"
ACCOUNTS_FILE = "accounts_cache.json"
SETTINGS_FILE = "settings_cache.json"
ALERTS_FILE = "sent_alerts_cache.json"
GRAPH_FILE = "correlation_graph_cache.json"
IOC_FILE = "ioc_watchlist.json"
ALERT_TEMPLATE_VERSION = "V4-ASCII"

CASES_DB = {}
MONITORED_ACCOUNTS = {}
SENT_ALERTS = set()

MONITOR_LOCK = threading.Lock()
ALERT_FILE_LOCK = threading.Lock()
PROCESSING_MESSAGES = set()

# Correlation/IOC state. These are lightweight prototype stores; they can be
# replaced by Neo4j/Redis/SIEM storage in a production deployment.
CORRELATION_LOCK = threading.Lock()
CORRELATION_GRAPH = {"nodes": [], "edges": []}


# -------------------------------------------------------------
# DISK PERSISTENCE ENGINE (ACCOUNTS, CASES & ALERTS)
# -------------------------------------------------------------

def load_cases_from_disk():
    if os.path.exists(CASES_FILE):
        try:
            with open(CASES_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_case_record(case_id, analysis_data):
    global CASES_DB
    CASES_DB[case_id] = analysis_data
    try:
        with open(CASES_FILE, "w", encoding="utf-8") as f:
            json.dump(CASES_DB, f)
    except Exception as e:
        print(f"Error persisting case {case_id}: {e}")

def load_monitored_accounts():
    if os.path.exists(ACCOUNTS_FILE):
        try:
            with open(ACCOUNTS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_monitored_account(email_addr, refresh_token):
    global MONITORED_ACCOUNTS
    MONITORED_ACCOUNTS[email_addr] = {"refresh_token": refresh_token}
    try:
        with open(ACCOUNTS_FILE, "w", encoding="utf-8") as f:
            json.dump(MONITORED_ACCOUNTS, f)
    except Exception as e:
        print(f"Error saving account {email_addr}: {e}")

def load_correlation_graph():
    global CORRELATION_GRAPH
    if os.path.exists(GRAPH_FILE):
        try:
            with open(GRAPH_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict) and isinstance(data.get("nodes"), list) and isinstance(data.get("edges"), list):
                    CORRELATION_GRAPH = data
        except Exception:
            pass
    return CORRELATION_GRAPH

def save_correlation_graph():
    try:
        with CORRELATION_LOCK:
            with open(GRAPH_FILE, "w", encoding="utf-8") as f:
                json.dump(CORRELATION_GRAPH, f, indent=2)
    except Exception as e:
        print(f"Error saving correlation graph: {e}")

def _upsert_graph_node(node_id, node_type, label=None, **extra):
    if not node_id:
        return
    node_id = str(node_id)
    with CORRELATION_LOCK:
        for node in CORRELATION_GRAPH["nodes"]:
            if node.get("id") == node_id:
                if label:
                    node["label"] = label
                node.update({k: v for k, v in extra.items() if v is not None})
                return
        node = {"id": node_id, "type": node_type, "label": label or node_id}
        node.update({k: v for k, v in extra.items() if v is not None})
        CORRELATION_GRAPH["nodes"].append(node)

def _upsert_graph_edge(source, target, relation):
    if not source or not target:
        return
    edge_key = (str(source), str(target), str(relation))
    with CORRELATION_LOCK:
        for edge in CORRELATION_GRAPH["edges"]:
            if (edge.get("source"), edge.get("target"), edge.get("relation")) == edge_key:
                edge["weight"] = int(edge.get("weight", 1)) + 1
                return
        CORRELATION_GRAPH["edges"].append({
            "source": str(source),
            "target": str(target),
            "relation": str(relation),
            "weight": 1
        })

def load_ioc_watchlist():
    """Load optional local IOC data. No external feed is assumed by default."""
    default = {"ips": [], "domains": [], "urls": []}
    try:
        env_data = os.environ.get("NEXORA_IOC_JSON", "").strip()
        if env_data:
            data = json.loads(env_data)
            if isinstance(data, dict):
                return {
                    "ips": [str(x).strip().lower() for x in data.get("ips", [])],
                    "domains": [str(x).strip().lower() for x in data.get("domains", [])],
                    "urls": [str(x).strip().lower() for x in data.get("urls", [])]
                }
    except Exception as e:
        print(f"IOC environment data ignored: {e}")
    if os.path.exists(IOC_FILE):
        try:
            with open(IOC_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return {
                        "ips": [str(x).strip().lower() for x in data.get("ips", [])],
                        "domains": [str(x).strip().lower() for x in data.get("domains", [])],
                        "urls": [str(x).strip().lower() for x in data.get("urls", [])]
                    }
        except Exception:
            pass
    return default

def domain_from_url(url_value):
    match = re.search(r"(?:https?://|www\.)([^/?:#\s]+)", str(url_value), re.IGNORECASE)
    return match.group(1).lower().strip('.') if match else ""

def run_domain_intelligence(domain, resolver):
    result = {"domain": domain or "", "a": [], "mx": [], "ns": [], "txt": []}
    if not domain:
        return result
    for record_type, key in (("A", "a"), ("MX", "mx"), ("NS", "ns"), ("TXT", "txt")):
        try:
            answers = resolver.resolve(domain, record_type)
            values = []
            for answer in answers:
                value = answer.to_text().strip('"')
                values.append(value[:250])
            result[key] = values[:10]
        except Exception:
            result[key] = []
    return result

def correlate_analysis(analysis):
    """Add graph/campaign/IOC intelligence to an already completed analysis."""
    global CORRELATION_GRAPH
    load_correlation_graph()
    iocs = load_ioc_watchlist()

    meta = analysis.get("metadata", {})
    sender = str(meta.get("from", ""))
    sender_match = re.search(r"@([\w.-]+)", sender)
    sender_domain = sender_match.group(1).lower() if sender_match else ""
    return_path = str(meta.get("return_path", ""))
    rp_match = re.search(r"@([\w.-]+)", return_path)
    return_domain = rp_match.group(1).lower() if rp_match else ""
    message_node = "email:" + hashlib.sha256(str(meta.get("message_id", meta.get("evidence_sha256", ""))).encode()).hexdigest()[:16]
    case_id = analysis.get("case_id", "")

    node_specs = [(message_node, "EMAIL", str(meta.get("subject", "(No Subject)"))[:80])]
    if sender_domain:
        node_specs.append(("domain:" + sender_domain, "DOMAIN", sender_domain))
    if return_domain and return_domain != sender_domain:
        node_specs.append(("domain:" + return_domain, "DOMAIN", return_domain))
    for ip in analysis.get("origin_investigation", {}).get("ip", ""),:
        if ip and ip not in ("127.0.0.1", "Unknown"):
            node_specs.append(("ip:" + str(ip), "IP", str(ip)))
    for hop in analysis.get("hops", []):
        for ip in hop.get("extracted_ips", [])[:4]:
            node_specs.append(("ip:" + str(ip), "IP", str(ip)))
    url_domains = []
    for url in analysis.get("urls", []):
        d = domain_from_url(url)
        if d:
            url_domains.append(d)
            node_specs.append(("domain:" + d, "DOMAIN", d))

    for nid, ntype, label in node_specs:
        _upsert_graph_node(nid, ntype, label)
    if sender_domain:
        _upsert_graph_edge(message_node, "domain:" + sender_domain, "SENDER_DOMAIN")
    if return_domain:
        _upsert_graph_edge(message_node, "domain:" + return_domain, "RETURN_PATH_DOMAIN")
    for nid, ntype, label in node_specs:
        if ntype == "IP":
            _upsert_graph_edge(message_node, nid, "RELAYED_THROUGH")
    for d in url_domains:
        _upsert_graph_edge(message_node, "domain:" + d, "LINKED_DOMAIN")

    # Find previously observed relationships for this email's entities.
    entity_ids = {nid for nid, _, _ in node_specs if not nid.startswith("email:")}
    related_cases = set()
    with CORRELATION_LOCK:
        graph_edges = list(CORRELATION_GRAPH["edges"])
    for edge in graph_edges:
        if edge.get("source") in entity_ids or edge.get("target") in entity_ids:
            other = edge.get("source") if edge.get("target") in entity_ids else edge.get("target")
            if other and str(other).startswith("email:") and other != message_node:
                related_cases.add(other)

    related_email_count = len(related_cases)
    campaign_id = None
    if related_email_count:
        campaign_id = "CAMP-" + hashlib.sha256("|".join(sorted(related_cases | {message_node})).encode()).hexdigest()[:8].upper()

    matched_iocs = {"ips": [], "domains": [], "urls": []}
    observed_ips = set()
    for hop in analysis.get("hops", []):
        observed_ips.update(str(x).lower() for x in hop.get("extracted_ips", []))
    origin_ip = str(analysis.get("origin_investigation", {}).get("ip", "")).lower()
    if origin_ip:
        observed_ips.add(origin_ip)
    for ip in observed_ips:
        if ip in set(iocs.get("ips", [])):
            matched_iocs["ips"].append(ip)
    observed_domains = set([sender_domain, return_domain] + url_domains) - {""}
    for d in observed_domains:
        if d in set(iocs.get("domains", [])):
            matched_iocs["domains"].append(d)
    for url in analysis.get("urls", []):
        if str(url).lower() in set(iocs.get("urls", [])):
            matched_iocs["urls"].append(url)

    correlation_reasons = []
    if related_email_count:
        correlation_reasons.append(f"Shared infrastructure indicators connect this email to {related_email_count} previously analysed email(s).")
    if matched_iocs["ips"] or matched_iocs["domains"] or matched_iocs["urls"]:
        correlation_reasons.append("One or more observed indicators matched the configured local IOC watchlist.")

    # Correlation is a prioritization signal, not proof of maliciousness or attribution.
    base_score = int(analysis.get("threat_assessment", {}).get("threat_score", 0))
    correlation_bonus = 0
    if related_email_count:
        correlation_bonus += min(10, related_email_count * 5)
    if matched_iocs["ips"] or matched_iocs["domains"] or matched_iocs["urls"]:
        correlation_bonus += 15
    if correlation_bonus:
        updated_score = min(100, base_score + correlation_bonus)
        assessment = analysis["threat_assessment"]
        assessment["threat_score"] = updated_score
        if updated_score >= 70:
            assessment["risk_tier"] = "CRITICAL RISK (IMPERSONATION / PHISHING)"
        elif updated_score >= 40:
            assessment["risk_tier"] = "ELEVATED RISK"
        else:
            assessment["risk_tier"] = "CLEAN / VERIFIED"
        assessment.setdefault("threat_reasons", []).append(
            f"Correlation Intelligence: +{correlation_bonus} prioritization points from related infrastructure/IOC matches."
        )

    # Infrastructure confidence describes evidence quality, not attacker identity.
    evidence_points = 0
    if analysis.get("hops"): evidence_points += 1
    if analysis.get("origin_investigation", {}).get("ip") not in (None, "", "Unknown", "127.0.0.1"): evidence_points += 1
    if analysis.get("dns_authentication", {}).get("spf"): evidence_points += 1
    if analysis.get("dns_authentication", {}).get("dmarc"): evidence_points += 1
    if related_email_count: evidence_points += 1
    confidence = "LOW" if evidence_points <= 1 else ("MEDIUM" if evidence_points <= 3 else "HIGH")

    analysis["correlation"] = {
        "graph_node_id": message_node,
        "related_email_count": related_email_count,
        "related_email_node_ids": sorted(related_cases),
        "campaign_id": campaign_id,
        "correlation_reasons": correlation_reasons,
        "ioc_matches": matched_iocs,
        "infrastructure_confidence": confidence,
        "attribution_status": "Infrastructure correlation support only; sender/threat-actor identity not established."
    }
    analysis["graph"] = {
        "nodes": [n for n in CORRELATION_GRAPH["nodes"] if n.get("id") == message_node or n.get("id") in entity_ids or n.get("id") in related_cases],
        "edges": [e for e in CORRELATION_GRAPH["edges"] if e.get("source") in ({message_node} | entity_ids | related_cases) or e.get("target") in ({message_node} | entity_ids | related_cases)]
    }
    save_correlation_graph()
    return analysis

def load_settings():
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_settings(settings_dict):
    try:
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(settings_dict, f)
    except Exception as e:
        print(f"Error saving settings: {e}")

def load_sent_alerts():
    if os.path.exists(ALERTS_FILE):
        try:
            with open(ALERTS_FILE, "r", encoding="utf-8") as f:
                return set(json.load(f))
        except Exception:
            return set()
    return set()

def record_alert_dispatched(identifier):
    global SENT_ALERTS
    clean_id = str(identifier).strip("<>").strip()
    if not clean_id:
        return

    with ALERT_FILE_LOCK:
        SENT_ALERTS.add(clean_id)
        try:
            tmp_file = f"{ALERTS_FILE}.tmp"
            with open(tmp_file, "w", encoding="utf-8") as f:
                json.dump(sorted(SENT_ALERTS), f)
            os.replace(tmp_file, ALERTS_FILE)
        except Exception as e:
            print(f"Error saving alert record: {e}")

CASES_DB = load_cases_from_disk()
MONITORED_ACCOUNTS = load_monitored_accounts()
SENT_ALERTS = load_sent_alerts()

BEC_URGENCY_PATTERNS = [
    r"\b(wire transfer|bank payment|invoice overdue|direct deposit|gift cards?|payout)\b",
    r"\b(verify password|update credentials|reset password|click here to verify)\b",
    r"\b(unauthorized login|compromised account|termination of access)\b",
    r"\b(ceo request|confidential payment|vendor bank details)\b"
]

KNOWN_DATACENTER_ORGS = [
    "m247", "ovh", "digitalocean", "linode", "tor", "datacamp", "hetzner", "vultr"
]

TRUSTED_ESP_DOMAINS = [
    "sendgrid.net", "mailgun.org", "exacttarget.com", "amazonses.com", 
    "hubspotemail.net", "salesforce.com", "zendesk.com", "mandrillapp.com"
]

# -------------------------------------------------------------
# 1. GMAIL API DISPATCH & LABEL ENGINE
# -------------------------------------------------------------

def get_or_create_soc_label(headers):
    try:
        res = requests.get("https://gmail.googleapis.com/gmail/v1/users/me/labels", headers=headers, timeout=5).json()
        labels = res.get("labels", [])
        for l in labels:
            if l.get("name") == "SOC-SCANNED":
                return l.get("id")

        create_res = requests.post(
            "https://gmail.googleapis.com/gmail/v1/users/me/labels",
            headers=headers,
            json={
                "name": "SOC-SCANNED",
                "labelListVisibility": "labelShow",
                "messageListVisibility": "show"
            },
            timeout=5
        ).json()
        return create_res.get("id")
    except Exception as e:
        print(f"Error managing SOC label: {e}")
        return None

def apply_soc_label_to_message(headers, msg_id, mark_as_read=False):
    try:
        label_id = get_or_create_soc_label(headers)
        body = {}
        if label_id:
            body["addLabelIds"] = [label_id]
        if mark_as_read:
            body["removeLabelIds"] = ["UNREAD"]
        if body:
            requests.post(
                f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg_id}/modify",
                headers=headers,
                json=body,
                timeout=5
            )
    except Exception as e:
        print(f"Error modifying message {msg_id}: {e}")

def sanitize_to_ascii(text):
    if not text:
        return ""
    return re.sub(r"[^\x20-\x7E]", "", str(text)).strip()

def dispatch_soc_alert_email(headers, recipient_email, case_id, analysis, unique_msg_id):
    """Send one clean, aesthetic SOC alert and permanently deduplicate it."""
    global SENT_ALERTS

    unique_msg_id = str(unique_msg_id).strip("<>").strip()
    unique_key = f"ALERT_SENT_{unique_msg_id}"

    # Fast duplicate check before any network call.
    with ALERT_FILE_LOCK:
        if unique_key in SENT_ALERTS or unique_msg_id in SENT_ALERTS:
            print(f"[ALERT] Duplicate suppressed for source message {unique_msg_id}")
            return False

    try:
        meta = analysis.get("metadata", {})
        threat = analysis.get("threat_assessment", {})
        origin = analysis.get("origin_investigation", {})
        dns_auth = analysis.get("dns_authentication", {})

        score = int(threat.get("threat_score", 0) or 0)
        risk_tier = sanitize_to_ascii(threat.get("risk_tier", "ELEVATED RISK")) or "ELEVATED RISK"

        accent_color = "#f43f5e" if score >= 70 else ("#f59e0b" if score >= 40 else "#10b981")
        badge_bg = "#2a1018" if score >= 70 else ("#2b210b" if score >= 40 else "#0b2a20")

        raw_subj = sanitize_to_ascii(meta.get("subject", "Untitled"))[:80]
        if not raw_subj:
            raw_subj = "Suspicious Message"

        # Clean ASCII subject line avoiding raw unicode characters that trigger question marks
        subject_line = f"[SOC ALERT] Threat Detected - {score}% Risk - Case #{case_id}"

        # Escape dynamic values
        e_subject = html.escape(raw_subj, quote=True)
        e_sender = html.escape(sanitize_to_ascii(meta.get("from", "Unknown")), quote=True)
        e_return = html.escape(sanitize_to_ascii(meta.get("return_path", "None")), quote=True)
        e_ip = html.escape(sanitize_to_ascii(origin.get("ip", "Unknown")), quote=True)
        e_city = html.escape(sanitize_to_ascii(origin.get("city", "Unknown")), quote=True)
        e_country = html.escape(sanitize_to_ascii(origin.get("country", "Unknown")), quote=True)
        e_node = html.escape(sanitize_to_ascii(origin.get("node_type", "Unknown")), quote=True)
        e_spf = html.escape(sanitize_to_ascii(dns_auth.get("spf", "Neutral"))[:30], quote=True)
        e_dmarc = html.escape(sanitize_to_ascii(dns_auth.get("dmarc", "None"))[:30], quote=True)
        e_risk = html.escape(risk_tier, quote=True)
        evidence = sanitize_to_ascii(meta.get("evidence_sha256", ""))
        if not evidence:
            evidence = hashlib.sha256(str(unique_msg_id).encode("utf-8")).hexdigest()
        e_evidence = html.escape(evidence, quote=True)
        e_case = html.escape(str(case_id), quote=True)

        reasons = threat.get("threat_reasons", []) or [
            "No high-confidence threat indicators were identified."
        ]
        reasons_items = []
        for reason in reasons[:8]:
            clean_reason = html.escape(sanitize_to_ascii(reason), quote=True)
            reasons_items.append(
                f'<li style="margin:0 0 8px 0;color:#cbd5e1;font-size:13px;line-height:1.55;">{clean_reason}</li>'
            )
        reasons_html = "".join(reasons_items)

        dashboard_url = f"https://aiemailthreat.onrender.com/?case={quote(str(case_id))}"

        # Beautified Email Template with Modern Cyber Theme & Clean Banner
        html_body = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Nexora Sentinel SOC Alert</title>
</head>
<body style="margin:0;padding:32px 16px;background:#030712;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#e5e7eb;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
    <tr><td align="center">
      <table role="presentation" width="620" cellspacing="0" cellpadding="0" border="0" style="width:100%;max-width:620px;background:#0b1220;border:1px solid #1e293b;border-radius:18px;overflow:hidden;box-shadow:0 20px 25px -5px rgba(0, 0, 0, 0.5);">
        
        <!-- Beautified Sleek Gradient Header Banner -->
        <tr>
          <td style="padding:32px 30px;background:linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%);border-bottom:1px solid #334155;text-align:left;">
            <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
              <tr>
                <td>
                  <div style="font-size:10px;font-weight:800;letter-spacing:2px;color:#38bdf8;text-transform:uppercase;margin-bottom:8px;">NEXORA SENTINEL &bull; SECURE SOC</div>
                  <div style="font-size:22px;font-weight:900;color:#ffffff;line-height:1.3;letter-spacing:-0.3px;">Automated Threat Intelligence Report</div>
                  <div style="font-size:12px;color:#94a3b8;margin-top:6px;">Zero-detonation email telemetry analysis</div>
                </td>
                <td align="right" style="vertical-align:top;">
                  <div style="background:rgba(56, 189, 248, 0.1);border:1px solid rgba(56, 189, 248, 0.3);color:#38bdf8;font-size:11px;font-weight:bold;padding:6px 12px;border-radius:20px;display:inline-block;">SIH26106</div>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- Risk Metrics Overview Block -->
        <tr>
          <td style="padding:24px 30px 10px 30px;background:#070d1a;">
            <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
              <tr>
                <td width="42%" style="padding:18px;background:#0f172a;border:1px solid #1e293b;border-radius:12px;">
                  <div style="font-size:10px;font-weight:bold;color:#64748b;text-transform:uppercase;letter-spacing:1px;">Threat Score</div>
                  <div style="font-size:38px;font-weight:900;color:{accent_color};margin-top:4px;letter-spacing:-1px;">{score}%</div>
                </td>
                <td width="4%"></td>
                <td width="54%" style="padding:18px;background:#0f172a;border:1px solid #1e293b;border-radius:12px;vertical-align:top;">
                  <div style="font-size:10px;font-weight:bold;color:#64748b;text-transform:uppercase;letter-spacing:1px;">Risk Verdict</div>
                  <div style="margin-top:8px;display:inline-block;padding:6px 12px;border-radius:8px;background:{badge_bg};border:1px solid {accent_color};color:{accent_color};font-size:11px;font-weight:bold;letter-spacing:0.5px;">{e_risk}</div>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- Message Metadata Box -->
        <tr>
          <td style="padding:10px 30px 20px 30px;background:#070d1a;">
            <div style="padding:18px;background:#0f172a;border:1px solid #1e293b;border-radius:12px;">
              <div style="font-size:11px;font-weight:bold;color:#38bdf8;text-transform:uppercase;letter-spacing:1px;margin-bottom:12px;">Message Telemetry Details</div>
              <table role="presentation" width="100%" cellspacing="0" cellpadding="6" border="0" style="font-size:12px;">
                <tr><td width="30%" style="color:#64748b;font-weight:bold;">Case ID</td><td style="color:#f8fafc;font-family:monospace;font-weight:bold;">#{e_case}</td></tr>
                <tr><td style="color:#64748b;font-weight:bold;">Subject</td><td style="color:#e2e8f0;">{e_subject}</td></tr>
                <tr><td style="color:#64748b;font-weight:bold;">Claimed Sender</td><td style="color:#cbd5e1;font-family:monospace;word-break:break-word;">{e_sender}</td></tr>
                <tr><td style="color:#64748b;font-weight:bold;">Return-Path</td><td style="color:#fda4af;font-family:monospace;word-break:break-word;">{e_return}</td></tr>
                <tr><td style="color:#64748b;font-weight:bold;">Origin MTA</td><td style="color:#38bdf8;font-family:monospace;">{e_ip} | {e_city}, {e_country}</td></tr>
                <tr><td style="color:#64748b;font-weight:bold;">Node Type</td><td style="color:#e2e8f0;">{e_node}</td></tr>
                <tr><td style="color:#64748b;font-weight:bold;">Authentication</td><td style="color:#cbd5e1;">SPF: <b style="color:#38bdf8;">{e_spf}</b> | DMARC: <b style="color:#e2e8f0;">{e_dmarc}</b></td></tr>
              </table>
            </div>
          </td>
        </tr>

        <!-- Threat Indicators Box -->
        <tr>
          <td style="padding:0 30px 20px 30px;background:#070d1a;">
            <div style="padding:18px;background:#0f172a;border:1px solid #1e293b;border-radius:12px;">
              <div style="font-size:11px;font-weight:bold;color:#f59e0b;text-transform:uppercase;letter-spacing:1px;margin-bottom:12px;">Detected Risk Indicators</div>
              <ul style="margin:0;padding-left:18px;">{reasons_html}</ul>
            </div>
          </td>
        </tr>

        <!-- Digital Evidence Record Box -->
        <tr>
          <td style="padding:0 30px 24px 30px;background:#070d1a;">
            <div style="padding:16px;background:#030712;border:1px dashed #334155;border-radius:10px;">
              <div style="font-size:10px;font-weight:bold;color:#10b981;letter-spacing:1px;text-transform:uppercase;">BSA Electronic Evidence Seal (Sec 65B)</div>
              <div style="font-size:10px;color:#94a3b8;margin-top:6px;line-height:1.5;word-break:break-all;font-family:monospace;">SHA-256: {e_evidence}</div>
            </div>
          </td>
        </tr>

        <!-- Action Button -->
        <tr>
          <td align="center" style="padding:0 30px 32px 30px;background:#070d1a;">
            <a href="{dashboard_url}" target="_blank" style="display:inline-block;padding:14px 28px;background:linear-gradient(135deg, #2563eb 0%, #4f46e5 100%);border-radius:10px;color:#ffffff;text-decoration:none;font-size:13px;font-weight:bold;box-shadow:0 4px 12px rgba(37, 99, 235, 0.4);">Open Forensic Case Dashboard</a>
          </td>
        </tr>

        <!-- Footer -->
        <tr>
          <td style="padding:20px 30px;background:#030712;border-top:1px solid #1e293b;text-align:center;">
            <div style="font-size:10px;color:#64748b;line-height:1.6;">Generated automatically by Nexora Sentinel SOC Daemon.</div>
            <div style="font-size:10px;color:#475569;margin-top:4px;">Secure Incident Reference: #{e_case}</div>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>
</body>
</html>"""

        msg = MIMEMultipart("alternative")
        msg["To"] = recipient_email
        msg["From"] = f"Nexora Threat Desk <{recipient_email}>"
        msg["Reply-To"] = recipient_email
        msg["Subject"] = subject_line
        msg["X-Nexora-Sentinel"] = "alert"
        msg["X-Nexora-Alert-ID"] = unique_msg_id[:120]
        msg["Date"] = formatdate(localtime=True)
        gen_id = make_msgid(domain="nexora.sentinel")
        msg["Message-ID"] = gen_id

        plain_text = (
            f"NEXORA SENTINEL SOC ALERT\n"
            f"Case ID: #{case_id}\n"
            f"Threat Score: {score}%\n"
            f"Risk: {risk_tier}\n"
            f"Subject: {raw_subj}\n"
            f"Dashboard: {dashboard_url}\n"
        )
        msg.attach(MIMEText(plain_text, "plain", "utf-8"))
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        raw_msg = base64.urlsafe_b64encode(msg.as_bytes()).decode("ascii")

        res = requests.post(
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
            headers=headers,
            json={"raw": raw_msg},
            timeout=10,
        )

        if res.status_code == 200:
            data = res.json()
            new_id = data.get("id")

            record_alert_dispatched(unique_msg_id)
            record_alert_dispatched(unique_key)
            record_alert_dispatched(str(gen_id))

            if new_id:
                record_alert_dispatched(new_id)
                record_alert_dispatched(f"ALERT_SENT_{new_id}")
                apply_soc_label_to_message(headers, new_id, mark_as_read=True)

            # Also persist the source message as dispatched ONLY after Gmail
            # accepted the alert. This prevents a successful alert from being
            # sent again on a later monitor cycle.
            record_alert_dispatched(unique_msg_id)
            record_alert_dispatched(unique_key)

            print(f"[SUCCESS] Dispatched SOC alert for Case #{case_id} to {recipient_email}")
            return True

        print(f"[FAILED] Gmail Send API: {res.status_code} - {res.text}")
        return False

    except Exception as e:
        print(f"[ERROR] dispatch_soc_alert_email: {e}")
        return False

# -------------------------------------------------------------
# 2. FORENSIC & IP INTELLIGENCE ENGINES
# -------------------------------------------------------------

def get_base_domain(domain_str: str) -> str:
    parts = domain_str.strip().lower().split('.')
    if len(parts) >= 2:
        return f"{parts[-2]}.{parts[-1]}"
    return domain_str.lower()

def extract_email_body_text(msg):
    text_content = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            cdispo = str(part.get('Content-Disposition'))
            if 'attachment' not in cdispo and ctype in ['text/plain', 'text/html']:
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        text_content.append(payload.decode('utf-8', errors='ignore'))
                except Exception:
                    pass
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                text_content.append(payload.decode('utf-8', errors='ignore'))
            else:
                text_content.append(str(msg.get_payload()))
        except Exception:
            text_content.append(str(msg.get_payload()))

    return "\n".join(text_content)

def normalize_email_text(text_value):
    """Convert HTML email content to readable text and normalize whitespace."""
    if not text_value:
        return ""
    value = str(text_value)
    value = re.sub(r"(?is)<(script|style).*?>.*?</\\1>", " ", value)
    value = re.sub(r"(?i)<br\\s*/?>", "\n", value)
    value = re.sub(r"(?i)</(p|div|li|tr|h[1-6])\\s*>", "\n", value)
    value = re.sub(r"(?s)<[^>]+>", " ", value)
    value = html.unescape(value)
    return re.sub(r"\\s+", " ", value).strip()
def get_ip_intelligence(ip_address: str):
    if not ip_address or ip_address in ["127.0.0.1", "localhost"]:
        return {
            "ip": ip_address,
            "country": "Local Relay",
            "city": "Internal",
            "lat": 0.0,
            "lon": 0.0,
            "maps_url": "https://maps.google.com",
            "isp": "Private Loopback",
            "org": "Internal",
            "asn": "AS0",
            "is_anonymized": False,
            "node_type": "Internal / RFC-1918"
        }
    try:
        url = f"http://ip-api.com/json/{ip_address}?fields=status,country,city,lat,lon,isp,org,as,hosting,proxy,query"
        res = requests.get(url, timeout=2.5).json()
        if res.get("status") == "success":
            isp_org_str = f"{res.get('isp', '')} {res.get('org', '')} {res.get('as', '')}".lower()
            trusted_providers = ["google", "microsoft", "amazon", "cloudflare", "yahoo", "sendgrid", "mailgun"]
            is_trusted = any(p in isp_org_str for p in trusted_providers)
            is_vpn_dc = (res.get("hosting", False) or res.get("proxy", False) or any(k in isp_org_str for k in KNOWN_DATACENTER_ORGS)) and not is_trusted

            lat = res.get("lat", 0.0)
            lon = res.get("lon", 0.0)
            maps_url = f"https://www.google.com/maps/search/?api=1&query={lat},{lon}"

            return {
                "ip": res.get("query"),
                "country": res.get("country", "Unknown"),
                "city": res.get("city", "Unknown"),
                "lat": lat,
                "lon": lon,
                "maps_url": maps_url,
                "isp": res.get("isp", "Unknown"),
                "org": res.get("org", "Unknown"),
                "asn": res.get("as", "Unknown"),
                "is_anonymized": is_vpn_dc,
                "node_type": "Data Center / VPN Relay" if is_vpn_dc else ("Corporate Cloud Mailbox" if is_trusted else "Residential / ISP")
            }
    except Exception:
        pass
    return {
        "ip": ip_address,
        "country": "Unknown",
        "city": "Unknown",
        "lat": 0.0,
        "lon": 0.0,
        "maps_url": f"https://www.google.com/maps/search/?api=1&query={ip_address}",
        "isp": "Unknown",
        "org": "Unknown",
        "asn": "Unknown",
        "is_anonymized": False,
        "node_type": "Unresolved Relay"
    }

def analyze_email_forensics(raw_bytes: bytes):
    sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
    msg = email.message_from_bytes(raw_bytes, policy=policy.default)

    sender = str(msg.get('From', 'Unknown'))
    return_path = str(msg.get('Return-Path', 'Unknown'))
    subject = str(msg.get('Subject', '(No Subject)'))
    date_header = str(msg.get('Date', 'Unknown'))
    message_id = str(msg.get('Message-ID', 'None'))

    domain_match = re.search(r"@([\w.-]+)", sender)
    sender_domain = domain_match.group(1).strip(">").lower() if domain_match else ""

    return_path_match = re.search(r"@([\w.-]+)", return_path)
    return_path_domain = return_path_match.group(1).strip(">").lower() if return_path_match else ""

    sender_base = get_base_domain(sender_domain)
    return_base = get_base_domain(return_path_domain)

    is_trusted_esp = any(esp in return_path_domain for esp in TRUSTED_ESP_DOMAINS)

    is_spoofed_sender = False
    if sender_domain and return_path_domain:
        if (sender_base != return_base) and not is_trusted_esp:
            is_spoofed_sender = True

    received_headers = msg.get_all('Received', [])
    hops = []
    discovered_ips = []

    for idx, hop_str in enumerate(received_headers):
        ips = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", str(hop_str))
        public_ips = []
        for ip in ips:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local):
                    public_ips.append(ip)
            except ValueError:
                continue

        discovered_ips.extend(public_ips)
        geo = get_ip_intelligence(public_ips[0]) if public_ips else None
        hops.append({
            "hop_index": idx + 1,
            "raw": str(hop_str).strip()[:110] + "...",
            "extracted_ips": public_ips,
            "geo": geo
        })

    origin_geo = None
    if discovered_ips:
        origin_geo = get_ip_intelligence(discovered_ips[-1])

    spf_status = "Not Configured / SoftFail"
    dmarc_status = "Missing DMARC Policy"
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 2.0

    if sender_domain:
        for d in [sender_domain, sender_base]:
            try:
                txt_records = resolver.resolve(d, 'TXT')
                for txt in txt_records:
                    txt_str = txt.to_text()
                    if "v=spf1" in txt_str:
                        spf_status = f"Configured ({txt_str[:25]}...)"
                        break
                if "Configured" in spf_status:
                    break
            except Exception:
                pass

        if "Configured" not in spf_status:
            spf_status = "Lookup Neutral"

        for d in [f"_dmarc.{sender_domain}", f"_dmarc.{sender_base}"]:
            try:
                dmarc_records = resolver.resolve(d, 'TXT')
                for txt in dmarc_records:
                    txt_str = txt.to_text()
                    if "v=DMARC1" in txt_str:
                        if "p=reject" in txt_str:
                            dmarc_status = "p=reject (Enforced / Protected)"
                        elif "p=quarantine" in txt_str:
                            dmarc_status = "p=quarantine (Strict)"
                        else:
                            dmarc_status = "p=none (Monitoring Policy)"
                        break
                if "p=" in dmarc_status:
                    break
            except Exception:
                pass

    dkim_header = str(msg.get("DKIM-Signature", "")).strip()
    dkim_status = "Present (signature header observed)" if dkim_header else "Not observed"
    domain_intelligence = run_domain_intelligence(sender_domain, resolver) if sender_domain else {"domain": "", "a": [], "mx": [], "ns": [], "txt": []}

    body_content = extract_email_body_text(msg)
    normalized_subject = normalize_email_text(subject)
    normalized_body = normalize_email_text(body_content)
    full_text_to_scan = f"{normalized_subject}\n{normalized_body}".strip()
    scan_text = full_text_to_scan.lower()

    found_cues = []
    for pattern in BEC_URGENCY_PATTERNS:
        matches = re.findall(pattern, full_text_to_scan, re.IGNORECASE)
        if matches:
            found_cues.extend(matches)

    extracted_urls = re.findall(r"https?://[^\s<>\"')]+|www\.[^\s<>\"')]+", body_content, re.IGNORECASE)
    threat_score = 0
    threat_reasons = []

    if is_spoofed_sender:
        threat_score += 45
        threat_reasons.append(f"Domain Spoofing: 'From' header ({sender_domain}) does not match Return-Path ({return_path_domain}).")

    if "Missing" in dmarc_status and sender_base not in ["google.com", "microsoft.com", "apple.com", "amazon.com", "github.com", "openai.com"]:
        threat_score += 20
        threat_reasons.append("Unenforced DMARC Policy: Domain allows inbound impersonation.")

    if origin_geo and origin_geo.get("is_anonymized") and not is_trusted_esp:
        threat_score += 25
        threat_reasons.append(f"Anonymized Sending Node: Origin IP belongs to {origin_geo.get('isp', 'Unknown')} (Datacenter / VPN).")

    cue_groups = {
        "executive_impersonation": (15, "Executive impersonation language", [r"\bceo\b", r"\bchief executive\b", r"\bexecutive office\b", r"\bmanaging director\b", r"\bdirector\b", r"\bfrom the ceo\b"]),
        "payment_fraud": (15, "Payment / bank-transfer pressure", [r"\bwire transfer\b", r"\bbank payment\b", r"\bvendor payment\b", r"\bpayment\b", r"\btransfer\b", r"\bbank details\b", r"\baccount details\b"]),
        "urgency_pressure": (10, "Artificial urgency / time pressure", [r"\burgent\b", r"\bimmediately\b", r"\bas soon as possible\b", r"\btoday\b", r"\btime[- ]sensitive\b", r"\baction required\b", r"\bwithin \d+ (?:minutes?|hours?|days?)\b"]),
        "confidentiality_pressure": (10, "Confidentiality / secrecy pressure", [r"\bconfidential\b", r"\bdo not discuss\b", r"\bdo not share\b", r"\bkeep this private\b", r"\bdo not tell\b"]),
        "invoice_pressure": (10, "Invoice / accounts-payable pressure", [r"\binvoice\b", r"\boverdue\b", r"\boutstanding invoice\b", r"\baccounts payable\b", r"\baccounts department\b"]),
        "account_compromise": (15, "Account-compromise / credential-verification language", [r"\bunauthorized login\b", r"\bcompromised account\b", r"\bverify your password\b", r"\bverify your account\b", r"\bupdate credentials\b", r"\breset password\b"]),
    }

    matched_categories = []
    for category, (weight, label, patterns) in cue_groups.items():
        if any(re.search(pattern, scan_text, re.IGNORECASE) for pattern in patterns):
            matched_categories.append(category)
            threat_score += weight
            threat_reasons.append(f"Linkless Threat Indicator: {label} (+{weight}).")

    if len(matched_categories) >= 3:
        threat_reasons.append(f"Multi-Vector Linkless BEC Pattern: {len(matched_categories)} independent social-engineering categories detected.")

    if found_cues and not matched_categories:
        nlp_penalty = 30 if len(set(found_cues)) >= 2 else 15
        threat_score += nlp_penalty
        threat_reasons.append(f"Social Engineering Threat Cues: Detected keywords ({', '.join(sorted(set(found_cues)))}) .")

    if extracted_urls and (found_cues or matched_categories):
        threat_score += 25
        threat_reasons.append(f"Suspicious Embedded URLs: Discovered {len(extracted_urls)} link(s) combined with high-pressure cues.")
    elif extracted_urls and is_spoofed_sender:
        threat_score += 20
        threat_reasons.append("Unauthenticated links inside spoofed sender envelope.")

    threat_score = min(threat_score, 100)
    if not threat_reasons:
        threat_reasons.append("No high-confidence threat indicators were identified.")

    result = {
        "metadata": {
            "subject": subject,
            "from": sender,
            "return_path": return_path,
            "date": date_header,
            "message_id": message_id,
            "evidence_sha256": sha256_hash
        },
        "threat_assessment": {
            "threat_score": threat_score,
            "risk_tier": "CRITICAL RISK (IMPERSONATION / PHISHING)" if threat_score >= 70 else ("ELEVATED RISK" if threat_score >= 40 else "CLEAN / VERIFIED"),
            "threat_reasons": threat_reasons
        },
        "dns_authentication": {
            "spf": spf_status,
            "dmarc": dmarc_status,
            "dkim": dkim_status
        },
        "domain_intelligence": domain_intelligence,
        "origin_investigation": origin_geo or {"ip": "127.0.0.1", "country": "Unknown", "city": "Unknown", "lat": 0.0, "lon": 0.0, "maps_url": "https://maps.google.com", "isp": "Unknown", "node_type": "Unknown"},
        "hops": hops,
        "urls": extracted_urls,
        "social_engineering_cues": list(set(found_cues))
    }

    return correlate_analysis(result)

# -------------------------------------------------------------
# 3. 24/7 BACKGROUND MONITORING WORKER (RECURSION-PROOF)
# -------------------------------------------------------------

def refresh_google_token(refresh_token):
    token_url = "https://oauth2.googleapis.com/token"
    token_data = {
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token"
    }
    try:
        res = requests.post(token_url, data=token_data, timeout=10).json()
        return res.get("access_token")
    except Exception:
        return None

def _background_threat_monitor():
    global MONITORED_ACCOUNTS, SENT_ALERTS, PROCESSING_MESSAGES

    if not MONITORED_ACCOUNTS:
        MONITORED_ACCOUNTS = load_monitored_accounts()

    settings = load_settings()
    configured_soc_email = settings.get("soc_email", "").strip()

    for email_addr, creds in list(MONITORED_ACCOUNTS.items()):
        try:
            refresh_token = creds.get("refresh_token")
            if not refresh_token:
                continue

            token = refresh_google_token(refresh_token)
            if not token:
                continue

            headers = {"Authorization": f"Bearer {token}"}

            # Relaxed query to safely discover unread threat messages without missing them
            query = 'is:unread -label:SOC-SCANNED (in:inbox OR in:spam)'
            list_url = (
                "https://gmail.googleapis.com/gmail/v1/users/me/messages?"
                + urlencode({"q": query, "includeSpamTrash": "true", "maxResults": "10"})
            )

            res = requests.get(list_url, headers=headers, timeout=10)
            if res.status_code != 200:
                continue

            messages = res.json().get("messages", [])

            for m in messages:
                msg_id = str(m.get("id", "")).strip()
                if not msg_id:
                    continue

                with ALERT_FILE_LOCK:
                    if msg_id in SENT_ALERTS or f"ALERT_SENT_{msg_id}" in SENT_ALERTS or msg_id in PROCESSING_MESSAGES:
                        continue
                    PROCESSING_MESSAGES.add(msg_id)

                try:
                    meta_url = (
                        f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{quote(msg_id)}"
                        "?format=metadata"
                        "&metadataHeaders=Subject"
                        "&metadataHeaders=From"
                        "&metadataHeaders=Message-ID"
                        "&metadataHeaders=X-Nexora-Sentinel"
                        "&metadataHeaders=X-Nexora-Alert-ID"
                    )
                    meta_res = requests.get(meta_url, headers=headers, timeout=5)
                    if meta_res.status_code != 200:
                        continue

                    meta_data = meta_res.json()
                    h_list = meta_data.get("payload", {}).get("headers", [])
                    header_map = {
                        h.get("name", "").lower(): h.get("value", "")
                        for h in h_list
                    }

                    subj = header_map.get("subject", "")
                    sndr = header_map.get("from", "").lower()
                    msg_uuid = header_map.get("message-id", "").strip("<>")
                    is_nexora_header = header_map.get("x-nexora-sentinel", "").strip().lower()
                    alert_id = header_map.get("x-nexora-alert-id", "").strip("<>").strip()
                    snippet = str(meta_data.get("snippet", "")).lower()
                    clean_subj = sanitize_to_ascii(subj).lower()

                    # ---------------------------------------------------------
                    # ABSOLUTE SOC-ALERT LOOP BREAKER
                    # ---------------------------------------------------------
                    # Our own SOC alert is a newly generated Gmail message, so it
                    # must NEVER enter forensic scoring. Otherwise its headers can
                    # look suspicious and it may be classified as spoofed/BEC,
                    # causing an alert -> alert -> alert loop.
                    #
                    # Check explicit Nexora markers FIRST, before fetching/parsing
                    # the raw message or calculating a threat score.
                    source_sender = sndr.strip().lower()
                    source_from_matches_mailbox = (
                        bool(email_addr)
                        and email_addr.lower() in source_sender
                    )
                    source_is_self_sent = source_sender.startswith(
                        f"{email_addr.lower()} "
                    ) or f"<{email_addr.lower()}>" in source_sender

                    self_markers = (
                        is_nexora_header == "alert"
                        or bool(alert_id)
                        or "[soc alert]" in clean_subj
                        or "soc incident alert" in clean_subj
                        or "threat detected" in clean_subj
                        or "nexora sentinel" in clean_subj
                        or "ai threat sentinel" in clean_subj
                        or "nexora sentinel" in snippet
                        or "incident dispatch" in snippet
                        or "open forensic case dashboard" in snippet
                        or "nexora.sentinel" in msg_uuid.lower()
                        or msg_uuid in SENT_ALERTS
                        or alert_id in SENT_ALERTS
                        or source_is_self_sent
                        or source_from_matches_mailbox
                    )

                    if self_markers:
                        print(
                            f"[LOOP-BREAKER] Ignoring Nexora/self-generated message "
                            f"{msg_id} | subject={subj[:100]!r}"
                        )
                        apply_soc_label_to_message(
                            headers, msg_id, mark_as_read=True
                        )
                        record_alert_dispatched(msg_id)
                        record_alert_dispatched(f"ALERT_SENT_{msg_id}")
                        if msg_uuid:
                            record_alert_dispatched(msg_uuid)
                        if alert_id:
                            record_alert_dispatched(alert_id)
                        continue

                    raw_url = f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{quote(msg_id)}?format=raw"
                    raw_res = requests.get(raw_url, headers=headers, timeout=10)
                    if raw_res.status_code != 200:
                        continue

                    raw_base64 = raw_res.json().get("raw", "")
                    if not raw_base64:
                        continue

                    raw_bytes = base64.urlsafe_b64decode(raw_base64.encode("ascii"))

                    # Second loop-protection layer: never score an email that was
                    # generated by this Sentinel instance.
                    raw_lower = raw_bytes.decode("utf-8", errors="ignore").lower()
                    raw_self_markers = (
                        "x-nexora-sentinel: alert" in raw_lower
                        or "x-nexora-alert-id:" in raw_lower
                        or "nexora.sentinel" in raw_lower
                        or "open forensic case dashboard" in raw_lower
                    )
                    if raw_self_markers:
                        print(
                            f"[LOOP-BREAKER] Raw-message marker detected; "
                            f"skipping forensic analysis for {msg_id}"
                        )
                        apply_soc_label_to_message(
                            headers, msg_id, mark_as_read=True
                        )
                        record_alert_dispatched(msg_id)
                        record_alert_dispatched(f"ALERT_SENT_{msg_id}")
                        continue

                    analysis = analyze_email_forensics(raw_bytes)
                    threat_score = int(analysis["threat_assessment"]["threat_score"])
                    print(f"[SCAN] {msg_id}: threat_score={threat_score}%")

                    # Mark the source email as scanned, but DO NOT add its ID to
                    # SENT_ALERTS yet. dispatch_soc_alert_email() uses that set as
                    # its duplicate-send guard. Adding msg_id here would cause the
                    # dispatcher to immediately return False every time.
                    apply_soc_label_to_message(headers, msg_id, mark_as_read=False)

                    target_email = email_addr
                    if configured_soc_email and configured_soc_email != "CONNECTED_MAILBOX" and "@" in configured_soc_email:
                        target_email = configured_soc_email

                    if threat_score >= 40:
                        case_id = str(uuid.uuid4())[:8]
                        save_case_record(case_id, analysis)

                        sent = dispatch_soc_alert_email(
                            headers,
                            target_email,
                            case_id,
                            analysis,
                            msg_id
                        )

                        if sent:
                            print(f"[ALERT] SOC alert successfully sent for source message {msg_id}")
                        else:
                            print(f"[ALERT] SOC alert was not sent for source message {msg_id}")
                    else:
                        # Only record non-alert messages as processed here.
                        record_alert_dispatched(msg_id)
                        if msg_uuid:
                            record_alert_dispatched(msg_uuid)

                finally:
                    with ALERT_FILE_LOCK:
                        PROCESSING_MESSAGES.discard(msg_id)

        except Exception as e:
            print(f"Monitor loop error for {email_addr}: {e}")


def background_threat_monitor():
    if not MONITOR_LOCK.acquire(blocking=False):
        return
    try:
        _background_threat_monitor()
    finally:
        MONITOR_LOCK.release()


def background_threat_worker_loop():
    while True:
        try:
            background_threat_monitor()
        except Exception as e:
            print(f"Background worker loop error: {e}")
        time.sleep(45)


bg_thread = threading.Thread(
    target=background_threat_worker_loop,
    name="nexora-soc-monitor",
    daemon=True,
)
bg_thread.start()

# -------------------------------------------------------------
# 4. HTTP ROUTES & API ENDPOINTS
# -------------------------------------------------------------

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/auth/login')
def auth_login():
    if not GOOGLE_CLIENT_ID:
        return "<h3 style='color:red;font-family:sans-serif;'>OAuth Error: GOOGLE_CLIENT_ID is not configured.</h3>", 400

    scope = " ".join([
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/gmail.modify",
        "https://www.googleapis.com/auth/gmail.labels",
        "https://www.googleapis.com/auth/gmail.send",
    ])

    auth_url = "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode({
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": scope,
        "access_type": "offline",
        "prompt": "consent select_account",
    })
    return redirect(auth_url)

@app.route('/auth/callback')
def auth_callback():
    code = request.args.get('code')
    error = request.args.get('error')

    if error:
        return f"<h3 style='color:red;font-family:sans-serif;'>Google Authorization Refused: {error}</h3>", 400
    if not code:
        return "<h3 style='color:red;font-family:sans-serif;'>Error: No authorization code received from Google.</h3>", 400

    token_url = "https://oauth2.googleapis.com/token"
    token_data = {
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code"
    }

    token_res = requests.post(token_url, data=token_data, timeout=10).json()
    access_token = token_res.get("access_token")
    refresh_token = token_res.get("refresh_token")

    if not access_token:
        return f"<h3 style='color:red;font-family:sans-serif;'>Token Exchange Failed:</h3><pre>{token_res}</pre>", 400

    session['access_token'] = access_token
    headers = {"Authorization": f"Bearer {access_token}"}

    get_or_create_soc_label(headers)

    user_email = "connected_user"
    try:
        profile_res = requests.get("https://gmail.googleapis.com/gmail/v1/users/me/profile", headers=headers, timeout=5).json()
        user_email = profile_res.get("emailAddress", "connected_user")
    except Exception:
        pass

    session['user_email'] = user_email

    if "@" in user_email:
        save_settings({"soc_email": user_email})

    if refresh_token:
        save_monitored_account(user_email, refresh_token)

    list_url = 'https://gmail.googleapis.com/gmail/v1/users/me/messages?' + urlencode({'maxResults': '10', 'q': 'in:inbox -subject:"[SOC ALERT]"'})
    list_res = requests.get(list_url, headers=headers, timeout=10).json()
    messages_summary = list_res.get("messages", [])

    if not messages_summary:
        return redirect("/?case=c66930bf&msg=inbox_empty")

    inbox_list = []
    for m in messages_summary:
        try:
            msg_meta = requests.get(
                f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{quote(m['id'])}?format=metadata&metadataHeaders=Subject&metadataHeaders=From&metadataHeaders=Date",
                headers=headers,
                timeout=3
            ).json()

            headers_list = msg_meta.get("payload", {}).get("headers", [])
            subject = next((h["value"] for h in headers_list if h["name"].lower() == "subject"), "(No Subject)")
            sender = next((h["value"] for h in headers_list if h["name"].lower() == "from"), "Unknown Sender")
            date_str = next((h["value"] for h in headers_list if h["name"].lower() == "date"), "")
            snippet = msg_meta.get("snippet", "")

            if "[SOC ALERT" in subject or "Security alert" in subject:
                continue

            is_suspicious = any(re.search(pat, f"{subject} {snippet}", re.IGNORECASE) for pat in BEC_URGENCY_PATTERNS)

            inbox_list.append({
                "id": m["id"],
                "subject": subject,
                "from": sender,
                "date": date_str,
                "snippet": snippet,
                "threat_preview": "CRITICAL" if is_suspicious else "CLEAN"
            })
        except Exception:
            continue

    session['inbox_list'] = inbox_list
    return redirect("/?view=inbox_select")

@app.route('/api/refresh_inbox')
def refresh_inbox():
    access_token = session.get('access_token')
    if not access_token:
        return jsonify({"error": "No active session"}), 401

    headers = {"Authorization": f"Bearer {access_token}"}
    try:
        list_url = 'https://gmail.googleapis.com/gmail/v1/users/me/messages?' + urlencode({'maxResults': '10', 'q': 'in:inbox -subject:"[SOC ALERT]"'})
        list_res = requests.get(list_url, headers=headers, timeout=10).json()
        messages_summary = list_res.get("messages", [])

        inbox_list = []
        for m in messages_summary:
            try:
                msg_meta = requests.get(
                    f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{quote(m['id'])}?format=metadata&metadataHeaders=Subject&metadataHeaders=From&metadataHeaders=Date",
                    headers=headers,
                    timeout=3
                ).json()

                headers_list = msg_meta.get("payload", {}).get("headers", [])
                subject = next((h["value"] for h in headers_list if h["name"].lower() == "subject"), "(No Subject)")
                sender = next((h["value"] for h in headers_list if h["name"].lower() == "from"), "Unknown Sender")
                date_str = next((h["value"] for h in headers_list if h["name"].lower() == "date"), "")
                snippet = msg_meta.get("snippet", "")

                if "[SOC ALERT" in subject or "Security alert" in subject:
                    continue

                is_suspicious = any(re.search(pat, f"{subject} {snippet}", re.IGNORECASE) for pat in BEC_URGENCY_PATTERNS)

                inbox_list.append({
                    "id": m["id"],
                    "subject": subject,
                    "from": sender,
                    "date": date_str,
                    "snippet": snippet,
                    "threat_preview": "CRITICAL" if is_suspicious else "CLEAN"
                })
            except Exception:
                continue

        session['inbox_list'] = inbox_list
        return jsonify({"status": "success", "inbox": inbox_list})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/get_soc_alert_email')
def get_soc_alert_email():
    settings = load_settings()
    email_val = settings.get("soc_email", "").strip()
    if not email_val or email_val == "CONNECTED_MAILBOX":
        email_val = session.get("user_email", "")
    return jsonify({"soc_email": email_val})

@app.route('/api/set_soc_alert_email', methods=['POST'])
def set_soc_alert_email():
    data = request.get_json(silent=True) or {}
    email_val = data.get("soc_email", "").strip()
    if email_val == "CONNECTED_MAILBOX" or not email_val:
        email_val = session.get("user_email", "")
    save_settings({"soc_email": email_val})
    return jsonify({"status": "success", "soc_email": email_val})

@app.route('/scan_inbox_message/<msg_id>')
def scan_inbox_message(msg_id):
    access_token = session.get('access_token')
    if not access_token:
        return redirect('/auth/login')

    headers = {"Authorization": f"Bearer {access_token}"}
    msg_url = f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{quote(msg_id)}?format=raw"
    msg_res = requests.get(msg_url, headers=headers, timeout=10).json()

    raw_base64 = msg_res.get("raw", "")
    raw_bytes = base64.urlsafe_b64decode(raw_base64.encode("ASCII"))

    apply_soc_label_to_message(headers, msg_id, mark_as_read=False)

    analysis = analyze_email_forensics(raw_bytes)
    case_id = str(uuid.uuid4())[:8]
    save_case_record(case_id, analysis)

    return redirect(f"/?case={quote(str(case_id))}")

@app.route('/auth/logout')
def auth_logout():
    global MONITORED_ACCOUNTS
    user_email = session.get('user_email')

    if user_email and user_email in MONITORED_ACCOUNTS:
        MONITORED_ACCOUNTS.pop(user_email, None)
        try:
            with open(ACCOUNTS_FILE, "w", encoding="utf-8") as f:
                json.dump(MONITORED_ACCOUNTS, f)
            print(f"[DAEMON STOPPED] Removed {user_email} from background monitor.")
        except Exception as e:
            print(f"Error saving accounts cache on logout: {e}")

    session.pop('access_token', None)
    session.pop('inbox_list', None)
    session.pop('user_email', None)

    return redirect('/?status=disconnected')

@app.route('/api/get_session_inbox')
def get_session_inbox():
    return jsonify(session.get('inbox_list', []))

@app.route('/api/cleanup_labels', methods=['POST'])
def cleanup_labels():
    access_token = session.get('access_token')
    if not access_token:
        return jsonify({"error": "No active session"}), 401

    headers = {"Authorization": f"Bearer {access_token}"}
    try:
        labels_res = requests.get("https://gmail.googleapis.com/gmail/v1/users/me/labels", headers=headers, timeout=5).json()
        labels = labels_res.get("labels", [])
        target_label = next((l for l in labels if l["name"] == "SOC-SCANNED"), None)

        if target_label:
            delete_url = f"https://gmail.googleapis.com/gmail/v1/users/me/labels/{quote(target_label['id'])}"
            requests.delete(delete_url, headers=headers, timeout=5)
            return jsonify({"status": "success", "message": "SOC-SCANNED label deleted."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({"status": "success", "message": "No label found to remove."})

@app.route('/api/clear_cache_locks', methods=['POST', 'GET'])
def clear_cache_locks():
    global SENT_ALERTS
    SENT_ALERTS = set()
    if os.path.exists(ALERTS_FILE):
        try:
            os.remove(ALERTS_FILE)
        except Exception:
            pass
    return jsonify({"status": "success", "message": "All alert duplicate locks successfully cleared."})

@app.route('/scan_raw', methods=['POST'])
def scan_raw():
    data = request.get_json(silent=True)
    if not data or 'raw_email' not in data:
        return jsonify({"error": "Missing raw_email"}), 400

    raw_content = data['raw_email'].encode('utf-8')
    result = analyze_email_forensics(raw_content)

    case_id = str(uuid.uuid4())[:8]
    save_case_record(case_id, result)

    result['case_id'] = case_id
    result['report_url'] = f"https://aiemailthreat.onrender.com/?case={quote(str(case_id))}"
    return jsonify(result)

@app.route('/scan_demo', methods=['POST', 'GET'])
def scan_demo():
    sample_payload = (
        b"Received: from 185.220.101.5 (mail.tor-exit.de [185.220.101.5])\r\n"
        b"\tby relay.forwarder-cloud.org with ESMTP id 8472910;\r\n"
        b"\tSun, 30 Aug 2026 14:22:10 +0000\r\n"
        b"Received: from relay.forwarder-cloud.org (relay.forwarder-cloud.org [51.15.89.24])\r\n"
        b"\tby mx.google.com with ESMTPS id j89si123490;\r\n"
        b"\tSun, 30 Aug 2026 14:22:12 +0000\r\n"
        b"From: Executive Payroll Support <billing@paypal.com>\r\n"
        b"Return-Path: <attacker@cloud-vps-phish.net>\r\n"
        b"Subject: URGENT: Wire Transfer Authorization & Credential Verification\r\n"
        b"Date: Sun, 30 Aug 2026 14:22:00 +0000\r\n"
        b"Message-ID: <threat-demo-sih26106-sentinel@nexus>\r\n"
        b"\r\n"
        b"Immediate action required. Your executive corporate account will be suspended within 24 hours.\r\n"
        b"Please process the overdue wire transfer to the updated account and verify password here: http://secure-auth-update.com"
    )
    analysis = analyze_email_forensics(sample_payload)
    case_id = "c66930bf"
    save_case_record(case_id, analysis)
    analysis['case_id'] = case_id
    analysis['report_url'] = f"https://aiemailthreat.onrender.com/?case={quote(str(case_id))}"
    return jsonify(analysis)

@app.route('/api/get_graph/<case_id>', methods=['GET'])
def get_graph(case_id):
    global CASES_DB
    if case_id not in CASES_DB:
        CASES_DB = load_cases_from_disk()
    case = CASES_DB.get(case_id)
    if not case:
        return jsonify({"error": "Case not found"}), 404
    return jsonify(case.get("graph", {"nodes": [], "edges": []}))

@app.route('/api/get_case/<case_id>', methods=['GET'])
def get_case(case_id):
    global CASES_DB
    if case_id not in CASES_DB:
        CASES_DB = load_cases_from_disk()

    if case_id in CASES_DB:
        return jsonify(CASES_DB[case_id])
    if case_id == "c66930bf":
        return scan_demo()
    return jsonify({"error": "Case not found"}), 404

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
