import os
import re
import json
import uuid
import base64
import hashlib
import email
from email import policy
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid
import ipaddress
import threading
import time
import requests
import dns.resolver
from flask import Flask, render_template, request, jsonify, redirect, session

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "sih_nexora_sentinel_secret_2026")

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "474486731193-h4beukvlb1l3ca5napbtnb2nvcti3bq0.apps.googleusercontent.com")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "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")
REDIRECT_URI = "https://aiemailthreat.onrender.com/auth/callback"

CASES_FILE = "cases_cache.json"
ACCOUNTS_FILE = "accounts_cache.json"
SETTINGS_FILE = "settings_cache.json"
ALERTS_FILE = "sent_alerts_cache.json"

CASES_DB = {}
MONITORED_ACCOUNTS = {}
SENT_ALERTS = set()

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
    SENT_ALERTS.add(str(identifier))
    try:
        with open(ALERTS_FILE, "w", encoding="utf-8") as f:
            json.dump(list(SENT_ALERTS), f)
    except Exception as e:
        print(f"Error saving alert record: {e}")

# Initialize state from disk
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

def apply_soc_label_to_message(headers, msg_id):
    try:
        label_id = get_or_create_soc_label(headers)
        body = {"removeLabelIds": ["UNREAD"]}
        if label_id:
            body["addLabelIds"] = [label_id]
        requests.post(
            f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg_id}/modify",
            headers=headers,
            json=body,
            timeout=5
        )
    except Exception as e:
        print(f"Error applying SOC label: {e}")

def dispatch_soc_alert_email(headers, recipient_email, case_id, analysis, unique_msg_id):
    global SENT_ALERTS
    unique_key = f"ALERT_SENT_{unique_msg_id}"
    
    if not recipient_email or recipient_email == "CONNECTED_MAILBOX" or unique_key in SENT_ALERTS:
        return False

    # Immediate in-memory lock
    record_alert_dispatched(unique_key)

    try:
        meta = analysis.get("metadata", {})
        threat = analysis.get("threat_assessment", {})
        origin = analysis.get("origin_investigation", {})
        
        # Pure ASCII clean subject prevents character corruption across relays
        clean_subj = re.sub(r'[^\x00-\x7F]+', '', meta.get('subject', 'Untitled'))[:35]
        subject_text = f"[SOC ALERT] Threat Detected ({threat.get('threat_score', 0)}%) - {clean_subj}"
        
        body = f"""AI Email Threat Sentinel - Incident Dispatch

THREAT VERDICT: {threat.get('risk_tier', 'ELEVATED RISK')} ({threat.get('threat_score', 0)}%)
CASE ID: #{case_id}
LIVE DASHBOARD: https://aiemailthreat.onrender.com/?case={case_id}

EVALUATION SUMMARY:
- Subject: {meta.get('subject')}
- Claimed Sender: {meta.get('from')}
- Return-Path: {meta.get('return_path')}
- Origin IP: {origin.get('ip')} ({origin.get('city', 'Unknown')}, {origin.get('country', 'Unknown')})
- Node Type: {origin.get('node_type')}
- Section 65B SHA-256 Seal: {meta.get('evidence_sha256')}

DETECTED RISK INDICATORS:
{chr(10).join(['* ' + r for r in threat.get('threat_reasons', [])])}

Inspect full network hops and evidence telemetry on the live triage hub.
"""
        msg = MIMEText(body, 'plain', 'utf-8')
        msg['To'] = recipient_email
        msg['From'] = f"Nexora SOC Sentinel <{recipient_email}>"
        msg['Reply-To'] = recipient_email
        msg['Subject'] = subject_text
        msg['X-Nexora-Alert'] = "true"
        msg['Date'] = formatdate(localtime=True)
        msg['Message-ID'] = make_msgid()
        
        raw_msg = base64.urlsafe_b64encode(msg.as_bytes()).decode("utf-8")
        send_res = requests.post(
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
            headers=headers,
            json={"raw": raw_msg},
            timeout=10
        )
        
        if send_res.status_code == 200:
            print(f"✅ Clean SOC alert email dispatched for msg {unique_key}")
            return True
        return False
    except Exception as e:
        print(f"Failed to dispatch SOC alert: {e}")
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

    body_content = extract_email_body_text(msg)
    full_text_to_scan = f"{subject}\n{body_content}"
    
    found_cues = []
    for pattern in BEC_URGENCY_PATTERNS:
        matches = re.findall(pattern, full_text_to_scan, re.IGNORECASE)
        if matches:
            found_cues.extend(matches)

    extracted_urls = re.findall(r'https?://[^\s<>"\'\)]+|www\.[^\s<>"\'\)]+', body_content)

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
        threat_reasons.append(f"Anonymized Sending Node: Origin IP belongs to {origin_geo['isp']} (Datacenter / VPN).")

    if found_cues:
        nlp_penalty = 30 if len(found_cues) >= 2 else 15
        threat_score += nlp_penalty
        threat_reasons.append(f"Social Engineering Threat Cues: Detected keywords ({', '.join(set(found_cues))}).")

    if extracted_urls and found_cues:
        threat_score += 25
        threat_reasons.append(f"Suspicious Embedded URLs: Discovered {len(extracted_urls)} link(s) combined with high-pressure cues.")
    elif extracted_urls and is_spoofed_sender:
        threat_score += 20
        threat_reasons.append("Unauthenticated links inside spoofed sender envelope.")

    threat_score = min(threat_score, 100)

    if not threat_reasons:
        threat_reasons.append("Verified Sender: Clean return-path alignment and authenticated corporate delivery.")

    return {
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
            "dmarc": dmarc_status
        },
        "origin_investigation": origin_geo or {"ip": "127.0.0.1", "country": "Unknown", "city": "Unknown", "lat": 0.0, "lon": 0.0, "maps_url": "https://maps.google.com", "isp": "Unknown", "node_type": "Unknown"},
        "hops": hops,
        "urls": extracted_urls,
        "social_engineering_cues": list(set(found_cues))
    }

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

def background_threat_monitor():
    global MONITORED_ACCOUNTS, SENT_ALERTS
    if not MONITORED_ACCOUNTS:
        MONITORED_ACCOUNTS = load_monitored_accounts()
        
    settings = load_settings()
    configured_soc_email = settings.get("soc_email", "").strip()

    for email_addr, creds in list(MONITORED_ACCOUNTS.items()):
        try:
            token = refresh_google_token(creds['refresh_token'])
            if not token:
                continue

            headers = {"Authorization": f"Bearer {token}"}
            
            # Strict query to exclude alerts, sent messages, and already scanned items
            query = 'is:unread -is:sent -from:me -label:SOC-SCANNED'
            list_url = f'https://gmail.googleapis.com/gmail/v1/users/me/messages?q={requests.utils.quote(query)}&maxResults=5'
            
            res = requests.get(list_url, headers=headers, timeout=10).json()
            messages = res.get("messages", [])

            for m in messages:
                msg_id = m['id']
                
                # Check locks
                if msg_id in SENT_ALERTS or f"ALERT_SENT_{msg_id}" in SENT_ALERTS:
                    apply_soc_label_to_message(headers, msg_id)
                    continue

                # Pre-inspection header check
                meta_res = requests.get(
                    f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg_id}?format=metadata&metadataHeaders=Subject&metadataHeaders=From",
                    headers=headers,
                    timeout=5
                ).json()
                
                h_list = meta_res.get("payload", {}).get("headers", [])
                subj = next((h["value"] for h in h_list if h["name"].lower() == "subject"), "")
                sndr = next((h["value"] for h in h_list if h["name"].lower() == "from"), "").lower()

                # Loop suppression: ignore alerts, self-sent, and notifications
                if (
                    "soc" in subj.lower() 
                    or "alert" in subj.lower() 
                    or email_addr.lower() in sndr 
                    or "nexora" in sndr
                ):
                    apply_soc_label_to_message(headers, msg_id)
                    record_alert_dispatched(msg_id)
                    record_alert_dispatched(f"ALERT_SENT_{msg_id}")
                    continue

                raw_res = requests.get(f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg_id}?format=raw", headers=headers, timeout=10).json()
                raw_base64 = raw_res.get("raw", "")
                if not raw_base64:
                    continue
                raw_bytes = base64.urlsafe_b64decode(raw_base64.encode("ASCII"))
                
                analysis = analyze_email_forensics(raw_bytes)
                threat_score = analysis['threat_assessment']['threat_score']

                # Mark scanned and lock ID
                apply_soc_label_to_message(headers, msg_id)
                record_alert_dispatched(msg_id)

                # Only alert for legitimate incoming external threats >= 40%
                if threat_score >= 40:
                    case_id = str(uuid.uuid4())[:8]
                    save_case_record(case_id, analysis)
                    
                    target_alert_email = email_addr
                    if configured_soc_email and configured_soc_email != "CONNECTED_MAILBOX" and "@" in configured_soc_email:
                        target_alert_email = configured_soc_email
                    
                    dispatch_soc_alert_email(headers, target_alert_email, case_id, analysis, msg_id)

        except Exception as e:
            print(f"Monitor error for {email_addr}: {e}")

def background_threat_worker_loop():
    while True:
        try:
            background_threat_monitor()
        except Exception as e:
            print(f"Background worker loop error: {e}")
        time.sleep(45)

bg_thread = threading.Thread(target=background_threat_worker_loop, daemon=True)
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
        
    scope = "https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/gmail.modify https://www.googleapis.com/auth/gmail.labels https://www.googleapis.com/auth/gmail.send"
    auth_url = (
        f"https://accounts.google.com/o/oauth2/v2/auth?"
        f"client_id={GOOGLE_CLIENT_ID}&"
        f"redirect_uri={REDIRECT_URI}&"
        f"response_type=code&"
        f"scope={scope}&"
        f"access_type=offline&"
        f"prompt=consent"
    )
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

    list_url = 'https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=10&q=is:inbox%20-subject:"SOC ALERT"'
    list_res = requests.get(list_url, headers=headers, timeout=10).json()
    messages_summary = list_res.get("messages", [])

    if not messages_summary:
        return redirect("/?case=c66930bf&msg=inbox_empty")

    inbox_list = []
    for m in messages_summary:
        try:
            msg_meta = requests.get(
                f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{m['id']}?format=metadata&metadataHeaders=Subject&metadataHeaders=From&metadataHeaders=Date",
                headers=headers,
                timeout=3
            ).json()
            
            headers_list = msg_meta.get("payload", {}).get("headers", [])
            subject = next((h["value"] for h in headers_list if h["name"].lower() == "subject"), "(No Subject)")
            sender = next((h["value"] for h in headers_list if h["name"].lower() == "from"), "Unknown Sender")
            date_str = next((h["value"] for h in headers_list if h["name"].lower() == "date"), "")
            snippet = msg_meta.get("snippet", "")

            if "[SOC ALERT]" in subject or "Security alert" in subject or "SOC ALERT" in subject:
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

    threading.Thread(target=background_threat_monitor).start()

    headers = {"Authorization": f"Bearer {access_token}"}
    try:
        list_url = 'https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=10&q=is:inbox%20-subject:"SOC ALERT"'
        list_res = requests.get(list_url, headers=headers, timeout=10).json()
        messages_summary = list_res.get("messages", [])

        inbox_list = []
        for m in messages_summary:
            try:
                msg_meta = requests.get(
                    f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{m['id']}?format=metadata&metadataHeaders=Subject&metadataHeaders=From&metadataHeaders=Date",
                    headers=headers,
                    timeout=3
                ).json()
                
                headers_list = msg_meta.get("payload", {}).get("headers", [])
                subject = next((h["value"] for h in headers_list if h["name"].lower() == "subject"), "(No Subject)")
                sender = next((h["value"] for h in headers_list if h["name"].lower() == "from"), "Unknown Sender")
                date_str = next((h["value"] for h in headers_list if h["name"].lower() == "date"), "")
                snippet = msg_meta.get("snippet", "")

                if "[SOC ALERT]" in subject or "Security alert" in subject or "SOC ALERT" in subject:
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
    msg_url = f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg_id}?format=raw"
    msg_res = requests.get(msg_url, headers=headers, timeout=10).json()
    
    raw_base64 = msg_res.get("raw", "")
    raw_bytes = base64.urlsafe_b64decode(raw_base64.encode("ASCII"))

    apply_soc_label_to_message(headers, msg_id)

    analysis = analyze_email_forensics(raw_bytes)
    case_id = str(uuid.uuid4())[:8]
    save_case_record(case_id, analysis)

    return redirect(f"/?case={case_id}")

@app.route('/api/get_session_inbox')
def get_session_inbox():
    return jsonify(session.get('inbox_list', []))

@app.route('/auth/logout')
def auth_logout():
    session.pop('access_token', None)
    session.pop('inbox_list', None)
    session.pop('user_email', None)
    return redirect('/')

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
            delete_url = f"https://gmail.googleapis.com/gmail/v1/users/me/labels/{target_label['id']}"
            requests.delete(delete_url, headers=headers, timeout=5)
            return jsonify({"status": "success", "message": "SOC-SCANNED label deleted."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
    return jsonify({"status": "success", "message": "No label found to remove."})

@app.route('/api/clear_cache_locks', methods=['POST', 'GET'])
def clear_cache_locks():
    """Flushes alert cache locks cleanly so you can test repeat emails."""
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
    result['report_url'] = f"https://aiemailthreat.onrender.com/?case={case_id}"
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
    analysis['report_url'] = f"https://aiemailthreat.onrender.com/?case={case_id}"
    return jsonify(analysis)

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
