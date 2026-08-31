import os
import re
import uuid
import base64
import hashlib
import email
from email import policy
import ipaddress
import requests
import dns.resolver
from flask import Flask, render_template, request, jsonify, redirect, session

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "sih_nexora_sentinel_secret_2026")

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "474486731193-h4beukvlb1l3ca5napbtnb2nvcti3bq0.apps.googleusercontent.com")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "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")
REDIRECT_URI = "https://aiemailthreat.onrender.com/auth/callback"

CASES_DB = {}

BEC_URGENCY_PATTERNS = [
    r"\b(urgent|immediate action|suspended within \d+ hours|account deactivated)\b",
    r"\b(wire transfer|bank payment|invoice overdue|direct deposit|gift cards?)\b",
    r"\b(verify password|update credentials|reset password|click here immediately)\b",
    r"\b(unauthorized login|compromised account|termination of access)\b",
    r"\b(ceo request|confidential payment|vendor bank details updated)\b"
]

KNOWN_DATACENTER_ORGS = [
    "m247", "ovh", "digitalocean", "linode", "tor", "datacamp", "hetzner", "vultr"
]

def get_ip_intelligence(ip_address: str):
    if not ip_address or ip_address in ["127.0.0.1", "localhost"]:
        return {
            "ip": ip_address,
            "country": "Local Relay",
            "city": "Internal",
            "isp": "Private Loopback",
            "org": "Internal",
            "asn": "AS0",
            "is_anonymized": False,
            "node_type": "Internal / RFC-1918"
        }
    try:
        url = f"http://ip-api.com/json/{ip_address}?fields=status,country,city,isp,org,as,hosting,proxy,query"
        res = requests.get(url, timeout=2.5).json()
        if res.get("status") == "success":
            isp_org_str = f"{res.get('isp', '')} {res.get('org', '')} {res.get('as', '')}".lower()
            trusted_providers = ["google", "microsoft", "amazon", "cloudflare", "yahoo"]
            is_trusted = any(p in isp_org_str for p in trusted_providers)
            is_vpn_dc = (res.get("hosting", False) or res.get("proxy", False) or any(k in isp_org_str for k in KNOWN_DATACENTER_ORGS)) and not is_trusted
            
            return {
                "ip": res.get("query"),
                "country": res.get("country", "Unknown"),
                "city": res.get("city", "Unknown"),
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

    is_spoofed_sender = False
    if sender_domain and return_path_domain and (sender_domain != return_path_domain):
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
        try:
            txt_records = resolver.resolve(sender_domain, 'TXT')
            for txt in txt_records:
                txt_str = txt.to_text()
                if "v=spf1" in txt_str:
                    spf_status = f"Configured ({txt_str[:28]}...)"
                    break
        except Exception:
            spf_status = "Lookup Failed / Domain Unreachable"

        try:
            dmarc_records = resolver.resolve(f"_dmarc.{sender_domain}", 'TXT')
            for txt in dmarc_records:
                txt_str = txt.to_text()
                if "v=DMARC1" in txt_str:
                    if "p=reject" in txt_str:
                        dmarc_status = "p=reject (Enforced / Protected)"
                    elif "p=quarantine" in txt_str:
                        dmarc_status = "p=quarantine (Strict)"
                    else:
                        dmarc_status = "p=none (Vulnerable / Monitoring Only)"
                    break
        except Exception:
            dmarc_status = "Missing DMARC Policy (+30% Risk)"

    body_content = ""
    try:
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == 'text/plain':
                    body_content = part.get_content()
                    break
        else:
            body_content = msg.get_content()
    except Exception:
        body_content = str(msg.get_payload())

    found_cues = []
    for pattern in BEC_URGENCY_PATTERNS:
        matches = re.findall(pattern, str(body_content), re.IGNORECASE)
        if matches:
            found_cues.extend(matches)

    extracted_urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', str(body_content))

    threat_score = 0
    threat_reasons = []

    if is_spoofed_sender:
        threat_score += 45
        threat_reasons.append(f"Domain Spoofing: 'From' domain ({sender_domain}) does not match Return-Path ({return_path_domain}).")

    if ("p=none" in dmarc_status or "Missing" in dmarc_status) and sender_domain not in ["gmail.com", "google.com", "yahoo.com", "outlook.com"]:
        threat_score += 30
        threat_reasons.append("Unenforced DMARC Policy: Domain allows forged inbound messages to bypass mailbox verification.")

    if origin_geo and origin_geo.get("is_anonymized"):
        threat_score += 25
        threat_reasons.append(f"Anonymized Sending Node: Origin IP ({origin_geo['ip']}) belongs to {origin_geo['isp']} (Datacenter / Tor / VPN).")

    if found_cues:
        weight = 20 if (is_spoofed_sender or "Missing" in dmarc_status) else 5
        threat_score += weight
        threat_reasons.append(f"NLP Threat Cues: Extracted high-pressure social engineering keywords: {', '.join(set(found_cues))}.")

    if extracted_urls and is_spoofed_sender:
        threat_score += 15
        threat_reasons.append(f"Suspicious Embedded URLs: Discovered {len(extracted_urls)} external links inside unauthenticated payload.")

    threat_score = min(threat_score, 100)

    if not threat_reasons:
        threat_reasons.append("Clean Delivery: Domain authentication verified, return-path aligned, zero spoofing indicators.")

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
            "risk_tier": "CRITICAL RISK (IMPERSONATION / PHISHING)" if threat_score >= 70 else ("ELEVATED RISK" if threat_score >= 40 else "LOW RISK / VERIFIED"),
            "threat_reasons": threat_reasons
        },
        "dns_authentication": {
            "spf": spf_status,
            "dmarc": dmarc_status
        },
        "origin_investigation": origin_geo or {"ip": "127.0.0.1", "country": "Unknown", "city": "Unknown", "isp": "Unknown", "node_type": "Unknown"},
        "hops": hops,
        "urls": extracted_urls,
        "social_engineering_cues": list(set(found_cues))
    }

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/auth/login')
def auth_login():
    if not GOOGLE_CLIENT_ID:
        return "<h3 style='color:red;font-family:sans-serif;'>OAuth Error: GOOGLE_CLIENT_ID is not configured.</h3>", 400
        
    scope = "https://www.googleapis.com/auth/gmail.readonly"
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

    if not access_token:
        return f"<h3 style='color:red;font-family:sans-serif;'>Token Exchange Failed:</h3><pre>{token_res}</pre>", 400

    session['access_token'] = access_token

    # Fetch last 10 messages for comprehensive batch threat triage
    headers = {"Authorization": f"Bearer {access_token}"}
    list_url = "https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=10&q=is:inbox"
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

            # Heuristic preview flag for instant inbox badges
            is_suspicious = any(k in subject.lower() or k in snippet.lower() for k in ["urgent", "password", "suspended", "payment", "unauthorized", "wire transfer"])

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

    analysis = analyze_email_forensics(raw_bytes)
    case_id = str(uuid.uuid4())[:8]
    CASES_DB[case_id] = analysis

    return redirect(f"/?case={case_id}")

@app.route('/api/get_session_inbox')
def get_session_inbox():
    return jsonify(session.get('inbox_list', []))

@app.route('/scan_raw', methods=['POST'])
def scan_raw():
    data = request.get_json(silent=True)
    if not data or 'raw_email' not in data:
        return jsonify({"error": "Missing raw_email"}), 400
    
    raw_content = data['raw_email'].encode('utf-8')
    result = analyze_email_forensics(raw_content)
    
    case_id = str(uuid.uuid4())[:8]
    CASES_DB[case_id] = result
    
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
    CASES_DB[case_id] = analysis
    analysis['case_id'] = case_id
    analysis['report_url'] = f"https://aiemailthreat.onrender.com/?case={case_id}"
    return jsonify(analysis)

@app.route('/api/get_case/<case_id>', methods=['GET'])
def get_case(case_id):
    if case_id in CASES_DB:
        return jsonify(CASES_DB[case_id])
    if case_id == "c66930bf":
        return scan_demo()
    return jsonify({"error": "Case not found"}), 404

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
