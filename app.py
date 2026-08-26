import os
import re
import datetime
import hashlib
import email
from email import policy
from flask import Flask, render_template, request, jsonify
import dns.resolver
import requests
import uuid
from datetime import datetime

app = Flask(__name__)

# Heuristic lists for detection
BEC_URGENCY_PATTERNS = [
    r"\b(urgent|immediate action|suspended within \d+ hours|account deactivated)\b",
    r"\b(wire transfer|bank payment|invoice overdue|direct deposit|gift cards?)\b",
    r"\b(verify password|update credentials|reset password|click here immediately)\b",
    r"\b(unauthorized login|compromised account|termination of access)\b"
]

KNOWN_DATACENTER_ORGS = ["m247", "ovh", "digitalocean", "linode", "aws", "amazon", "tor", "vpn", "datacamp", "cloudflare"]

def get_ip_intelligence(ip_address: str):
    """Resolves Geolocation, ASN, and flags VPN / Datacenter infrastructure."""
    try:
        url = f"http://ip-api.com/json/{ip_address}?fields=status,country,city,isp,org,as,hosting,proxy,query"
        res = requests.get(url, timeout=2.5).json()
        if res.get("status") == "success":
            isp_org_str = f"{res.get('isp', '')} {res.get('org', '')} {res.get('as', '')}".lower()
            is_vpn_dc = res.get("hosting", False) or res.get("proxy", False) or any(k in isp_org_str for k in KNOWN_DATACENTER_ORGS)
            
            return {
                "ip": res.get("query"),
                "country": res.get("country", "Unknown"),
                "city": res.get("city", "Unknown"),
                "isp": res.get("isp", "Unknown"),
                "org": res.get("org", "Unknown"),
                "asn": res.get("as", "Unknown"),
                "is_anonymized": is_vpn_dc,
                "node_type": "Data Center / VPN Relay" if is_vpn_dc else "Residential / ISP"
            }
    except Exception:
        pass
    return None

def analyze_email_forensics(raw_bytes: bytes):
    msg = email.message_from_bytes(raw_bytes, policy=policy.default)

    # 1. Extract Core Metadata
    sender = str(msg.get('From', 'Unknown'))
    return_path = str(msg.get('Return-Path', 'Unknown'))
    subject = str(msg.get('Subject', '(No Subject)'))
    date_header = str(msg.get('Date', 'Unknown'))
    message_id = str(msg.get('Message-ID', 'None'))

    # Evidence Hash (Section 65B compliance)
    sha256_hash = hashlib.sha256(raw_bytes).hexdigest()

    # 2. Extract Domain & Match Spoofing
    domain_match = re.search(r"@([\w.-]+)", sender)
    sender_domain = domain_match.group(1).strip(">").lower() if domain_match else ""

    return_path_match = re.search(r"@([\w.-]+)", return_path)
    return_path_domain = return_path_match.group(1).strip(">").lower() if return_path_match else ""

    is_spoofed_sender = False
    if sender_domain and return_path_domain and (sender_domain != return_path_domain):
        is_spoofed_sender = True

    # 3. Header Route & Relay Hop Forensics
    received_headers = msg.get_all('Received', [])
    hops = []
    discovered_ips = []

    for idx, hop_str in enumerate(received_headers):
        ips = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", str(hop_str))
        public_ips = [ip for ip in ips if not ip.startswith(("127.", "10.", "192.168.", "0.", "172.16."))]
        discovered_ips.extend(public_ips)

        geo = get_ip_intelligence(public_ips[0]) if public_ips else None
        hops.append({
            "hop_index": idx + 1,
            "raw": str(hop_str).strip()[:100] + "...",
            "extracted_ips": public_ips,
            "geo": geo
        })

    # Earliest originating IP analysis
    origin_geo = None
    if discovered_ips:
        origin_geo = get_ip_intelligence(discovered_ips[-1])

    # 4. Live DNS Security Authentication (SPF, DMARC)
    spf_status = "Not Found"
    dmarc_status = "Not Found"
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 2.0

    if sender_domain:
        try:
            txt_records = resolver.resolve(sender_domain, 'TXT')
            for txt in txt_records:
                txt_str = txt.to_text()
                if "v=spf1" in txt_str:
                    spf_status = f"Configured ({txt_str[:30]}...)"
                    break
        except Exception:
            spf_status = "Failed / Domain Unreachable"

        try:
            dmarc_records = resolver.resolve(f"_dmarc.{sender_domain}", 'TXT')
            for txt in dmarc_records:
                txt_str = txt.to_text()
                if "v=DMARC1" in txt_str:
                    dmarc_status = f"Configured ({txt_str[:30]}...)"
                    break
        except Exception:
            dmarc_status = "Missing DMARC Policy"

    # 5. NLP Social Engineering & Urgency Detector
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
        matches = re.findall(pattern, body_content, re.IGNORECASE)
        if matches:
            found_cues.extend(matches)

    extracted_urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', str(body_content))

    # 6. Multi-Factor Confidence Fraud Scoring Algorithm
    threat_score = 5
    threat_reasons = []

    if is_spoofed_sender:
        threat_score += 40
        threat_reasons.append(f"Domain Spoofing: 'From' domain ({sender_domain}) differs from Return-Path ({return_path_domain}).")

    if origin_geo and origin_geo.get("is_anonymized"):
        threat_score += 25
        threat_reasons.append(f"Anonymization Layer: Origin IP ({origin_geo['ip']}) belongs to Data Center / VPN infrastructure.")

    if found_cues:
        threat_score += 20
        threat_reasons.append(f"NLP Threat Cues: Detected coercive urgency patterns ({len(found_cues)} indicators).")

    if extracted_urls:
        threat_score += 10
        threat_reasons.append(f"Suspicious Embedded URLs: {len(extracted_urls)} link(s) discovered in payload.")

    threat_score = min(threat_score, 100)

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
            "risk_tier": "CRITICAL RISK (IMPERSONATION / PHISHING)" if threat_score > 60 else "LOW RISK / VERIFIED",
            "threat_reasons": threat_reasons
        },
        "dns_authentication": {
            "spf": spf_status,
            "dmarc": dmarc_status
        },
        "origin_investigation": origin_geo,
        "hops": hops,
        "urls": extracted_urls,
        "social_engineering_cues": list(set(found_cues))
    }



@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    f = request.files['file']
    return jsonify(analyze_email_forensics(f.read()))

@app.route('/scan_demo', methods=['POST'])
def scan_demo():
    sample_path = os.path.join(os.path.dirname(__file__), "sample_attack.eml")
    with open(sample_path, "rb") as f:
        return jsonify(analyze_email_forensics(f.read()))

if __name__ == '__main__':
    app.run(debug=True, port=5000)

if __name__ == '__main__':
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

CASES_DB = {}

@app.route('/scan_raw', methods=['POST'])
def scan_raw():
    data = request.get_json(silent=True)
    if not data or 'raw_email' not in data:
        return jsonify({"error": "Missing raw_email"}), 400
    
    raw_content = data['raw_email'].encode('utf-8')
    result = analyze_email_forensics(raw_content)
    
    # Generate unique ID and save
    case_id = str(uuid.uuid4())[:8]
    CASES_DB[case_id] = result
    
    # Attach unique URL to response
    result['case_id'] = case_id
    result['report_url'] = f"https://aiemailthreat.onrender.com/?case={case_id}"
    
    return jsonify(result)

@app.route('/api/get_case/<case_id>', methods=['GET'])
def get_case(case_id):
    if case_id in CASES_DB:
        return jsonify(CASES_DB[case_id])
    return jsonify({"error": "Case not found"}), 404
@app.route('/api/get_case/<case_id>', methods=['GET'])
def get_case(case_id):
    for incident in SCANNED_INCIDENTS:
        if incident.get('case_id') == case_id:
            return jsonify(incident)
    return jsonify({"error": "Incident not found"}), 404
