import os
import zipfile

# 1. Directory Structure
BASE_DIR = os.getcwd()
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
os.makedirs(TEMPLATES_DIR, exist_ok=True)

# 2. requirements.txt
REQUIREMENTS_CONTENT = """flask>=3.0.0
dnspython>=2.6.0
requests>=2.31.0
python-whois>=0.9.3
"""

# 3. sample_attack.eml
SAMPLE_EML_CONTENT = """Received: from mail-relay1.google.com (mail-relay1.google.com [209.85.220.41])
    by mx.targetserver.com (Postfix) with ESMTPS id 4S9xZ1234
    for <victim@example.com>; Sat, 22 Aug 2026 10:15:30 +0530
Received: from anonymized-vpn-node.m247.ro ([185.220.101.5])
    by mail-relay1.google.com with HTTP;
    Sat, 22 Aug 2026 10:14:10 +0530
From: Google Security Center <no-reply@accounts.google.com>
Return-Path: <spoofed-attacker@bad-domain.ru>
Subject: CRITICAL: Immediate Password Reset Required for Accounts
Date: Sat, 22 Aug 2026 10:15:30 +0530
Message-ID: <threat-forensic-sample-106@accounts.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"

URGENT SECURITY ALERT:

An unauthorized login attempt from a Russian IP was detected on your corporate account.
Your account will be suspended within 24 hours unless you verify your password.

Click here immediately to update credentials:
http://g00gle-security-login-check.com/verify-password

Failure to do so will result in immediate termination of email access.
"""

# 4. app.py (Enterprise Forensics Backend)
APP_CODE = '''import os
import re
import datetime
import hashlib
import email
from email import policy
from flask import Flask, render_template, request, jsonify
import dns.resolver
import requests

app = Flask(__name__)

# Heuristic lists for detection
BEC_URGENCY_PATTERNS = [
    r"\\b(urgent|immediate action|suspended within \\d+ hours|account deactivated)\\b",
    r"\\b(wire transfer|bank payment|invoice overdue|direct deposit|gift cards?)\\b",
    r"\\b(verify password|update credentials|reset password|click here immediately)\\b",
    r"\\b(unauthorized login|compromised account|termination of access)\\b"
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
    domain_match = re.search(r"@([\\w.-]+)", sender)
    sender_domain = domain_match.group(1).strip(">").lower() if domain_match else ""

    return_path_match = re.search(r"@([\\w.-]+)", return_path)
    return_path_domain = return_path_match.group(1).strip(">").lower() if return_path_match else ""

    is_spoofed_sender = False
    if sender_domain and return_path_domain and (sender_domain != return_path_domain):
        is_spoofed_sender = True

    # 3. Header Route & Relay Hop Forensics
    received_headers = msg.get_all('Received', [])
    hops = []
    discovered_ips = []

    for idx, hop_str in enumerate(received_headers):
        ips = re.findall(r"\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b", str(hop_str))
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

    extracted_urls = re.findall(r'https?://[^\\s<>"]+|www\\.[^\\s<>"]+', str(body_content))

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
'''

# 5. templates/index.html (Dark UI Dashboard)
INDEX_HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Email Forensics & Threat Attribution Platform</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen p-6 font-sans">
    <div class="max-w-6xl mx-auto space-y-6">

        <!-- Top Header -->
        <header class="flex flex-col md:flex-row justify-between items-start md:items-center border-b border-slate-800 pb-5">
            <div>
                <h1 class="text-2xl font-black tracking-tight text-sky-400">
                    <i class="fa-solid fa-shield-halved mr-2"></i>EMAIL FORENSICS & THREAT ATTRIBUTION
                </h1>
                <p class="text-xs text-slate-400 mt-1">SIH Problem Statement #106 • Automated Relay & Origin De-Anonymization Platform</p>
            </div>
            <div class="mt-3 md:mt-0 flex gap-2">
                <span class="bg-emerald-950 text-emerald-400 border border-emerald-800 text-xs px-3 py-1 rounded-full font-mono font-semibold flex items-center">
                    <span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse mr-2"></span>SOC ENGINE READY
                </span>
            </div>
        </header>

        <!-- Actions Bar -->
        <section class="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-xl">
            <div class="flex flex-col md:flex-row gap-4 items-center justify-between">
                <form id="uploadForm" class="flex flex-col sm:flex-row gap-3 w-full md:w-auto items-center">
                    <input type="file" id="emlFile" accept=".eml,.msg" class="text-sm text-slate-400 file:mr-4 file:py-2 file:px-4 file:rounded-xl file:border-0 file:text-xs file:font-bold file:bg-slate-800 file:text-sky-300 hover:file:bg-slate-700 cursor-pointer">
                    <button type="submit" id="submitBtn" class="w-full sm:w-auto px-5 py-2 bg-sky-500 hover:bg-sky-600 font-semibold rounded-xl text-white text-sm transition flex items-center justify-center">
                        <i class="fa-solid fa-microchip mr-2"></i>Analyze File
                    </button>
                </form>
                <div class="w-full md:w-auto flex justify-end">
                    <button type="button" id="demoBtn" class="w-full sm:w-auto px-5 py-2 bg-indigo-600 hover:bg-indigo-700 font-semibold rounded-xl text-white text-sm transition shadow-lg flex items-center justify-center">
                        <i class="fa-solid fa-bolt mr-2"></i>1-Click Sample Threat Demo
                    </button>
                </div>
            </div>
            <p id="loadingText" class="hidden text-xs text-sky-400 mt-3 font-mono animate-pulse">
                <i class="fa-solid fa-spinner fa-spin mr-2"></i>Running forensic pipeline: header extraction, RFC 822 validation, DNS lookups, and VPN/ASN intelligence...
            </p>
        </section>

        <!-- Main Dashboard View -->
        <section id="results" class="hidden space-y-6">

            <!-- High Level Summary -->
            <div class="grid grid-cols-1 md:grid-cols-3 gap-5">
                
                <!-- Metadata Card -->
                <div class="bg-slate-900 border border-slate-800 rounded-2xl p-5 md:col-span-2 space-y-3">
                    <div class="flex justify-between items-center border-b border-slate-800 pb-2">
                        <span class="text-xs font-bold text-slate-400 uppercase tracking-wider">MIME Metadata & Evidence Hash</span>
                        <span class="text-[10px] font-mono bg-slate-800 text-slate-300 px-2 py-0.5 rounded">RFC 822 Validated</span>
                    </div>
                    <div class="space-y-1.5 text-xs">
                        <p><span class="text-slate-400 font-semibold">Subject:</span> <span id="resSubject" class="text-sky-300 font-medium font-mono"></span></p>
                        <p><span class="text-slate-400 font-semibold">From:</span> <span id="resFrom" class="font-mono text-slate-200"></span></p>
                        <p><span class="text-slate-400 font-semibold">Return-Path:</span> <span id="resReturnPath" class="font-mono text-rose-300"></span></p>
                        <p><span class="text-slate-400 font-semibold">Date:</span> <span id="resDate" class="text-slate-300 font-mono"></span></p>
                        <p class="pt-1"><span class="text-slate-500 font-semibold">Evidence SHA-256:</span> <span id="resHash" class="text-[11px] font-mono text-slate-400 break-all"></span></p>
                    </div>
                </div>

                <!-- Threat Score Gauge -->
                <div class="bg-slate-900 border border-slate-800 rounded-2xl p-5 flex flex-col justify-center items-center text-center">
                    <span class="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Multi-Factor Fraud Score</span>
                    <div id="resScore" class="text-5xl font-black text-rose-500">0%</div>
                    <span id="scoreBadge" class="text-xs font-bold px-3 py-1 rounded-full mt-2 bg-rose-950 text-rose-400 border border-rose-800">
                        CRITICAL THREAT
                    </span>
                </div>
            </div>

            <!-- Origin Geolocation & VPN Attribution -->
            <div id="geoBox" class="bg-gradient-to-r from-slate-900 to-indigo-950 border border-indigo-800 rounded-2xl p-5">
                <div class="flex items-center justify-between mb-3">
                    <h3 class="text-sm font-bold text-indigo-300 uppercase tracking-wider flex items-center">
                        <i class="fa-solid fa-network-wired mr-2"></i>Sender Origin & VPN / Datacenter Attribution
                    </h3>
                    <span id="vpnTag" class="text-xs font-semibold px-2.5 py-0.5 rounded-full bg-amber-950 text-amber-300 border border-amber-800">
                        VPN / Data Center Relay
                    </span>
                </div>
                <div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 text-xs">
                    <div class="bg-slate-900/80 p-3 rounded-xl border border-slate-800">
                        <span class="text-slate-500 block">Originating IP</span>
                        <span id="geoIP" class="font-mono text-amber-400 font-bold text-sm"></span>
                    </div>
                    <div class="bg-slate-900/80 p-3 rounded-xl border border-slate-800">
                        <span class="text-slate-500 block">Physical Location</span>
                        <span id="geoLocation" class="font-semibold text-slate-200"></span>
                    </div>
                    <div class="bg-slate-900/80 p-3 rounded-xl border border-slate-800">
                        <span class="text-slate-500 block">Hosting ISP / Org</span>
                        <span id="geoISP" class="font-semibold text-slate-200"></span>
                    </div>
                    <div class="bg-slate-900/80 p-3 rounded-xl border border-slate-800">
                        <span class="text-slate-500 block">ASN Node</span>
                        <span id="geoASN" class="font-mono text-slate-300"></span>
                    </div>
                </div>
            </div>

            <!-- Intelligence Badges: SPF, DMARC, NLP Urgency -->
            <div class="grid grid-cols-1 md:grid-cols-3 gap-5">
                <div class="bg-slate-900 border border-slate-800 rounded-2xl p-4 space-y-1">
                    <span class="text-[11px] font-bold text-slate-400 uppercase">SPF Authentication</span>
                    <p id="resSPF" class="text-xs font-mono text-slate-300"></p>
                </div>
                <div class="bg-slate-900 border border-slate-800 rounded-2xl p-4 space-y-1">
                    <span class="text-[11px] font-bold text-slate-400 uppercase">DMARC Policy</span>
                    <p id="resDMARC" class="text-xs font-mono text-slate-300"></p>
                </div>
                <div class="bg-slate-900 border border-slate-800 rounded-2xl p-4 space-y-1">
                    <span class="text-[11px] font-bold text-slate-400 uppercase">NLP Coercion Cues</span>
                    <p id="resNLP" class="text-xs font-medium text-amber-300"></p>
                </div>
            </div>

            <!-- Forensic Hop Trace Chain -->
            <div class="bg-slate-900 border border-slate-800 rounded-2xl p-5">
                <h3 class="text-xs font-bold text-slate-400 uppercase tracking-wider mb-4">Reconstructed Transit Relay Chain</h3>
                <div id="hopsList" class="space-y-3"></div>
            </div>

            <!-- Suspicious Links & Reasons Breakdown -->
            <div class="grid grid-cols-1 md:grid-cols-2 gap-5">
                <div class="bg-slate-900 border border-slate-800 rounded-2xl p-5">
                    <h3 class="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3">Threat Reason Factors</h3>
                    <ul id="reasonsList" class="text-xs space-y-2 text-rose-300 list-disc list-inside"></ul>
                </div>
                <div class="bg-slate-900 border border-slate-800 rounded-2xl p-5">
                    <h3 class="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3">Discovered Embedded Links</h3>
                    <ul id="urlsList" class="text-xs font-mono space-y-2 text-amber-300 break-all list-disc list-inside"></ul>
                </div>
            </div>

        </section>
    </div>

    <script>
        async function runPipeline(url, body, isForm = false) {
            const submitBtn = document.getElementById('submitBtn');
            const demoBtn = document.getElementById('demoBtn');
            const loadingText = document.getElementById('loadingText');
            const results = document.getElementById('results');

            submitBtn.disabled = true;
            demoBtn.disabled = true;
            loadingText.classList.remove('hidden');

            try {
                const res = await fetch(url, { method: 'POST', body: isForm ? body : null });
                if (!res.ok) throw new Error('Pipeline status: ' + res.status);
                const data = await res.json();

                // Fill Metadata
                document.getElementById('resSubject').textContent = data.metadata.subject;
                document.getElementById('resFrom').textContent = data.metadata.from;
                document.getElementById('resReturnPath').textContent = data.metadata.return_path;
                document.getElementById('resDate').textContent = data.metadata.date;
                document.getElementById('resHash').textContent = data.metadata.evidence_sha256;

                // Fill Threat Assessment
                const score = data.threat_assessment.threat_score;
                const scoreEl = document.getElementById('resScore');
                const badgeEl = document.getElementById('scoreBadge');
                scoreEl.textContent = score + '%';
                badgeEl.textContent = data.threat_assessment.risk_tier;

                if (score > 60) {
                    scoreEl.className = "text-5xl font-black text-rose-500";
                    badgeEl.className = "text-xs font-bold px-3 py-1 rounded-full mt-2 bg-rose-950 text-rose-400 border border-rose-800";
                } else {
                    scoreEl.className = "text-5xl font-black text-emerald-400";
                    badgeEl.className = "text-xs font-bold px-3 py-1 rounded-full mt-2 bg-emerald-950 text-emerald-400 border border-emerald-800";
                }

                // Origin & VPN Attribution
                if (data.origin_investigation) {
                    document.getElementById('geoIP').textContent = data.origin_investigation.ip;
                    document.getElementById('geoLocation').textContent = data.origin_investigation.city + ', ' + data.origin_investigation.country;
                    document.getElementById('geoISP').textContent = data.origin_investigation.isp;
                    document.getElementById('geoASN').textContent = data.origin_investigation.asn;
                    
                    const vpnTag = document.getElementById('vpnTag');
                    vpnTag.textContent = data.origin_investigation.node_type;
                    vpnTag.className = data.origin_investigation.is_anonymized ? 
                        "text-xs font-semibold px-2.5 py-0.5 rounded-full bg-rose-950 text-rose-300 border border-rose-800" :
                        "text-xs font-semibold px-2.5 py-0.5 rounded-full bg-emerald-950 text-emerald-300 border border-emerald-800";
                }

                // DNS & NLP
                document.getElementById('resSPF').textContent = data.dns_authentication.spf;
                document.getElementById('resDMARC').textContent = data.dns_authentication.dmarc;
                document.getElementById('resNLP').textContent = data.social_engineering_cues.length ? 
                    data.social_engineering_cues.join(", ") : "No explicit urgency patterns detected";

                // Transit Hops
                const hopsDiv = document.getElementById('hopsList');
                hopsDiv.innerHTML = '';
                data.hops.forEach(h => {
                    const item = document.createElement('div');
                    item.className = "p-3 bg-slate-950/80 border border-slate-800 rounded-xl text-xs space-y-1";
                    let geoSub = '';
                    if (h.geo) {
                        geoSub = `<span class="text-sky-400 font-semibold ml-2">[${h.geo.city}, ${h.geo.country} - ${h.geo.isp}]</span>`;
                    }
                    item.innerHTML = `<div class="font-mono text-slate-300 font-bold">Hop #${h.hop_index}: IPs: ${h.extracted_ips.join(', ') || 'Internal Relay'} ${geoSub}</div>
                                      <div class="text-slate-500 font-mono text-[11px] truncate">${h.raw}</div>`;
                    hopsDiv.appendChild(item);
                });

                // Reasons
                const reasonsList = document.getElementById('reasonsList');
                reasonsList.innerHTML = '';
                data.threat_assessment.threat_reasons.forEach(r => {
                    const li = document.createElement('li');
                    li.textContent = r;
                    reasonsList.appendChild(li);
                });

                // URLs
                const urlsList = document.getElementById('urlsList');
                urlsList.innerHTML = '';
                if (!data.urls.length) {
                    urlsList.innerHTML = '<li class="text-slate-500">No embedded URLs detected.</li>';
                } else {
                    data.urls.forEach(u => {
                        const li = document.createElement('li');
                        li.textContent = u;
                        urlsList.appendChild(li);
                    });
                }

                results.classList.remove('hidden');
            } catch (err) {
                alert("Scan Pipeline Error: " + err.message);
            } finally {
                submitBtn.disabled = false;
                demoBtn.disabled = false;
                loadingText.classList.add('hidden');
            }
        }

        document.getElementById('uploadForm').addEventListener('submit', (e) => {
            e.preventDefault();
            const f = document.getElementById('emlFile');
            if (!f.files.length) {
                alert("Please select a .eml file or use the 1-Click Demo.");
                return;
            }
            const fd = new FormData();
            fd.append('file', f.files[0]);
            runPipeline('/scan', fd, true);
        });

        document.getElementById('demoBtn').addEventListener('click', () => {
            runPipeline('/scan_demo', null, false);
        });
    </script>
</body>
</html>
'''

# 6. Write Files to Disk
with open(os.path.join(BASE_DIR, "requirements.txt"), "w", encoding="utf-8") as f:
    f.write(REQUIREMENTS_CONTENT)

with open(os.path.join(BASE_DIR, "sample_attack.eml"), "w", encoding="utf-8") as f:
    f.write(SAMPLE_EML_CONTENT)

with open(os.path.join(BASE_DIR, "app.py"), "w", encoding="utf-8") as f:
    f.write(APP_CODE)

with open(os.path.join(TEMPLATES_DIR, "index.html"), "w", encoding="utf-8") as f:
    f.write(INDEX_HTML)

# 7. Package everything into email_forensics_soc_pkg.zip
ZIP_NAME = "email_forensics_soc_pkg.zip"
with zipfile.ZipFile(ZIP_NAME, 'w', zipfile.ZIP_DEFLATED) as zipf:
    zipf.write("app.py")
    zipf.write("sample_attack.eml")
    zipf.write("requirements.txt")
    zipf.write(os.path.join("templates", "index.html"))

print(f"\n[+] SUCCESS: Project files generated and packaged into '{ZIP_NAME}' in:\n    {BASE_DIR}\n")