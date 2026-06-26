#!/usr/bin/env python3
import os
import re
import json
import hashlib
import sqlite3
import email
from pathlib import Path
from datetime import datetime
from typing import Optional
from io import BytesIO
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
from urllib.request import Request, urlopen
from base64 import b64encode

DB_PATH = "phishing.db"
DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS submissions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT,
  sender TEXT,
  subject TEXT,
  verdict TEXT,
  ioc_count INTEGER,
  file_hash TEXT,
  html_report TEXT
);
CREATE TABLE IF NOT EXISTS iocs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  submission_id INTEGER,
  ioc_type TEXT,
  value TEXT,
  FOREIGN KEY(submission_id) REFERENCES submissions(id)
);
"""

class PhishingAnalyzer:
    def __init__(self):
        self.socint_url = os.getenv("SOCINT_API_URL", "http://localhost:8000/api")
        self.socint_user = os.getenv("SOCINT_USER", "admin@socint.internal")
        self.socint_pass = os.getenv("SOCINT_PASS", "changeme123!")
        self.token = None
        self.init_db()
        self.auth_socint()

    def init_db(self):
        conn = sqlite3.connect(DB_PATH)
        conn.executescript(DB_SCHEMA)
        conn.commit()
        conn.close()

    def auth_socint(self):
        try:
            payload = json.dumps({
                "email": self.socint_user,
                "password": self.socint_pass
            }).encode()
            req = Request(f"{self.socint_url}/auth/login", data=payload, headers={"Content-Type": "application/json"})
            resp = urlopen(req, timeout=5)
            data = json.loads(resp.read())
            self.token = data.get("access_token")
        except Exception as e:
            print(f"SOCint auth failed: {e}")

    def enrich_ioc(self, ioc_type: str, value: str) -> dict:
        if not self.token:
            return {"status": "unknown"}

        try:
            headers = {
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json"
            }
            payload = json.dumps({"type": ioc_type, "value": value}).encode()
            req = Request(f"{self.socint_url}/enrich", data=payload, headers=headers)
            resp = urlopen(req, timeout=5)
            return json.loads(resp.read())
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def extract_iocs(self, email_text: str) -> dict:
        iocs = {"ips": [], "urls": [], "domains": [], "hashes": []}

        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        url_pattern = r'https?://[^\s<>\[\]{}|\\^`"\']+|ftp://[^\s<>\[\]{}|\\^`"\']+'
        domain_pattern = r'(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}'
        hash_pattern = r'\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b'

        iocs["ips"] = list(set(re.findall(ip_pattern, email_text, re.IGNORECASE)))
        iocs["urls"] = list(set(re.findall(url_pattern, email_text, re.IGNORECASE)))
        iocs["domains"] = list(set(re.findall(domain_pattern, email_text.lower())))
        iocs["hashes"] = list(set(re.findall(hash_pattern, email_text.lower())))

        return iocs

    def analyze_email(self, eml_content: bytes) -> dict:
        try:
            msg = email.message_from_bytes(eml_content)
            sender = msg.get("From", "unknown")
            subject = msg.get("Subject", "")
            timestamp = msg.get("Date", datetime.utcnow().isoformat())

            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        body += part.get_payload(decode=True).decode(errors='ignore')
                    elif part.get_content_type() == "text/html":
                        body += part.get_payload(decode=True).decode(errors='ignore')
            else:
                body = msg.get_payload(decode=True).decode(errors='ignore')

            iocs = self.extract_iocs(body + subject + sender)

            malicious_count = 0
            suspicious_count = 0
            clean_count = 0

            for ip in iocs["ips"]:
                result = self.enrich_ioc("ipv4-addr", ip)
                if result.get("status") in ["malicious", "suspicious"]:
                    malicious_count += 1
                elif result.get("status") == "clean":
                    clean_count += 1

            for url in iocs["urls"][:5]:
                result = self.enrich_ioc("url", url)
                if result.get("status") in ["malicious", "suspicious"]:
                    malicious_count += 1

            spf_pass = "pass" in msg.get("Authentication-Results", "").lower()
            dkim_pass = "pass" in msg.get("DKIM-Signature", "").lower() or "pass" in msg.get("Authentication-Results", "").lower()
            dmarc_pass = "pass" in msg.get("Authentication-Results", "").lower()

            verdict = "malicious" if malicious_count > 0 else ("suspicious" if suspicious_count > 1 or not spf_pass else "clean")

            file_hash = hashlib.sha256(eml_content).hexdigest()

            return {
                "sender": sender,
                "subject": subject,
                "timestamp": timestamp,
                "verdict": verdict,
                "iocs": iocs,
                "spf": spf_pass,
                "dkim": dkim_pass,
                "dmarc": dmarc_pass,
                "malicious_count": malicious_count,
                "suspicious_count": suspicious_count,
                "clean_count": clean_count,
                "file_hash": file_hash
            }
        except Exception as e:
            return {"error": str(e)}

    def save_submission(self, analysis: dict) -> int:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            INSERT INTO submissions (timestamp, sender, subject, verdict, ioc_count, file_hash, html_report)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            analysis.get("timestamp"),
            analysis.get("sender"),
            analysis.get("subject"),
            analysis.get("verdict"),
            len(analysis.get("iocs", {}).get("ips", [])) + len(analysis.get("iocs", {}).get("urls", [])),
            analysis.get("file_hash"),
            json.dumps(analysis)
        ))
        submission_id = c.lastrowid

        for ioc_type, values in analysis.get("iocs", {}).items():
            for value in values:
                c.execute("INSERT INTO iocs (submission_id, ioc_type, value) VALUES (?, ?, ?)", (submission_id, ioc_type, value))

        conn.commit()
        conn.close()
        return submission_id

    def submit_iocs_to_socint(self, analysis: dict) -> bool:
        if not self.token:
            return False

        stix_objects = []
        for ip in analysis.get("iocs", {}).get("ips", [])[:10]:
            stix_objects.append({
                "type": "indicator",
                "pattern": f"[ipv4-addr:value = '{ip}']",
                "pattern_type": "stix",
                "indicator_types": ["malicious-activity"],
                "labels": ["phishing", "phishing-analyzer"],
                "x_clawint_source": "phishing-analyzer",
                "confidence": 75,
                "valid_from": datetime.utcnow().isoformat() + "Z"
            })

        for url in analysis.get("iocs", {}).get("urls", [])[:10]:
            stix_objects.append({
                "type": "indicator",
                "pattern": f"[url:value = '{url}']",
                "pattern_type": "stix",
                "indicator_types": ["malicious-activity"],
                "labels": ["phishing", "phishing-analyzer"],
                "x_clawint_source": "phishing-analyzer",
                "confidence": 75,
                "valid_from": datetime.utcnow().isoformat() + "Z"
            })

        if not stix_objects:
            return True

        try:
            headers = {
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json"
            }
            payload = json.dumps(stix_objects).encode()
            req = Request(f"{self.socint_url}/intel/bulk", data=payload, headers=headers, method="POST")
            resp = urlopen(req, timeout=10)
            return resp.status == 200
        except Exception as e:
            print(f"Failed to submit IOCs: {e}")
            return False

MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_SIZE_MB", "50")) * 1024 * 1024

analyzer = PhishingAnalyzer()

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            html = """
<!DOCTYPE html>
<html><head><title>Phishing Analyzer</title><style>
body{font-family:sans-serif;max-width:1000px;margin:50px auto;background:#0a0e27;color:#e0e0e0;padding:20px}
.container{background:#1a1f3a;border:1px solid #444;padding:20px;border-radius:8px}
h1{color:#ff6b6b;margin:0}
input,textarea{width:100%;padding:10px;margin:10px 0;background:#2d3748;border:1px solid #555;color:#e0e0e0;border-radius:4px}
button{background:#ff6b6b;color:white;padding:10px 20px;border:none;border-radius:4px;cursor:pointer;font-weight:bold}
button:hover{background:#ff5252}
.result{margin-top:20px;padding:15px;background:#2d3748;border-radius:4px;border-left:4px solid}
.malicious{border-left-color:#ff6b6b}
.suspicious{border-left-color:#ffd93d}
.clean{border-left-color:#6bcf7f}
table{width:100%;border-collapse:collapse;margin:10px 0}
th,td{text-align:left;padding:8px;border-bottom:1px solid #444}
th{background:#3d4758;color:#ff6b6b}
</style></head><body>
<div class="container">
<h1>Phishing Analyzer</h1>
<p>Upload .eml file or paste email raw text</p>
<form id="form" onsubmit="return submit_form()">
<input type="file" id="file" accept=".eml" placeholder="Email file (.eml)">
<textarea id="raw" rows="5" placeholder="Or paste raw email text here..."></textarea>
<button type="submit">Analyze Email</button>
</form>
<div id="output"></div>
</div>
<script>
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
async function submit_form(){
  const file = document.getElementById('file').files[0];
  const raw = document.getElementById('raw').value;

  if(!file && !raw) return alert('Upload file or paste text'), false;

  const fd = new FormData();
  if(file) fd.append('file', file);
  else fd.append('raw', raw);

  const r = await fetch('/analyze', {method:'POST', body: fd});
  const data = await r.json();

  const safe_verdict = esc(data.verdict || 'suspicious');
  let html = `<div class="result ${safe_verdict}"><strong>Verdict: ${safe_verdict.toUpperCase()}</strong><br>
From: ${esc(data.sender || '?')}<br>Subject: ${esc(data.subject || '?')}<br>Timestamp: ${esc(data.timestamp || '?')}<br>
Malicious: ${esc(String(data.malicious_count || 0))} | Suspicious: ${esc(String(data.suspicious_count || 0))} | Clean: ${esc(String(data.clean_count || 0))}<br>
SPF: ${data.spf?'PASS':'FAIL'} | DKIM: ${data.dkim?'PASS':'FAIL'} | DMARC: ${data.dmarc?'PASS':'FAIL'}<br>`;

  if(data.iocs) {
    html += '<table><tr><th>Type</th><th>Value</th><th>Verdict</th></tr>';
    const iocs = data.iocs;
    const pairs = [
      ...(iocs.ips||[]).map(v=>['ip',v]),
      ...(iocs.urls||[]).map(v=>['url',v]),
      ...(iocs.domains||[]).map(v=>['domain',v])
    ];
    pairs.forEach(([t,v]) => {
      html += `<tr><td>${esc(t)}</td><td>${esc(v)}</td><td>-</td></tr>`;
    });
    html += '</table>';
  }
  html += '</div>';
  document.getElementById('output').innerHTML = html;
  return false;
}
</script>
</body></html>
"""
            self.wfile.write(html.encode())
        elif self.path == "/api/stats":
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("SELECT COUNT(*), verdict FROM submissions GROUP BY verdict")
            stats = {row[1]: row[0] for row in c.fetchall()}
            conn.close()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "total_submissions": sum(stats.values()),
                "verdicts": stats
            }).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/analyze":
            content_len = int(self.headers.get("Content-Length", 0))
            if content_len > MAX_UPLOAD_BYTES:
                self.send_response(413)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "upload too large"}).encode())
                return
            body = self.rfile.read(content_len)

            try:
                from urllib.parse import parse_qs
                import cgi
                ct = self.headers.get("Content-Type", "")

                if "multipart/form-data" in ct:
                    boundary = ct.split("boundary=")[1].encode()
                    parts = body.split(b"--" + boundary)
                    eml_content = None
                    for part in parts:
                        if b"filename=" in part:
                            eml_content = part.split(b"\r\n\r\n", 1)[1].rsplit(b"\r\n", 1)[0]
                            break
                    if not eml_content:
                        raise ValueError("No file found")
                else:
                    parsed = parse_qs(body.decode())
                    raw = parsed.get("raw", [""])[0]
                    eml_content = raw.encode()

                analysis = analyzer.analyze_email(eml_content)
                if "error" not in analysis:
                    submission_id = analyzer.save_submission(analysis)
                    analyzer.submit_iocs_to_socint(analysis)

                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(analysis).encode())
            except Exception as e:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass

if __name__ == "__main__":
    port = int(os.getenv("PHISHING_PORT", 8091))
    host = os.getenv("PHISHING_HOST", "0.0.0.0")
    server = HTTPServer((host, port), Handler)
    print(f"Phishing Analyzer running on http://{host}:{port}")
    server.serve_forever()
