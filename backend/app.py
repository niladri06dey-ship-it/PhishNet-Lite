# ============================================================
# PhishNet Lite - Flask Backend (app.py)
# A rule-based phishing URL detection API
# ============================================================

from flask import Flask, request, jsonify
from flask_cors import CORS
import re
import requests
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)

# ---------------- RULE-BASED (STRICT) ----------------
def rule_based_detection(url):
    score = 0
    url_lower = url.lower()

    # 1. HTTP (not HTTPS)
    if url.startswith("http://"):
        score += 2

    # 2. Phishing keywords
    keywords = [
        "login", "verify", "secure", "password",
        "update", "account", "bank", "signin"
    ]
    if any(word in url_lower for word in keywords):
        score += 2

    # 3. Long URL
    if len(url) > 60:
        score += 1

    # 4. @ symbol (VERY suspicious)
    if "@" in url:
        score += 3

    # 5. Suspicious TLDs
    if any(domain in url_lower for domain in [".xyz", ".tk", ".ml", ".ga"]):
        score += 2

    # 6. Too many dots (subdomain trick)
    if url.count('.') > 3:
        score += 2

    # 7. IP address instead of domain
    if re.search(r'\d{1,3}(\.\d{1,3}){3}', url):
        score += 3

    return score


# ---------------- GOOGLE SAFE BROWSING ----------------
def check_google(url):
    API_KEY = os.getenv("GOOGLE_API_KEY")
    if not API_KEY:
        return False

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"

    payload = {
        "client": {"clientId": "phishnet-lite", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        res = requests.post(endpoint, json=payload, timeout=5)
        return res.status_code == 200 and "matches" in res.json()
    except:
        return False


# ---------------- VIRUSTOTAL ----------------
def check_virustotal(url):
    API_KEY = os.getenv("VT_API_KEY")
    if not API_KEY:
        return False

    headers = {"x-apikey": API_KEY}

    try:
        res = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url}
        )

        if res.status_code != 200:
            return False

        analysis_id = res.json()["data"]["id"]

        report = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers
        )

        stats = report.json()["data"]["attributes"]["stats"]
        malicious = stats.get("malicious", 0)

        # stricter threshold
        return malicious >= 2

    except:
        return False


# ---------------- URL VALIDATION ----------------
def is_valid_url(url):
    pattern = re.compile(
        r'^(https?://)?([a-z0-9.-]+)\.([a-z]{2,})',
        re.IGNORECASE
    )
    return bool(pattern.match(url))


# ---------------- MAIN API ----------------
@app.route('/check', methods=['POST'])
def check():
    data = request.get_json()
    url = data.get('url', '')

    if not url or not is_valid_url(url):
        return jsonify({
            "result": "Phishing ❌",
            "label": "Phishing",
            "class": "danger",
            "source": "Invalid URL"
        })

    score = rule_based_detection(url)
    google_flag = check_google(url)
    vt_flag = check_virustotal(url)

    sources = []

    if google_flag:
        sources.append("Google Safe Browsing")

    if vt_flag:
        sources.append("VirusTotal")

    if score >= 5:
        sources.append("Rule Engine")

    # 🔴 FINAL DECISION (STRICT)
    if sources:
        return jsonify({
            "result": "Phishing ❌",
            "label": "Phishing",
            "class": "danger",
            "source": ", ".join(sources)
        })

    return jsonify({
        "result": "Safe ✅",
        "label": "Safe",
        "class": "safe",
        "source": "No threat detected"
    })


# ---------------- RUN ----------------
if __name__ == "__main__":
    print("🛡️ Strict PhishNet running at http://127.0.0.1:5000")
    app.run(debug=True)