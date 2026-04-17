from flask import Flask, request, jsonify
from flask_cors import CORS
import re, requests, os, datetime
from dotenv import load_dotenv
from pymongo import MongoClient
from urllib.parse import urlparse

# Safe import for whois
try:
    import whois
except:
    whois = None

load_dotenv()

app = Flask(__name__)
CORS(app)

# ---------------- ENV ----------------
MONGO_URI = os.getenv("MONGO_URI")
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

# ---------------- MONGODB (SAFE INIT) ----------------
try:
    client = MongoClient(MONGO_URI)
    db = client["phishnet"]
    collection = db["logs"]
except:
    collection = None

# ---------------- HOME ----------------
@app.route('/')
def home():
    return "🛡️ PhishNet Lite Backend Running"

# ---------------- RULE ENGINE ----------------
def rule_based_detection(url):
    score = 0
    url_lower = url.lower()

    if url.startswith("http://"):
        score += 3

    if any(k in url_lower for k in [
        "login","verify","secure","password",
        "update","account","bank","signin",
        "otp","payment","confirm"
    ]):
        score += 3

    if len(url) > 75:
        score += 2

    if "@" in url:
        score += 4

    if any(d in url_lower for d in [".xyz",".tk",".ml",".ga",".cf",".gq"]):
        score += 3

    if url.count('.') > 3:
        score += 3

    if re.search(r'\d{1,3}(\.\d{1,3}){3}', url):
        score += 4

    if url.count('-') > 2:
        score += 2

    return score

# ---------------- BRAND SPOOF ----------------
def detect_brand_spoofing(url):
    brands = ["google","facebook","amazon","paytm","upi","bank","sbi","icici","hdfc"]
    score = 0

    for b in brands:
        if b in url.lower() and not url.endswith(f"{b}.com"):
            score += 2

    return score

# ---------------- GOOGLE SAFE BROWSING ----------------
def check_google_safe_browsing(url):
    if not GOOGLE_API_KEY:
        return False

    try:
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
        body = {
            "client": {"clientId": "phishnet", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }

        res = requests.post(endpoint, json=body, timeout=3)
        data = res.json()

        return bool(data.get("matches"))
    except:
        return False

# ---------------- DOMAIN AGE ----------------
def domain_age_check(url):
    if not whois:
        return 1

    try:
        domain = urlparse(url).netloc
        info = whois.whois(domain)

        creation_date = info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            return 1

        age_days = (datetime.datetime.now() - creation_date).days

        if age_days < 30:
            return 3
        elif age_days < 180:
            return 2
        else:
            return 0
    except:
        return 1

# ---------------- VALIDATION ----------------
def is_valid_url(url):
    return bool(re.match(r'^(https?://)?([a-z0-9.-]+)\.([a-z]{2,})', url, re.I))

# ---------------- MAIN API ----------------
@app.route('/check', methods=['POST'])
def check():
    data = request.get_json()
    url = data.get('url', '')

    if not url or not is_valid_url(url):
        result = {
            "result": "Phishing ❌",
            "label": "Phishing",
            "class": "phishing",
            "source": "Invalid URL"
        }
    else:
        score = 0

        # 🔥 Core logic
        score += rule_based_detection(url)
        score += detect_brand_spoofing(url)

        # 🔥 Google check
        if check_google_safe_browsing(url):
            score += 5

        # 🔥 WHOIS (safe)
        try:
            score += domain_age_check(url)
        except:
            pass

        # ---------------- DECISION ----------------
        if score >= 6:
            result = {
                "result": "Phishing ❌",
                "label": "Phishing",
                "class": "phishing",
                "source": "Threat Intelligence + Rules"
            }
        elif score >= 3:
            result = {
                "result": "Suspicious ⚠️",
                "label": "Phishing",
                "class": "phishing",
                "source": "Suspicious Patterns"
            }
        else:
            result = {
                "result": "Safe ✅",
                "label": "Safe",
                "class": "safe",
                "source": "No major threats"
            }

    # ---------------- SAVE ----------------
    if collection is not None:
        try:
            collection.insert_one({
                "url": url,
                **result,
                "time": datetime.datetime.now(datetime.timezone.utc)
            })
        except:
            pass

    return jsonify(result)

# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))