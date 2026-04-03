# 🛡️ PhishNet Lite — Real-Time Phishing Detector

A lightweight, real-time phishing detection tool that analyzes URLs using a multi-layered security approach combining rule-based logic and external threat intelligence APIs.

---

## 🚀 Overview

Phishing attacks trick users into revealing sensitive data through fake websites.  
PhishNet Lite helps detect such threats instantly by analyzing URLs before users visit them.

---

## ⚡ Key Features

- 🔍 Real-time URL scanning
- 🧠 Rule-based detection engine
- 🌐 Google Safe Browsing API integration
- 🧪 VirusTotal API integration
- 📊 Binary classification:
  - ✅ Safe  
  - ❌ Phishing  
- 🎯 Shows detection source (Rule / Google / VirusTotal)
- 🎨 Interactive UI with animations

---

## 🧠 Detection Architecture

User Input URL  
↓  
Rule-Based Analysis  
↓  
Google Safe Browsing  
↓  
VirusTotal  
↓  
Final Decision (Safe / Phishing)

---

## 📂 Project Structure


phishnet-lite/
│
├── frontend/
│ ├── index.html
│ ├── style.css
│ └── script.js
│
├── backend/
│ ├── app.py
│ └── .env
│
└── README.md


---

## ⚙️ Setup Guide

### 🔧 Backend

```bash
cd backend
pip install Flask Flask-Cors python-dotenv requests
python app.py

Server runs at:

http://127.0.0.1:5000
🔑 Environment Variables (.env)
GOOGLE_API_KEY=your_google_api_key
VT_API_KEY=your_virustotal_api_key
🌐 Frontend
Open frontend/index.html in browser
OR
Use Live Server in VS Code
▶️ API Endpoint

POST /check

Request
{
  "url": "http://example.com"
}
Response

Safe

{
  "result": "Safe ✅",
  "label": "Safe",
  "source": "No threat detected"
}

Phishing

{
  "result": "Phishing ❌",
  "label": "Phishing",
  "source": "Rule Engine / Google Safe Browsing / VirusTotal"
}
🧪 Testing URLs
Safe
https://google.com
https://github.com
Phishing
http://fake-login-bank.com
http://testsafebrowsing.appspot.com/s/phishing.html
🎯 Detection Logic
If ANY system detects threat → Phishing ❌
Else → Safe ✅
🎯 Use Cases
Cybersecurity awareness
Hackathon project
Educational demo
⚠️ Limitations
Depends on rule heuristics and API coverage
Free API rate limits
🚀 Future Improvements
🤖 Machine Learning detection
🌐 Browser extension
☁️ Cloud deployment


👨‍💻 Author

Niladri Dey
Mayukh Pal
Badhon Banerjee


🏆 Pitch Line

"PhishNet Lite uses a multi-engine detection system combining heuristic analysis and real-time threat intelligence APIs."
