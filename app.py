
from flask import Flask, render_template, request
import re
from bs4 import BeautifulSoup
from pexpect import EOF

app = Flask(__name__)

# Phishing me use hone wale common suspicious words
PHISHING_KEYWORDS = [
    "urgent", "immediately", "verify your account", "password expired",
    "account suspended", "unauthorized login", "bank transfer", "action required",
    "update your payment", "click here", "lottery", "congratulations"
]

def analyze_email_text(email_text):
    findings = []
    score = 0
    
    # 1. HTML saaf karke plain text nikalna
    soup = BeautifulSoup(email_text, "html.parser")
    clean_text = soup.get_text()
    lower_text = clean_text.lower()

    # 2. Keywords check karna
    detected_words = [word for word in PHISHING_KEYWORDS if word in lower_text]
    if detected_words:
        score += len(detected_words) * 15
        findings.append(f"Suspicious / Urgency Keywords Mile: {', '.join(detected_words)}")

    # 3. Links (URLs) nikalna aur check karna
    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', email_text)
    defanged_urls = []
    
    for url in urls:
        # Link ko defang karna (taaki galti se click na ho)
        defanged = url.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")
        defanged_urls.append(defanged)
        
        # Check karna agar IP address ka direct link hai (common in phishing)
        if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            score += 30
            findings.append(f"Direct IP URL mila (High Risk): {defanged}")

    if len(urls) > 3:
        score += 15
        findings.append(f"Email me bohot saare links hain ({len(urls)} links)")

    # 4. Header spoofing check (agar headers paste kiye gaye ho)
    if "spf=fail" in lower_text or "received-spf: fail" in lower_text:
        score += 35
        findings.append("SPF Authentication Fail: Sender address nakli ho sakta hai.")
    
    if "dmarc=fail" in lower_text:
        score += 35
        findings.append("DMARC Fail: Domain spoofing detect hui.")

    # Final Result nikalna
    score = min(score, 100)
    if score >= 50:
        verdict = "PHISHING DETECTED (Khatarnaak)"
        color = "red"
    elif score >= 20:
        verdict = "SUSPICIOUS (Dhyan se check kare)"
        color = "orange"
    else:
        verdict = "SAFE / LIKELY LEGITIMATE (Surakshit)"
        color = "green"

    return {
        "verdict": verdict,
        "score": score,
        "color": color,
        "findings": findings,
        "urls": list(set(defanged_urls))
    }

@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    pasted_text = ""
    if request.method == "POST":
        pasted_text = request.form.get("email_text", "")
        if pasted_text.strip():
            result = analyze_email_text(pasted_text)
            
    return render_template("index.html", result=result, pasted_text=pasted_text)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)