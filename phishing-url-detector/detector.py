import re
from urllib.parse import urlparse

def is_ip_address(url):
    return bool(re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", url))


def suspicious_chars(url):
    return bool(re.search(r"[@\-_=]", url))


def url_length_score(url):
    if len(url) < 54:
        return 0
    elif len(url) < 75:
        return 1
    else:
        return 2


def check_phishing(url):
    score = 0
    reasons = []

    parsed = urlparse(url)

    if is_ip_address(url):
        score += 2
        reasons.append("Uses IP address instead of domain")

    if suspicious_chars(url):
        score += 1
        reasons.append("Contains suspicious characters")

    if url_length_score(url) == 2:
        score += 2
        reasons.append("URL is very long")

    if not parsed.scheme.startswith("http"):
        score += 1
        reasons.append("No proper http/https scheme")

    if parsed.netloc.count('.') > 3:
        score += 1
        reasons.append("Too many subdomains")

    return score, reasons


def main():
    print("🎣 Phishing URL Detector (Red Team Edition)")
    url = input("Enter a URL to analyze: ").strip()

    score, reasons = check_phishing(url)

    print("\n--- Analysis ---")
    print("Risk Score:", score)

    if score >= 4:
        print("Verdict: ⚠️ High Risk (Likely Phishing)")
    elif score >= 2:
        print("Verdict: 🟡 Medium Risk (Suspicious)")
    else:
        print("Verdict: 🟢 Low Risk (Likely Safe)")

    if reasons:
        print("\nReasons:")
        for r in reasons:
            print(" -", r)

if __name__ == "__main__":
    main()