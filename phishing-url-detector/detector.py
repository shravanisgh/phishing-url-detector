import re
from urllib.parse import urlparse

PHISHING_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "bank", "signin", "confirm", "password"
]

BRANDS = ["paypal", "google", "facebook", "amazon", "microsoft", "apple", "netflix"]


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


def keyword_score(url):
    score = 0
    reasons = []
    for word in PHISHING_KEYWORDS:
        if word in url.lower():
            score += 1
            reasons.append(f"Contains phishing keyword: '{word}'")
    return score, reasons


def brand_impersonation_score(url):
    score = 0
    reasons = []
    for brand in BRANDS:
        if brand in url.lower() and not url.lower().startswith("https://" + brand):
            score += 2
            reasons.append(f"Possible brand impersonation: '{brand}'")
    return score, reasons


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

    length_score = url_length_score(url)
    if length_score == 2:
        score += 2
        reasons.append("URL is very long")

    if parsed.scheme != "https":
        score += 2
        reasons.append("Not using HTTPS")

    if parsed.netloc.count('.') > 3:
        score += 1
        reasons.append("Too many subdomains")

    k_score, k_reasons = keyword_score(url)
    score += k_score
    reasons.extend(k_reasons)

    b_score, b_reasons = brand_impersonation_score(url)
    score += b_score
    reasons.extend(b_reasons)

    return score, reasons


def main():
    print("🎣 Phishing URL Detector (Red Team Edition)")
    url = input("Enter a URL to analyze: ").strip()

    score, reasons = check_phishing(url)

    print("\n--- Analysis ---")
    print("Risk Score:", score)

    if score >= 7:
        print("Verdict: 🔴 High Risk (Likely Phishing)")
    elif score >= 3:
        print("Verdict: 🟡 Medium Risk (Suspicious)")
    else:
        print("Verdict: 🟢 Low Risk (Likely Safe)")

    if reasons:
        print("\nReasons:")
        for r in reasons:
            print(" -", r)


if __name__ == "__main__":
    main()
