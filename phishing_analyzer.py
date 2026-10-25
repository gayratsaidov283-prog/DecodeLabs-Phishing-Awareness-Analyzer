import re
from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = {
    "urgent": 10,
    "immediately": 10,
    "verify your account": 20,
    "account suspended": 20,
    "password": 15,
    "login": 10,
    "click here": 15,
    "confirm your identity": 20,
    "payment failed": 15,
    "update billing": 15,
    "winner": 15,
    "prize": 15,
    "bank account": 15,
}

SUSPICIOUS_TLDS = {
    ".xyz",
    ".top",
    ".click",
    ".zip",
    ".tk",
}


def extract_urls(text):
    """Extract URLs from a message."""
    return re.findall(r"https?://[^\s]+", text)


def check_keywords(text):
    """Find suspicious phishing-related keywords."""
    text_lower = text.lower()
    findings = []
    score = 0

    for keyword, points in SUSPICIOUS_KEYWORDS.items():
        if keyword in text_lower:
            findings.append(f"Suspicious keyword: '{keyword}'")
            score += points

    return findings, score


def check_urls(text):
    """Analyze URLs for basic phishing indicators."""
    findings = []
    score = 0

    urls = extract_urls(text)

    for url in urls:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        if "@" in url:
            findings.append(f"URL contains @ symbol: {url}")
            score += 25

        if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
            findings.append(f"Suspicious domain extension: {domain}")
            score += 25

        if domain.count("-") >= 2:
            findings.append(f"Suspicious domain structure: {domain}")
            score += 15

        if len(domain) > 40:
            findings.append(f"Unusually long domain: {domain}")
            score += 10

    return findings, score


def analyze_message(message):
    """Analyze a message and return phishing risk information."""
    findings = []
    score = 0

    keyword_findings, keyword_score = check_keywords(message)
    url_findings, url_score = check_urls(message)

    findings.extend(keyword_findings)
    findings.extend(url_findings)

    score += keyword_score
    score += url_score

    score = min(score, 100)

    if score >= 60:
        classification = "MALICIOUS"
        action = "BLOCK & ESCALATE"
    elif score >= 25:
        classification = "SUSPICIOUS"
        action = "WARN USER"
    else:
        classification = "SAFE"
        action = "CLOSE"

    return {
        "score": score,
        "classification": classification,
        "action": action,
        "findings": findings,
    }


def main():
    print("=" * 50)
    print("Decode Labs - Project 3")
    print("Phishing Awareness Analyzer")
    print("=" * 50)

    message = input("\nEnter email/message to analyze:\n> ")

    result = analyze_message(message)

    print("\n--- Analysis Results ---")

    if result["findings"]:
        for finding in result["findings"]:
            print(f"[!] {finding}")
    else:
        print("[+] No obvious phishing indicators detected.")

    print(f"\nRisk Score: {result['score']}/100")
    print(f"Classification: {result['classification']}")
    print(f"Recommended Action: {result['action']}")

    print("\nSecurity Rule: PAUSE -> VERIFY -> REPORT")


if __name__ == "__main__":
    main()