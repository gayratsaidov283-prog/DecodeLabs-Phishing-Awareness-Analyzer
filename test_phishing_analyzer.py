import unittest

from phishing_analyzer import (
    analyze_message,
    extract_urls,
    check_keywords,
    check_urls,
)


class TestPhishingAnalyzer(unittest.TestCase):

    def test_safe_message(self):
        message = "Hello John, our meeting is scheduled for tomorrow."
        result = analyze_message(message)

        self.assertEqual(result["classification"], "SAFE")
        self.assertEqual(result["action"], "CLOSE")

    def test_malicious_message(self):
        message = (
            "URGENT! Your account has been suspended. "
            "Verify your account immediately. "
            "Click here: https://secure-account-login.xyz"
        )

        result = analyze_message(message)

        self.assertEqual(result["classification"], "MALICIOUS")
        self.assertEqual(result["action"], "BLOCK & ESCALATE")

    def test_suspicious_message(self):
        message = "Please verify your account and update billing."

        result = analyze_message(message)

        self.assertEqual(result["classification"], "SUSPICIOUS")
        self.assertEqual(result["action"], "WARN USER")

    def test_url_extraction(self):
        message = "Visit https://example.com for information."

        urls = extract_urls(message)

        self.assertEqual(urls, ["https://example.com"])

    def test_suspicious_domain(self):
        message = "Click https://account-security-login.xyz"

        findings, score = check_urls(message)

        self.assertGreater(score, 0)
        self.assertTrue(len(findings) > 0)

    def test_suspicious_keywords(self):
        message = "URGENT! Verify your account immediately."

        findings, score = check_keywords(message)

        self.assertGreater(score, 0)
        self.assertTrue(len(findings) > 0)

    def test_score_limit(self):
        message = (
            "URGENT immediately verify your account password login "
            "click here confirm your identity payment failed "
            "update billing winner prize bank account "
            "https://secure-account-login.xyz"
        )

        result = analyze_message(message)

        self.assertLessEqual(result["score"], 100)


if __name__ == "__main__":
    unittest.main()