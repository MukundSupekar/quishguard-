import unittest
from pathlib import Path
from quishguard.url_analyzer import analyze_url
from quishguard.phishing_engine import phishing_engine
from quishguard.malware_engine import malware_engine
from quishguard.risk_engine import risk_scoring_engine
from quishguard.threat_intel import threat_intel_manager
from quishguard.redirect_tracer import redirect_tracer
from quishguard.qr_engine import qr_engine
from quishguard.pdf_extractor import pdf_extractor

class TestQuishGuardDetection(unittest.TestCase):

    def test_url_analyzer_normalization(self):
        # Test default port stripping and lowercase normalization
        res = analyze_url("HTTP://EXAMPLE.COM:80/path/test?param=1")
        self.assertTrue(res.is_url)
        self.assertEqual(res.scheme, "http")
        self.assertEqual(res.hostname, "example.com")
        self.assertEqual(res.normalized_url, "http://example.com/path/test?param=1")

    def test_url_analyzer_ip_address(self):
        # Direct IP detection
        res = analyze_url("http://192.168.1.1/admin")
        self.assertTrue(res.is_ip)
        self.assertIn("direct IP", res.anomalies[0])

    def test_url_analyzer_homograph(self):
        # Punycode or Cyrillic 'a' (\u0430)
        res = analyze_url("https://xn--pple-43d.com")
        self.assertTrue(res.has_homograph)

    def test_phishing_typosquatting(self):
        # 'paypa1' typosquatting vs 'paypal'
        findings = phishing_engine.check_brand_impersonation("https://paypa1-security.com", "paypa1-security", "")
        self.assertTrue(len(findings) > 0)
        self.assertEqual(findings[0]["brand"], "paypal")

    def test_phishing_official_brand_whitelist(self):
        # Official paypal.com must not be flagged as brand impersonation
        findings = phishing_engine.check_brand_impersonation("https://www.paypal.com/signin", "paypal", "www")
        self.assertEqual(len(findings), 0)

    def test_phishing_keywords(self):
        # Credential and urgency keywords
        findings = phishing_engine.check_lexical_keywords("https://example.com/account/login/verify?action=urgent-suspended")
        types = [f["type"] for f in findings]
        self.assertIn("CREDENTIAL_HARVESTING_KEYWORDS", types)
        self.assertIn("URGENCY_KEYWORDS", types)

    def test_malware_file_extension(self):
        # Direct executable download
        findings = malware_engine.check_file_extensions("/downloads/setup.exe")
        self.assertTrue(len(findings) > 0)
        self.assertEqual(findings[0]["extension"], ".exe")

    def test_malware_double_extension(self):
        # Deceptive invoice.pdf.exe
        findings = malware_engine.check_file_extensions("/files/invoice.pdf.exe")
        self.assertTrue(len(findings) > 0)
        self.assertEqual(findings[0]["type"], "DOUBLE_EXTENSION_DECEPTION")

    def test_risk_scoring_clean(self):
        # Safe educational domain
        url_res = analyze_url("https://www.ox.ac.uk/research")
        red_res = {"redirect_count": 0, "has_cross_domain_redirect": False, "is_loop": False, "chain": []}
        phish_res = {"phishing_score": 0, "indicators": []}
        mal_res = {"malware_score": 0, "indicators": []}
        intel_res = {"overall_verdict": "CLEAN", "findings": []}
        
        score_data = risk_scoring_engine.evaluate(url_res, red_res, phish_res, mal_res, intel_res)
        self.assertLessEqual(score_data["risk_score"], 20)
        self.assertEqual(score_data["classification"], "SAFE")
        self.assertEqual(score_data["recommendation"], "ALLOW")

    def test_risk_scoring_phishing(self):
        # High risk phishing
        url_res = analyze_url("https://paypa1-security-check.xyz/login/verify?account=urgent")
        red_res = {"redirect_count": 0, "has_cross_domain_redirect": False, "is_loop": False, "chain": []}
        phish_res = phishing_engine.analyze(url_res.normalized_url, "paypa1-security-check", "", "/login/verify")
        mal_res = {"malware_score": 0, "indicators": []}
        intel_res = threat_intel_manager.query_threat_intel(url_res.registered_domain, url_res.normalized_url)
        
        score_data = risk_scoring_engine.evaluate(url_res, red_res, phish_res, mal_res, intel_res)
        self.assertGreaterEqual(score_data["risk_score"], 60)
        self.assertIn("PHISHING", score_data["classification"])
        self.assertEqual(score_data["recommendation"], "BLOCK")

if __name__ == "__main__":
    unittest.main()
