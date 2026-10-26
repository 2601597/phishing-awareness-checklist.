import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
from url_red_flag_checker import analyse, defang, verdict  # noqa: E402


class AnalyseTests(unittest.TestCase):
    def test_clean_https_url_is_low(self):
        score, flags = analyse("https://www.example.com/")
        self.assertEqual(flags, [])
        self.assertEqual(verdict(score), "LOW")

    def test_ip_address_host_is_flagged_even_without_scheme(self):
        # Regression test: scheme-less URLs must still get host checks.
        score, flags = analyse("192.168.0.1/login")
        self.assertTrue(any("IP address" in f for f in flags))

    def test_at_symbol_is_flagged(self):
        _, flags = analyse("https://paypal.com@evil.example/pay")
        self.assertTrue(any("'@'" in f for f in flags))

    def test_punycode_is_flagged(self):
        _, flags = analyse("https://xn--pple-43d.example/")
        self.assertTrue(any("Punycode" in f for f in flags))

    def test_shortener_is_flagged(self):
        _, flags = analyse("https://bit.ly/3abcde")
        self.assertTrue(any("shortener" in f for f in flags))

    def test_plain_http_is_flagged_but_missing_scheme_is_not(self):
        _, with_http = analyse("http://example.com")
        _, no_scheme = analyse("example.com")
        self.assertTrue(any("HTTPS" in f for f in with_http))
        self.assertFalse(any("HTTPS" in f for f in no_scheme))

    def test_obvious_phish_scores_high(self):
        score, _ = analyse("http://192.168.0.1:8080/secure-login-verify@account")
        self.assertEqual(verdict(score), "HIGH")


class HelperTests(unittest.TestCase):
    def test_defang(self):
        self.assertEqual(defang("https://example.com"), "hxxps://example[.]com")

    def test_verdict_thresholds(self):
        self.assertEqual([verdict(n) for n in (0, 1, 2, 3, 4)],
                         ["LOW", "LOW", "MEDIUM", "MEDIUM", "HIGH"])


if __name__ == "__main__":
    unittest.main()
