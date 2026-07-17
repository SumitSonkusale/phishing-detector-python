"""Unit tests for the URL analyser module.

All tests are purely offline - no network calls are made.
"""

import pytest

from phishing_detector.url_analyzer import analyse_url
from phishing_detector.models import RiskLevel


class TestIpAddressHost:
    def test_ipv4_url_flagged(self):
        findings = analyse_url("http://192.168.1.1/login")
        rules = [f.rule for f in findings]
        assert "IP_ADDRESS_HOST" in rules

    def test_ipv4_url_is_high_risk(self):
        findings = analyse_url("http://10.0.0.1/verify")
        ip_finding = next(f for f in findings if f.rule == "IP_ADDRESS_HOST")
        assert ip_finding.risk == RiskLevel.HIGH

    def test_domain_url_not_flagged_as_ip(self):
        findings = analyse_url("https://example.com/page")
        rules = [f.rule for f in findings]
        assert "IP_ADDRESS_HOST" not in rules


class TestSuspiciousTld:
    def test_tk_tld_flagged(self):
        findings = analyse_url("https://freesite.tk/login")
        rules = [f.rule for f in findings]
        assert "SUSPICIOUS_TLD" in rules

    def test_xyz_tld_flagged(self):
        findings = analyse_url("https://phishing.xyz/verify")
        rules = [f.rule for f in findings]
        assert "SUSPICIOUS_TLD" in rules

    def test_com_tld_not_flagged(self):
        findings = analyse_url("https://example.com")
        rules = [f.rule for f in findings]
        assert "SUSPICIOUS_TLD" not in rules


class TestExcessiveSubdomains:
    def test_four_labels_flagged(self):
        findings = analyse_url("https://secure.paypal.account.attacker.com/login")
        rules = [f.rule for f in findings]
        assert "EXCESSIVE_SUBDOMAINS" in rules

    def test_three_labels_not_flagged(self):
        findings = analyse_url("https://www.example.com/page")
        rules = [f.rule for f in findings]
        assert "EXCESSIVE_SUBDOMAINS" not in rules


class TestUrlShortener:
    def test_bit_ly_flagged(self):
        findings = analyse_url("https://bit.ly/3xK2mPq")
        rules = [f.rule for f in findings]
        assert "URL_SHORTENER" in rules

    def test_tinyurl_flagged(self):
        findings = analyse_url("https://tinyurl.com/abc123")
        rules = [f.rule for f in findings]
        assert "URL_SHORTENER" in rules

    def test_normal_domain_not_flagged(self):
        findings = analyse_url("https://example.com/page")
        rules = [f.rule for f in findings]
        assert "URL_SHORTENER" not in rules


class TestCredentialKeywords:
    def test_login_in_path_flagged(self):
        findings = analyse_url("https://example.com/login/verify")
        rules = [f.rule for f in findings]
        assert "CREDENTIAL_HARVEST_KEYWORDS" in rules

    def test_password_in_query_flagged(self):
        findings = analyse_url("https://example.com/update?password=reset")
        rules = [f.rule for f in findings]
        assert "CREDENTIAL_HARVEST_KEYWORDS" in rules

    def test_benign_path_not_flagged(self):
        findings = analyse_url("https://example.com/products/shoes")
        rules = [f.rule for f in findings]
        assert "CREDENTIAL_HARVEST_KEYWORDS" not in rules


class TestAtSignInUrl:
    def test_at_sign_flagged(self):
        findings = analyse_url("https://evil.com@legitimate.com/path")
        rules = [f.rule for f in findings]
        assert "AT_SIGN_IN_URL" in rules

    def test_normal_url_not_flagged(self):
        findings = analyse_url("https://example.com/path")
        rules = [f.rule for f in findings]
        assert "AT_SIGN_IN_URL" not in rules


class TestNonStandardPort:
    def test_port_8080_flagged(self):
        findings = analyse_url("http://example.com:8080/page")
        rules = [f.rule for f in findings]
        assert "NON_STANDARD_PORT" in rules

    def test_port_443_not_flagged(self):
        findings = analyse_url("https://example.com:443/page")
        rules = [f.rule for f in findings]
        assert "NON_STANDARD_PORT" not in rules

    def test_port_80_not_flagged(self):
        findings = analyse_url("http://example.com:80/page")
        rules = [f.rule for f in findings]
        assert "NON_STANDARD_PORT" not in rules


class TestDoubleSlashRedirect:
    def test_double_slash_in_path_flagged(self):
        findings = analyse_url("https://example.com//evil.com/payload")
        rules = [f.rule for f in findings]
        assert "DOUBLE_SLASH_REDIRECT" in rules

    def test_normal_path_not_flagged(self):
        findings = analyse_url("https://example.com/path/to/page")
        rules = [f.rule for f in findings]
        assert "DOUBLE_SLASH_REDIRECT" not in rules


def test_clean_url_produces_no_findings():
    """A well-formed URL should produce zero findings."""
    findings = analyse_url("https://www.bbc.co.uk/news/world")
    assert findings == []
