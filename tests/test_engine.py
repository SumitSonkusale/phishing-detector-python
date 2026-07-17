"""Integration tests for the detection engine and body analyser.

These tests exercise the full pipeline: headers + body + URLs through
the engine, and also target specific body analysis rules.
"""

from phishing_detector.engine import analyse_email, analyse_url_only
from phishing_detector.body_analyzer import analyse_body
from phishing_detector.models import RiskLevel


# ---------------------------------------------------------------------------
# Sample emails
# ---------------------------------------------------------------------------

_CLEAN_EMAIL = """From: Alice <alice@example.com>
To: Bob <bob@example.com>
Subject: Meeting tomorrow
Message-ID: <clean@example.com>
Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass

Hi Bob, just confirming our meeting tomorrow at 2pm.
"""

_PHISHING_EMAIL = """From: PayPal Security <security@random-domain.xyz>
Reply-To: attacker@evil.com
To: victim@example.com
Subject: URGENT: Your account will be suspended
Message-ID: <ph1@random-domain.xyz>
Authentication-Results: mx.example.com; spf=fail; dkim=fail

Your account will be suspended. Verify your account immediately.
Please confirm your password and login credentials at:
https://192.168.99.1/login/verify?password=reset
"""

_URGENCY_EMAIL = """From: Service <service@example.com>
To: user@example.com
Subject: Act now
Message-ID: <urgency1@example.com>
Authentication-Results: mx.example.com; spf=pass

Your account will be suspended. Act immediately to avoid termination.
"""

_HTML_ANCHOR_MISMATCH = """From: Legitimate <info@bank.com>
To: user@example.com
Subject: Check this
Message-ID: <html1@bank.com>
Authentication-Results: mx.example.com; spf=pass
Content-Type: text/html

<html><body>
<p>Click here: <a href="https://evil-phishing.xyz/steal">https://www.bank.com/login</a></p>
</body></html>
"""


# ---------------------------------------------------------------------------
# Engine: analyse_email
# ---------------------------------------------------------------------------

class TestAnalyseEmail:
    def test_phishing_email_returns_high_risk(self):
        result = analyse_email(_PHISHING_EMAIL)
        assert result.overall_risk == RiskLevel.HIGH

    def test_phishing_email_score_above_50(self):
        result = analyse_email(_PHISHING_EMAIL)
        assert result.score > 50

    def test_clean_email_no_high_risk_findings(self):
        result = analyse_email(_CLEAN_EMAIL)
        high_findings = [f for f in result.findings if f.risk == RiskLevel.HIGH]
        assert len(high_findings) == 0

    def test_result_has_summary(self):
        result = analyse_email(_PHISHING_EMAIL)
        assert len(result.summary) > 0

    def test_findings_are_deduplicated(self):
        result = analyse_email(_PHISHING_EMAIL)
        keys = [(f.category, f.rule, f.evidence[:80]) for f in result.findings]
        assert len(keys) == len(set(map(tuple, keys)))

    def test_extra_urls_are_analysed(self):
        result = analyse_email(_CLEAN_EMAIL, extra_urls=["https://bit.ly/suspect"])
        rules = [f.rule for f in result.findings]
        assert "URL_SHORTENER" in rules


# ---------------------------------------------------------------------------
# Engine: analyse_url_only
# ---------------------------------------------------------------------------

class TestAnalyseUrlOnly:
    def test_suspicious_url_returns_findings(self):
        result = analyse_url_only("https://192.168.0.1/login/verify")
        assert len(result.findings) > 0

    def test_clean_url_returns_low_risk(self):
        result = analyse_url_only("https://www.gov.uk/passport")
        assert result.overall_risk == RiskLevel.LOW
        assert result.score == 0


# ---------------------------------------------------------------------------
# Body analyser: urgency
# ---------------------------------------------------------------------------

class TestBodyUrgency:
    def test_urgency_language_flagged(self):
        findings = analyse_body(_URGENCY_EMAIL)
        rules = [f.rule for f in findings]
        assert "URGENCY_LANGUAGE" in rules

    def test_urgency_is_medium_risk(self):
        findings = analyse_body(_URGENCY_EMAIL)
        f = next(x for x in findings if x.rule == "URGENCY_LANGUAGE")
        assert f.risk == RiskLevel.MEDIUM


# ---------------------------------------------------------------------------
# Body analyser: anchor mismatch
# ---------------------------------------------------------------------------

class TestBodyAnchorMismatch:
    def test_anchor_mismatch_flagged(self):
        findings = analyse_body(_HTML_ANCHOR_MISMATCH)
        rules = [f.rule for f in findings]
        assert "ANCHOR_MISMATCH" in rules

    def test_anchor_mismatch_is_high_risk(self):
        findings = analyse_body(_HTML_ANCHOR_MISMATCH)
        f = next(x for x in findings if x.rule == "ANCHOR_MISMATCH")
        assert f.risk == RiskLevel.HIGH


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

class TestScoring:
    def test_score_bounded_at_100(self):
        """Score must never exceed 100 regardless of how many findings exist."""
        result = analyse_email(_PHISHING_EMAIL)
        assert result.score <= 100

    def test_score_is_zero_for_no_findings(self):
        result = analyse_url_only("https://www.gov.uk/passport")
        assert result.score == 0
