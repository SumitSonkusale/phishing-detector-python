"""Unit tests for the email header analyser module."""

from phishing_detector.header_analyzer import analyse_headers
from phishing_detector.models import RiskLevel


# Minimal valid email with no anomalies
_CLEAN_EMAIL = """From: Alice <alice@example.com>
To: Bob <bob@example.com>
Subject: Hello
Message-ID: <abc123@example.com>
Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass

This is a normal email.
"""

_REPLY_TO_MISMATCH = """From: Alice <alice@example.com>
Reply-To: attacker <attacker@evil.com>
To: Bob <bob@example.com>
Subject: Important
Message-ID: <msg1@example.com>
Authentication-Results: mx.example.com; spf=pass

Please reply to me.
"""

_BRAND_SPOOF = """From: PayPal Security <noreply@random123.com>
To: victim@example.com
Subject: Urgent: Verify your account
Message-ID: <msg2@random123.com>
Authentication-Results: mx.example.com; spf=fail

Verify your account now.
"""

_AUTH_FAIL = """From: Service <service@example.com>
To: user@example.com
Subject: Notice
Message-ID: <msg3@example.com>
Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail

Hello.
"""

_NO_MESSAGE_ID = """From: Sender <sender@example.com>
To: user@example.com
Subject: Test
Authentication-Results: mx.example.com; spf=pass

Hello.
"""

_FREE_EMAIL_BUSINESS = """From: Barclays Bank Support <barclays-support@gmail.com>
To: customer@example.com
Subject: Your account
Message-ID: <msg4@gmail.com>
Authentication-Results: mx.example.com; spf=pass

Please verify.
"""


class TestReplyToMismatch:
    def test_mismatch_flagged(self):
        findings = analyse_headers(_REPLY_TO_MISMATCH)
        rules = [f.rule for f in findings]
        assert "REPLY_TO_MISMATCH" in rules

    def test_mismatch_is_high_risk(self):
        findings = analyse_headers(_REPLY_TO_MISMATCH)
        f = next(x for x in findings if x.rule == "REPLY_TO_MISMATCH")
        assert f.risk == RiskLevel.HIGH

    def test_no_mismatch_on_clean_email(self):
        findings = analyse_headers(_CLEAN_EMAIL)
        rules = [f.rule for f in findings]
        assert "REPLY_TO_MISMATCH" not in rules


class TestBrandSpoof:
    def test_paypal_brand_spoof_detected(self):
        findings = analyse_headers(_BRAND_SPOOF)
        rules = [f.rule for f in findings]
        assert "DISPLAY_NAME_BRAND_SPOOF" in rules

    def test_clean_email_no_spoof(self):
        findings = analyse_headers(_CLEAN_EMAIL)
        rules = [f.rule for f in findings]
        assert "DISPLAY_NAME_BRAND_SPOOF" not in rules


class TestAuthResults:
    def test_auth_failure_flagged(self):
        findings = analyse_headers(_AUTH_FAIL)
        rules = [f.rule for f in findings]
        assert "AUTH_FAILURE" in rules

    def test_clean_email_no_auth_failure(self):
        findings = analyse_headers(_CLEAN_EMAIL)
        rules = [f.rule for f in findings]
        assert "AUTH_FAILURE" not in rules

    def test_missing_auth_results_flagged(self):
        raw = "From: a@b.com\nTo: c@d.com\nSubject: Hi\nMessage-ID: <x>\n\nHello"
        findings = analyse_headers(raw)
        rules = [f.rule for f in findings]
        assert "MISSING_AUTH_RESULTS" in rules


class TestMissingMessageId:
    def test_no_message_id_flagged(self):
        findings = analyse_headers(_NO_MESSAGE_ID)
        rules = [f.rule for f in findings]
        assert "MISSING_MESSAGE_ID" in rules

    def test_with_message_id_not_flagged(self):
        findings = analyse_headers(_CLEAN_EMAIL)
        rules = [f.rule for f in findings]
        assert "MISSING_MESSAGE_ID" not in rules


class TestFreeEmailBusinessSpoof:
    def test_bank_via_gmail_flagged(self):
        findings = analyse_headers(_FREE_EMAIL_BUSINESS)
        rules = [f.rule for f in findings]
        assert "FREE_EMAIL_BUSINESS_SPOOF" in rules


def test_clean_email_produces_minimal_findings():
    """A clean email should produce at most low-risk findings only."""
    findings = analyse_headers(_CLEAN_EMAIL)
    high_risk = [f for f in findings if f.risk == RiskLevel.HIGH]
    assert len(high_risk) == 0
