"""Email header analysis module.

Parses raw RFC 2822 email headers and checks for anomalies that are
commonly seen in phishing emails:
  - Reply-To / From mismatch
  - Suspicious X-Mailer or user-agent strings
  - Missing or failing SPF/DKIM/DMARC authentication results
  - Received-chain inconsistencies (hop count, private-IP origination)
  - Mismatched display name vs. actual address
  - Use of free email provider in a spoofed corporate-looking From

Design note: this module uses only the stdlib ``email`` package, so no
additional dependencies are required.
"""

from __future__ import annotations

import re
from email import message_from_string
from email.message import Message
from typing import List, Optional

from .models import Finding, RiskLevel

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_FREE_EMAIL_DOMAINS: frozenset[str] = frozenset([
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "aol.com", "protonmail.com", "icloud.com", "mail.com",
    "yandex.com", "zoho.com",
])

# Strings in X-Mailer / X-Originating-IP that suggest bulk/spam tools
_SUSPICIOUS_MAILER_RE = re.compile(
    r"(mass ?mailer|phpmailer|sendblaster|mailchimp|bulk|spam)",
    re.IGNORECASE,
)

# Pattern for extracting email address from "Display Name <addr>" format
_ADDR_RE = re.compile(r"<([^>]+)>")

# Authentication-Results pass/fail patterns
_AUTH_PASS_RE = re.compile(r"(spf|dkim|dmarc)\s*=\s*pass", re.IGNORECASE)
_AUTH_FAIL_RE = re.compile(r"(spf|dkim|dmarc)\s*=\s*(fail|none|neutral|softfail|permerror|temperror)", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyse_headers(raw_email: str) -> List[Finding]:
    """Parse raw email text and return phishing-related header Findings.

    Args:
        raw_email: Full raw email string (headers + optional body). Only
                   headers are inspected by this module; body analysis is
                   handled by :mod:`~phishing_detector.body_analyzer`.

    Returns:
        A list of :class:`~phishing_detector.models.Finding` objects.
    """
    msg: Message = message_from_string(raw_email)
    findings: List[Finding] = []

    findings.extend(_check_reply_to_mismatch(msg))
    findings.extend(_check_display_name_mismatch(msg))
    findings.extend(_check_free_email_spoofing(msg))
    findings.extend(_check_auth_results(msg))
    findings.extend(_check_suspicious_mailer(msg))
    findings.extend(_check_received_chain(msg))
    findings.extend(_check_missing_message_id(msg))

    return findings


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _extract_address(header_value: Optional[str]) -> Optional[str]:
    """Extract the bare email address from a header value."""
    if not header_value:
        return None
    match = _ADDR_RE.search(header_value)
    if match:
        return match.group(1).lower().strip()
    return header_value.lower().strip()


def _extract_domain(address: Optional[str]) -> Optional[str]:
    """Return the domain portion of an email address."""
    if address and "@" in address:
        return address.split("@", 1)[1]
    return None


# ---------------------------------------------------------------------------
# Individual rule implementations
# ---------------------------------------------------------------------------

def _check_reply_to_mismatch(msg: Message) -> List[Finding]:
    """Flag emails where Reply-To domain differs from the From domain."""
    from_addr = _extract_address(msg.get("From"))
    reply_to_addr = _extract_address(msg.get("Reply-To"))

    if not from_addr or not reply_to_addr:
        return []

    from_domain = _extract_domain(from_addr)
    reply_domain = _extract_domain(reply_to_addr)

    if from_domain and reply_domain and from_domain != reply_domain:
        return [Finding(
            category="HEADER",
            rule="REPLY_TO_MISMATCH",
            description=(
                f"Reply-To domain '{reply_domain}' differs from "
                f"From domain '{from_domain}'. Replies will go to a"
                f" different organisation."
            ),
            risk=RiskLevel.HIGH,
            evidence=f"From: {from_addr} | Reply-To: {reply_to_addr}",
        )]
    return []


def _check_display_name_mismatch(msg: Message) -> List[Finding]:
    """Flag when the display name in From implies a different org to the actual address."""
    from_raw = msg.get("From", "")
    from_addr = _extract_address(from_raw)

    if not from_addr or "<" not in from_raw:
        return []

    display_name = from_raw.split("<")[0].strip().lower().strip('"\'')
    addr_domain = _extract_domain(from_addr) or ""

    # Check if display name contains a well-known brand but domain doesn't match
    brands = ["paypal", "amazon", "microsoft", "apple", "google",
               "netflix", "facebook", "hsbc", "barclays", "lloyds"]
    for brand in brands:
        if brand in display_name and brand not in addr_domain:
            return [Finding(
                category="HEADER",
                rule="DISPLAY_NAME_BRAND_SPOOF",
                description=(
                    f"Display name contains '{brand}' but the sending domain is"
                    f" '{addr_domain}'. Classic brand impersonation."
                ),
                risk=RiskLevel.HIGH,
                evidence=from_raw,
            )]
    return []


def _check_free_email_spoofing(msg: Message) -> List[Finding]:
    """Flag emails that claim to be from a business but use a free email provider."""
    from_addr = _extract_address(msg.get("From"))
    from_domain = _extract_domain(from_addr)

    if from_domain and from_domain in _FREE_EMAIL_DOMAINS:
        # Heuristic: if display name looks like a business (contains Ltd, Inc, Corp, PLC)
        from_raw = msg.get("From", "")
        if re.search(r"(ltd|inc|corp|plc|llc|gmbh|bank|support|service|security)",
                     from_raw, re.IGNORECASE):
            return [Finding(
                category="HEADER",
                rule="FREE_EMAIL_BUSINESS_SPOOF",
                description=(
                    f"From address uses free provider '{from_domain}' but display"
                    " name suggests a business or service. Legitimate businesses"
                    " use their own domains."
                ),
                risk=RiskLevel.HIGH,
                evidence=from_raw,
            )]
    return []


def _check_auth_results(msg: Message) -> List[Finding]:
    """Check Authentication-Results header for SPF/DKIM/DMARC failures."""
    auth_results = msg.get("Authentication-Results", "")
    if not auth_results:
        return [Finding(
            category="HEADER",
            rule="MISSING_AUTH_RESULTS",
            description="No Authentication-Results header found. Cannot verify SPF/DKIM/DMARC.",
            risk=RiskLevel.LOW,
            evidence="",
        )]

    failures = _AUTH_FAIL_RE.findall(auth_results)
    if failures:
        protocols = ", ".join(f[0].upper() for f in failures)
        return [Finding(
            category="HEADER",
            rule="AUTH_FAILURE",
            description=f"Authentication checks failed for: {protocols}.",
            risk=RiskLevel.HIGH,
            evidence=auth_results[:200],
        )]
    return []


def _check_suspicious_mailer(msg: Message) -> List[Finding]:
    """Flag X-Mailer or User-Agent headers associated with bulk/spam tools."""
    for header in ("X-Mailer", "User-Agent", "X-Originating-Email"):
        value = msg.get(header, "")
        if value and _SUSPICIOUS_MAILER_RE.search(value):
            return [Finding(
                category="HEADER",
                rule="SUSPICIOUS_MAILER",
                description=f"Header '{header}' suggests a bulk mailing tool: '{value}'.",
                risk=RiskLevel.MEDIUM,
                evidence=value,
            )]
    return []


def _check_received_chain(msg: Message) -> List[Finding]:
    """Check Received headers for private-IP origination or unusual hop counts."""
    received = msg.get_all("Received") or []
    findings: List[Finding] = []

    # Private IP ranges in Received headers can indicate internal relay abuse
    private_ip_re = re.compile(
        r"from\s+.*?\[?(10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\]?",
        re.IGNORECASE,
    )
    for hop in received:
        if private_ip_re.search(hop):
            findings.append(Finding(
                category="HEADER",
                rule="PRIVATE_IP_IN_RECEIVED",
                description="A Received header contains a private (RFC 1918) IP address.",
                risk=RiskLevel.LOW,
                evidence=hop[:200],
            ))
            break  # one finding is enough

    # Many hops can indicate deliberate obfuscation
    if len(received) > 8:
        findings.append(Finding(
            category="HEADER",
            rule="EXCESSIVE_HOPS",
            description=f"Email passed through {len(received)} mail servers. Unusual hop"
                        f" counts can indicate deliberate routing obfuscation.",
            risk=RiskLevel.LOW,
            evidence=f"{len(received)} Received headers",
        ))
    return findings


def _check_missing_message_id(msg: Message) -> List[Finding]:
    """Flag emails with no Message-ID header — a common trait of spam/phishing tools."""
    if not msg.get("Message-ID"):
        return [Finding(
            category="HEADER",
            rule="MISSING_MESSAGE_ID",
            description="Email has no Message-ID header. Legitimate MTAs always add one.",
            risk=RiskLevel.MEDIUM,
            evidence="",
        )]
    return []
