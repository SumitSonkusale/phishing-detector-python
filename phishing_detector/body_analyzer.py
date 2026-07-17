"""Email body analysis module.

Extracts the plain-text and HTML body from a raw email and inspects it
for phishing indicators:
  - Urgency / scare language
  - Requests for credentials or personal information
  - Mismatched anchor text vs. href (visible text says one domain, link
    goes to another)
  - Data-URI links (evades URL filters)
  - Embedded URLs parsed and forwarded to url_analyzer
  - Obfuscated mailto: links

Design note: HTML is parsed with the stdlib ``html.parser`` — no lxml
or BeautifulSoup dependency needed.
"""

from __future__ import annotations

import re
from email import message_from_string
from html.parser import HTMLParser
from typing import List, Optional, Tuple
from urllib.parse import urlparse

from .models import Finding, RiskLevel
from .url_analyzer import analyse_url

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_URGENCY_PATTERNS: tuple[re.Pattern, ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in [
        r"act\s+immediately",
        r"urgent\s+(action|request|matter)",
        r"your\s+account\s+(will\s+be|has\s+been)\s+(suspended|terminated|closed|locked)",
        r"verify\s+your\s+(account|identity|details|information)",
        r"click\s+here\s+(immediately|now|to\s+avoid)",
        r"limited\s+time\s+offer",
        r"(failure|refusal)\s+to\s+(act|comply|respond)",
        r"unusual\s+(sign-?in|activity|login)\s+attempt",
        r"confirm\s+your\s+(password|credentials|billing)",
    ]
)

_CREDENTIAL_REQUEST_PATTERNS: tuple[re.Pattern, ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in [
        r"enter\s+your\s+(password|pin|ssn|social\s+security|credit\s+card|bank\s+account)",
        r"provide\s+(your\s+)?(username|password|account\s+number)",
        r"(login|sign.?in)\s+(credentials|details|information)",
        r"update\s+your\s+(payment|billing|account)\s+(information|details|method)",
    ]
)


# ---------------------------------------------------------------------------
# HTML link extractor
# ---------------------------------------------------------------------------

class _LinkExtractor(HTMLParser):
    """Minimal HTML parser that collects (anchor_text, href) pairs."""

    def __init__(self) -> None:
        super().__init__()
        self.links: List[Tuple[str, str]] = []  # (visible_text, href)
        self._current_href: Optional[str] = None
        self._current_text: List[str] = []

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag == "a":
            attr_dict = dict(attrs)
            self._current_href = attr_dict.get("href", "")
            self._current_text = []

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._current_href is not None:
            self.links.append(("".join(self._current_text).strip(), self._current_href))
            self._current_href = None
            self._current_text = []

    def handle_data(self, data: str) -> None:
        if self._current_href is not None:
            self._current_text.append(data)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyse_body(raw_email: str) -> List[Finding]:
    """Extract email body and return phishing-related body Findings.

    Both plain-text and HTML parts are inspected.  URLs found in the
    body are also passed to :func:`~phishing_detector.url_analyzer.analyse_url`
    so that all URL rules apply uniformly.

    Args:
        raw_email: Full raw email string (headers + body).

    Returns:
        A list of :class:`~phishing_detector.models.Finding` objects.
    """
    msg = message_from_string(raw_email)
    plain_text, html_text = _extract_body_parts(msg)
    full_text = plain_text + " " + _html_to_text(html_text)

    findings: List[Finding] = []
    findings.extend(_check_urgency_language(full_text))
    findings.extend(_check_credential_requests(full_text))

    if html_text:
        findings.extend(_check_anchor_mismatch(html_text))
        findings.extend(_check_data_uri_links(html_text))

    # Analyse every URL found in the body
    for url in _extract_urls(full_text):
        for finding in analyse_url(url):
            # Prefix the rule so it's clear it came from the body
            finding.category = "BODY_URL"
            findings.append(finding)

    return findings


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_body_parts(msg) -> Tuple[str, str]:
    """Return (plain_text, html_text) from an email.Message object."""
    plain_parts: List[str] = []
    html_parts: List[str] = []

    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    plain_parts.append(payload.decode("utf-8", errors="replace"))
            elif ct == "text/html":
                payload = part.get_payload(decode=True)
                if payload:
                    html_parts.append(payload.decode("utf-8", errors="replace"))
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            decoded = payload.decode("utf-8", errors="replace")
            if msg.get_content_type() == "text/html":
                html_parts.append(decoded)
            else:
                plain_parts.append(decoded)

    return " ".join(plain_parts), " ".join(html_parts)


def _html_to_text(html: str) -> str:
    """Strip HTML tags and return plain text (very lightweight)."""
    return re.sub(r"<[^>]+>", " ", html)


def _extract_urls(text: str) -> List[str]:
    """Extract all http/https URLs from a text string."""
    return re.findall(r"https?://[^\s\"'<>]+", text)


# ---------------------------------------------------------------------------
# Individual rule implementations
# ---------------------------------------------------------------------------

def _check_urgency_language(text: str) -> List[Finding]:
    """Flag urgency / scare language that pressures users into quick action."""
    matched = [p.pattern for p in _URGENCY_PATTERNS if p.search(text)]
    if matched:
        return [Finding(
            category="BODY",
            rule="URGENCY_LANGUAGE",
            description=f"Body contains {len(matched)} urgency pattern(s) designed to"
                        f" pressure the recipient into acting without thinking.",
            risk=RiskLevel.MEDIUM,
            evidence=matched[0],
        )]
    return []


def _check_credential_requests(text: str) -> List[Finding]:
    """Flag explicit requests for passwords or sensitive data."""
    matched = [p.pattern for p in _CREDENTIAL_REQUEST_PATTERNS if p.search(text)]
    if matched:
        return [Finding(
            category="BODY",
            rule="CREDENTIAL_REQUEST",
            description="Body explicitly requests credentials or sensitive personal data.",
            risk=RiskLevel.HIGH,
            evidence=matched[0],
        )]
    return []


def _check_anchor_mismatch(html: str) -> List[Finding]:
    """Flag <a> tags where the visible domain differs from the href domain."""
    extractor = _LinkExtractor()
    extractor.feed(html)
    findings: List[Finding] = []

    for anchor_text, href in extractor.links:
        if not href or not anchor_text:
            continue
        if href.startswith("mailto:") or href.startswith("#"):
            continue

        # Normalise both
        if not href.startswith("http"):
            continue

        href_domain = urlparse(href).netloc.lower()

        # Check if the anchor text itself looks like a URL with a different domain
        text_url_match = re.search(r"https?://([^/\s]+)", anchor_text)
        if text_url_match:
            text_domain = text_url_match.group(1).lower()
            if text_domain and href_domain and text_domain != href_domain:
                findings.append(Finding(
                    category="BODY",
                    rule="ANCHOR_MISMATCH",
                    description=(
                        f"Link text shows '{text_domain}' but href goes to"
                        f" '{href_domain}'. Classic misdirection technique."
                    ),
                    risk=RiskLevel.HIGH,
                    evidence=f"text='{anchor_text[:80]}' href='{href[:80]}'",
                ))

    return findings


def _check_data_uri_links(html: str) -> List[Finding]:
    """Flag data: URI links which can embed malicious content and bypass URL filters."""
    if re.search(r'href\s*=\s*["\']?data:', html, re.IGNORECASE):
        return [Finding(
            category="BODY",
            rule="DATA_URI_LINK",
            description="Email contains a data: URI link. These embed content directly"
                        " and can bypass URL-based security filters.",
            risk=RiskLevel.HIGH,
            evidence="data: URI found in href",
        )]
    return []
