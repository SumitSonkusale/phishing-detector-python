"""URL analysis module.

Inspects individual URLs for patterns commonly associated with phishing:
IP-address hosts, excessive subdomains, homograph characters, suspicious
TLDs, URL shorteners, misleading path keywords, and port anomalies.

Design note: all checks are purely static/offline — no external HTTP
requests are made here.  This keeps the module fast and safe to run in
a restricted SOC environment.
"""

from __future__ import annotations

import ipaddress
import re
from typing import List
from urllib.parse import urlparse

from .models import Finding, RiskLevel

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# TLDs frequently abused in phishing campaigns (not exhaustive)
_SUSPICIOUS_TLDS: frozenset[str] = frozenset([
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work",
    ".click", ".link", ".online", ".site", ".live", ".stream",
    ".download", ".support", ".loans",
])

# Well-known URL shortening services
_URL_SHORTENERS: frozenset[str] = frozenset([
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl",
    "short.link", "rebrand.ly", "cutt.ly", "is.gd", "buff.ly",
])

# Keywords in path/query that suggest credential harvesting
_CREDENTIAL_KEYWORDS: tuple[str, ...] = (
    "login", "signin", "verify", "secure", "account",
    "update", "confirm", "password", "credential", "banking",
    "paypal", "amazon", "microsoft", "google", "apple",
)

# Regex: homograph lookalike characters (simplified detection)
_HOMOGRAPH_RE = re.compile(r"[\u0430-\u044f\u0400-\u042f\u03b1-\u03c9]")  # Cyrillic/Greek


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyse_url(url: str) -> List[Finding]:
    """Analyse a single URL and return a list of phishing Findings.

    Args:
        url: The URL string to analyse.  Scheme is assumed https if absent.

    Returns:
        A (possibly empty) list of :class:`~phishing_detector.models.Finding`
        objects, one per triggered rule.
    """
    if not url.startswith(("http://", "https://", "ftp://")):
        url = "https://" + url

    findings: List[Finding] = []
    parsed = urlparse(url)
    host = parsed.netloc.lower().split(":")[0]  # strip port

    findings.extend(_check_ip_address_host(host, url))
    findings.extend(_check_suspicious_tld(host, url))
    findings.extend(_check_excessive_subdomains(host, url))
    findings.extend(_check_url_shortener(host, url))
    findings.extend(_check_credential_keywords(parsed.path + "?" + (parsed.query or ""), url))
    findings.extend(_check_homograph_characters(host, url))
    findings.extend(_check_non_standard_port(parsed.netloc, url))
    findings.extend(_check_at_sign_in_url(url))
    findings.extend(_check_double_slash_redirect(parsed.path, url))

    return findings


# ---------------------------------------------------------------------------
# Individual rule implementations
# ---------------------------------------------------------------------------

def _check_ip_address_host(host: str, evidence: str) -> List[Finding]:
    """Flag URLs that use a raw IP address instead of a domain name."""
    try:
        ipaddress.ip_address(host)
        return [Finding(
            category="URL",
            rule="IP_ADDRESS_HOST",
            description="URL uses a raw IP address as the host. Legitimate services"
                        " almost never do this.",
            risk=RiskLevel.HIGH,
            evidence=evidence,
        )]
    except ValueError:
        return []


def _check_suspicious_tld(host: str, evidence: str) -> List[Finding]:
    """Flag TLDs that are disproportionately used in phishing campaigns."""
    for tld in _SUSPICIOUS_TLDS:
        if host.endswith(tld):
            return [Finding(
                category="URL",
                rule="SUSPICIOUS_TLD",
                description=f"TLD '{tld}' is frequently abused in phishing campaigns.",
                risk=RiskLevel.MEDIUM,
                evidence=evidence,
            )]
    return []


def _check_excessive_subdomains(host: str, evidence: str) -> List[Finding]:
    """Flag domains with 5+ labels — a common trick to hide the true registrable domain."""
    labels = host.split(".")
    if len(labels) >= 5:
        return [Finding(
            category="URL",
            rule="EXCESSIVE_SUBDOMAINS",
            description=f"Host has {len(labels)} labels. Attackers pad subdomains to"
                        f" make the real domain harder to spot.",
            risk=RiskLevel.MEDIUM,
            evidence=evidence,
        )]
    return []


def _check_url_shortener(host: str, evidence: str) -> List[Finding]:
    """Flag known URL shortening services that hide the destination."""
    if host in _URL_SHORTENERS:
        return [Finding(
            category="URL",
            rule="URL_SHORTENER",
            description=f"Host '{host}' is a URL shortener. The real destination is hidden.",
            risk=RiskLevel.MEDIUM,
            evidence=evidence,
        )]
    return []


def _check_credential_keywords(path_and_query: str, evidence: str) -> List[Finding]:
    """Flag paths/queries containing keywords associated with credential harvesting."""
    lower = path_and_query.lower()
    matched = [kw for kw in _CREDENTIAL_KEYWORDS if kw in lower]
    if matched:
        return [Finding(
            category="URL",
            rule="CREDENTIAL_HARVEST_KEYWORDS",
            description=f"Path/query contains credential-harvesting keywords: {matched}.",
            risk=RiskLevel.MEDIUM,
            evidence=evidence,
        )]
    return []


def _check_homograph_characters(host: str, evidence: str) -> List[Finding]:
    """Detect Cyrillic/Greek characters in the hostname (IDN homograph attack)."""
    if _HOMOGRAPH_RE.search(host):
        return [Finding(
            category="URL",
            rule="HOMOGRAPH_CHARACTERS",
            description="Hostname contains non-Latin characters that visually mimic"
                        " Latin letters (IDN homograph attack).",
            risk=RiskLevel.HIGH,
            evidence=evidence,
        )]
    return []


def _check_non_standard_port(netloc: str, evidence: str) -> List[Finding]:
    """Flag URLs using non-standard ports (anything other than 80/443)."""
    if ":" in netloc:
        try:
            port = int(netloc.split(":")[-1])
            if port not in (80, 443):
                return [Finding(
                    category="URL",
                    rule="NON_STANDARD_PORT",
                    description=f"URL uses non-standard port {port}.",
                    risk=RiskLevel.LOW,
                    evidence=evidence,
                )]
        except ValueError:
            pass
    return []


def _check_at_sign_in_url(url: str) -> List[Finding]:
    """Flag '@' in URL — anything before it is ignored by browsers."""
    if "@" in urlparse(url).netloc:
        return [Finding(
            category="URL",
            rule="AT_SIGN_IN_URL",
            description="URL contains '@' in the authority component. Browsers discard"
                        " everything before '@', hiding the real host.",
            risk=RiskLevel.HIGH,
            evidence=url,
        )]
    return []


def _check_double_slash_redirect(path: str, evidence: str) -> List[Finding]:
    """Detect '//' in path used to redirect to an attacker-controlled domain."""
    if re.search(r"//[^/]", path):
        return [Finding(
            category="URL",
            rule="DOUBLE_SLASH_REDIRECT",
            description="Path contains '//' which can be used to redirect browsers"
                        " to a different host.",
            risk=RiskLevel.HIGH,
            evidence=evidence,
        )]
    return []
