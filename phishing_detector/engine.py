"""Detection engine — orchestrates header, body, and URL analysers.

This module is the single entry point for callers (CLI, tests, future
API layer).  It aggregates findings from all three analysers, deduplicates
URL findings that appear in both body and standalone URL input, computes
a normalised risk score (0–100), derives overall_risk, and writes a
one-sentence SOC-friendly summary.

Scoring rationale
-----------------
Each finding contributes a fixed number of points:
  HIGH   -> 25 points
  MEDIUM -> 10 points
  LOW    ->  3 points

The raw total is then clamped to [0, 100].  This simple linear model is
deliberately transparent — an analyst can trace every point back to an
individual rule, which is more useful in a SOC context than an opaque ML
score.
"""

from __future__ import annotations

from typing import List, Optional

from .body_analyzer import analyse_body
from .header_analyzer import analyse_headers
from .models import AnalysisResult, Finding, RiskLevel
from .url_analyzer import analyse_url

# Points contributed by each risk level
_POINTS: dict[RiskLevel, int] = {
    RiskLevel.HIGH: 25,
    RiskLevel.MEDIUM: 10,
    RiskLevel.LOW: 3,
}


def analyse_email(raw_email: str, extra_urls: Optional[List[str]] = None) -> AnalysisResult:
    """Run all analysers against a raw email and optional extra URLs.

    Args:
        raw_email: Full raw RFC 2822 email string (headers + body).
        extra_urls: Additional URLs to analyse that may not appear in the
                    email body (e.g. supplied separately by the analyst).

    Returns:
        An :class:`~phishing_detector.models.AnalysisResult` with score,
        risk level, deduped findings list, and a human-readable summary.
    """
    findings: List[Finding] = []
    findings.extend(analyse_headers(raw_email))
    findings.extend(analyse_body(raw_email))

    for url in (extra_urls or []):
        for f in analyse_url(url):
            f.category = "EXTRA_URL"
            findings.append(f)

    findings = _deduplicate(findings)
    findings.sort(key=lambda f: list(RiskLevel).index(f.risk))

    score = _compute_score(findings)
    overall_risk = _derive_overall_risk(findings)
    summary = _build_summary(overall_risk, findings)

    return AnalysisResult(
        overall_risk=overall_risk,
        score=score,
        findings=findings,
        summary=summary,
    )


def analyse_url_only(url: str) -> AnalysisResult:
    """Convenience function to analyse a single URL with no email context.

    Args:
        url: The URL to analyse.

    Returns:
        An :class:`~phishing_detector.models.AnalysisResult`.
    """
    findings = analyse_url(url)
    findings.sort(key=lambda f: list(RiskLevel).index(f.risk))
    score = _compute_score(findings)
    overall_risk = _derive_overall_risk(findings)
    summary = _build_summary(overall_risk, findings)
    return AnalysisResult(
        overall_risk=overall_risk,
        score=score,
        findings=findings,
        summary=summary,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _deduplicate(findings: List[Finding]) -> List[Finding]:
    """Remove duplicate findings by (category, rule, evidence) key."""
    seen: set[tuple[str, str, str]] = set()
    unique: List[Finding] = []
    for f in findings:
        key = (f.category, f.rule, f.evidence[:80])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def _compute_score(findings: List[Finding]) -> int:
    """Calculate a 0-100 phishing likelihood score from findings."""
    raw = sum(_POINTS[f.risk] for f in findings)
    return min(raw, 100)


def _derive_overall_risk(findings: List[Finding]) -> RiskLevel:
    """Return the highest risk level present, or LOW if no findings."""
    if any(f.risk == RiskLevel.HIGH for f in findings):
        return RiskLevel.HIGH
    if any(f.risk == RiskLevel.MEDIUM for f in findings):
        return RiskLevel.MEDIUM
    if findings:
        return RiskLevel.LOW
    return RiskLevel.LOW


def _build_summary(overall_risk: RiskLevel, findings: List[Finding]) -> str:
    """Build a one-sentence summary suitable for a SOC alert."""
    count = len(findings)
    if count == 0:
        return "No phishing indicators detected."
    high_count = sum(1 for f in findings if f.risk == RiskLevel.HIGH)
    top_rules = ", ".join(
        f.rule for f in findings[:3]
    )
    return (
        f"{overall_risk.value} risk — {count} indicator(s) found "
        f"({high_count} HIGH). Top rules: {top_rules}."
    )
