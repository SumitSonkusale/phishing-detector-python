"""Data models for the phishing detector.

All analyser modules return instances of these dataclasses so that
the engine and CLI layers remain decoupled from detection logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List


class RiskLevel(str, Enum):
    """Overall risk rating for a finding."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass
class Finding:
    """A single phishing indicator discovered during analysis.

    Attributes:
        category: Short category label (e.g. 'URL', 'HEADER', 'BODY').
        rule: Machine-readable rule identifier (e.g. 'IP_ADDRESS_URL').
        description: Human-readable explanation of what was found.
        risk: Severity of this individual finding.
        evidence: Raw snippet that triggered the finding (may be empty).
    """

    category: str
    rule: str
    description: str
    risk: RiskLevel
    evidence: str = ""


@dataclass
class AnalysisResult:
    """Aggregated result returned by the detection engine.

    Attributes:
        overall_risk: Highest risk level across all findings.
        score: Integer 0-100 representing overall phishing likelihood.
        findings: Ordered list of individual findings, highest risk first.
        summary: One-sentence summary suitable for a SOC alert.
    """

    overall_risk: RiskLevel
    score: int
    findings: List[Finding] = field(default_factory=list)
    summary: str = ""
