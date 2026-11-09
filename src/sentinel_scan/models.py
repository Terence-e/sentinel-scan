"""Data types shared by the checks and reports."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum, IntEnum

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
MAX_EVIDENCE_LENGTH = 300


def clean_text(value: object, limit: int = MAX_EVIDENCE_LENGTH) -> str:
    """Strip control characters from untrusted text, so it cannot spoof a terminal."""
    text = _CONTROL_CHARS.sub(" ", str(value)).strip()
    return text if len(text) <= limit else text[: limit - 3] + "..."


class Risk(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()


class Confidence(Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


@dataclass
class Finding:
    title: str
    category: str
    risk: Risk
    confidence: Confidence
    evidence: str
    explanation: str
    recommendation: str
    location: str = ""

    def __post_init__(self) -> None:
        self.evidence = clean_text(self.evidence)
        self.location = clean_text(self.location)

    def to_dict(self) -> dict[str, str]:
        return {
            "title": self.title,
            "category": self.category,
            "risk": self.risk.label,
            "confidence": self.confidence.value,
            "location": self.location,
            "evidence": self.evidence,
            "explanation": self.explanation,
            "recommendation": self.recommendation,
        }


@dataclass
class ScanResult:
    target: str
    tool_version: str
    started_at: str
    finished_at: str = ""
    checks_run: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    requests_sent: int = 0

    @property
    def overall_risk(self) -> Risk:
        return max((finding.risk for finding in self.findings), default=Risk.INFO)

    @property
    def risk_counts(self) -> dict[str, int]:
        counts = {risk.label: 0 for risk in sorted(Risk, reverse=True)}
        for finding in self.findings:
            counts[finding.risk.label] += 1
        return counts

    def to_dict(self) -> dict[str, object]:
        return {
            "target": self.target,
            "tool_version": self.tool_version,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "overall_risk": self.overall_risk.label,
            "risk_counts": self.risk_counts,
            "requests_sent": self.requests_sent,
            "checks_run": self.checks_run,
            "warnings": self.warnings,
            "findings": [finding.to_dict() for finding in self.findings],
        }
