"""Result types for detflow.

These are plain dataclasses with no behavior beyond a couple of convenience
properties, so they serialize cleanly and are easy to assert on in tests.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class RuleFormat(str, Enum):
    """A detection language detflow can draft and review."""

    SIGMA = "sigma"            # vendor-neutral Sigma YAML
    CORTEX_XQL = "cortex-xql"  # Cortex XSIAM XQL correlation query

    @classmethod
    def coerce(cls, value: "RuleFormat | str") -> "RuleFormat":
        if isinstance(value, cls):
            return value
        v = str(value).strip().lower().replace("_", "-")
        if v in ("xql", "cortex-xql", "cortex", "xsiam"):
            return cls.CORTEX_XQL
        return cls.SIGMA


class Severity(str, Enum):
    INFO = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def coerce(cls, value: "Severity | str | None",
               default: "Optional[Severity]" = None) -> "Severity":
        default = default or cls.MEDIUM
        if value is None:
            return default
        if isinstance(value, cls):
            return value
        v = str(value).strip().lower()
        for m in cls:
            if m.value == v or m.name.lower() == v:
                return m
        if v in ("info",):
            return cls.INFO
        return default


@dataclass
class Finding:
    """A single lint finding."""

    level: str  # "error" | "warn" | "info"
    message: str


@dataclass
class LintReport:
    status: str  # "pass" | "warn" | "fail"
    summary: str
    findings: List[Finding] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """True unless a hard error makes the rule unusable."""
        return self.status != "fail"

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "summary": self.summary,
            "findings": [{"level": f.level, "message": f.message} for f in self.findings],
            "ok": self.ok,
        }


@dataclass
class DraftResult:
    """The output of drafting a detection from plain English."""

    fmt: RuleFormat
    rule: Optional[str] = None  # the drafted rule text (Sigma YAML or XQL)
    notes: List[str] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return bool(self.rule)

    def to_dict(self) -> dict:
        return {"format": self.fmt.value, "rule": self.rule,
                "notes": list(self.notes), "error": self.error, "ok": self.ok}


@dataclass
class Overlap:
    """An existing catalog rule that looks related to the one under review."""

    name: str
    source: str  # which catalog/platform it came from
    reason: str  # why it's flagged (shared ATT&CK technique, name overlap, …)
    score: int

    def to_dict(self) -> dict:
        return {"name": self.name, "source": self.source,
                "reason": self.reason, "score": self.score}


@dataclass
class ReviewResult:
    """A senior-detection-engineer review of a proposed detection."""

    quality_score: Optional[int]          # 0-100, or None if the LLM was absent
    severity: Severity
    false_positive_risk: str              # "low" | "medium" | "high" | "unknown"
    fp_rationale: str
    mitre_techniques: List[str]
    coverage_gaps: List[str]
    strengths: List[str]
    improvements: List[str]
    verdict: str                          # "approve" | "revise" | "reject"
    summary: str
    overlaps: List[Overlap] = field(default_factory=list)
    lint: Optional[LintReport] = None
    llm_authored: bool = False            # True if an LLM produced the assessment

    def to_dict(self) -> dict:
        return {
            "quality_score": self.quality_score,
            "severity": self.severity.value,
            "false_positive_risk": self.false_positive_risk,
            "fp_rationale": self.fp_rationale,
            "mitre_techniques": list(self.mitre_techniques),
            "coverage_gaps": list(self.coverage_gaps),
            "strengths": list(self.strengths),
            "improvements": list(self.improvements),
            "verdict": self.verdict,
            "summary": self.summary,
            "overlaps": [o.to_dict() for o in self.overlaps],
            "lint": self.lint.to_dict() if self.lint else None,
            "llm_authored": self.llm_authored,
        }
