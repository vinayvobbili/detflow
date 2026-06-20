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


@dataclass
class ThreatTechnique:
    """One ATT&CK technique an adversary could use, mapped from a threat report."""

    technique_id: str            # e.g. "T1190" or "T1059.001"
    technique_name: str
    tactic: str                  # e.g. "Initial Access"
    evidence: str                # <=160 chars: why it maps, grounded in the report
    confidence: str              # "High" | "Medium" | "Low"
    order: int = 999             # kill-chain order, 1 = earliest

    def to_dict(self) -> dict:
        return {"technique_id": self.technique_id, "technique_name": self.technique_name,
                "tactic": self.tactic, "evidence": self.evidence,
                "confidence": self.confidence, "order": self.order}


@dataclass
class GeneratedRule:
    """A detection rule generated for a technique — Sigma, YARA, or Suricata."""

    rule_type: str               # "sigma" | "yara" | "suricata"
    rule_name: str
    rule_content: str
    description: str = ""
    related_technique: Optional[str] = None   # ATT&CK ID this rule covers
    lint: Optional[LintReport] = None         # populated for Sigma rules only

    def to_dict(self) -> dict:
        return {"rule_type": self.rule_type, "rule_name": self.rule_name,
                "rule_content": self.rule_content, "description": self.description,
                "related_technique": self.related_technique,
                "lint": self.lint.to_dict() if self.lint else None}


@dataclass
class IntelBrief:
    """An audience-targeted intelligence brief for a threat analysis."""

    threat_action: str = ""
    attack_overview: str = ""
    detection_focus: str = ""
    recommended_actions: List[str] = field(default_factory=list)
    audience: str = "dr"
    audience_label: str = "Detection & Response"

    def to_dict(self) -> dict:
        return {"threat_action": self.threat_action, "attack_overview": self.attack_overview,
                "detection_focus": self.detection_focus,
                "recommended_actions": list(self.recommended_actions),
                "audience": self.audience, "audience_label": self.audience_label}


@dataclass
class ThreatAnalysis:
    """A grounded, analyst-grade breakdown of a threat / advisory report.

    Maps the report to ATT&CK techniques, generates detection rules, and frames
    an intelligence brief. Export it to STIX 2.1, an ATT&CK Navigator layer, or a
    Markdown brief (see :mod:`detflow.analyze`).
    """

    title: str = ""
    severity: Severity = Severity.MEDIUM
    confidence: str = "Low"               # overall analysis confidence
    tlp: str = "AMBER"                     # RED | AMBER | GREEN | CLEAR
    overview: str = ""
    techniques: List[ThreatTechnique] = field(default_factory=list)
    rules: List[GeneratedRule] = field(default_factory=list)
    brief: IntelBrief = field(default_factory=IntelBrief)
    cves: List[str] = field(default_factory=list)
    threat_actor_name: Optional[str] = None
    threat_actor_confidence: Optional[str] = None
    generated_at: str = ""
    llm_authored: bool = False
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None and bool(self.techniques or self.rules or self.overview)

    @property
    def summary(self) -> str:
        """One-line human summary (severity · TLP · technique/rule counts · …)."""
        by_type: dict = {}
        for r in self.rules:
            t = (r.rule_type or "rule").lower()
            by_type[t] = by_type.get(t, 0) + 1
        rule_bits = ", ".join(f"{n} {t.title()}" for t, n in by_type.items())
        sigma_warn = sum(1 for r in self.rules
                         if (r.rule_type or "").lower() == "sigma" and r.lint and not r.lint.ok)
        bits = [
            f"Severity {self.severity.value}",
            f"TLP:{self.tlp}",
            f"{len(self.techniques)} ATT&CK technique(s)",
            f"{len(self.rules)} detection rule(s)" + (f" ({rule_bits})" if rule_bits else ""),
        ]
        if sigma_warn:
            bits.append(f"{sigma_warn} Sigma rule(s) need review")
        if self.brief.audience_label:
            bits.append(f"brief: {self.brief.audience_label}")
        if self.threat_actor_name:
            bits.append(f"actor: {self.threat_actor_name}")
        return " · ".join(bits)

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "tlp": self.tlp,
            "overview": self.overview,
            "techniques": [t.to_dict() for t in self.techniques],
            "rules": [r.to_dict() for r in self.rules],
            "brief": self.brief.to_dict(),
            "cves": list(self.cves),
            "threat_actor_name": self.threat_actor_name,
            "threat_actor_confidence": self.threat_actor_confidence,
            "generated_at": self.generated_at,
            "llm_authored": self.llm_authored,
            "error": self.error,
            "ok": self.ok,
            "summary": self.summary,
        }
