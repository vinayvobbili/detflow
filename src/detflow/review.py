"""Review a detection like a senior detection engineer.

:func:`review` lints the rule, finds overlap against a catalog you supply, and —
when a model is available — produces a structured assessment: a quality score,
false-positive risk and why, ATT&CK techniques, coverage gaps, strengths,
concrete improvements, and an approve/revise/reject verdict. With no model it
still returns a useful deterministic floor (lint + overlap + parsed metadata).
:func:`review` never raises.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Mapping, Optional, Sequence

from detflow.lint import lint as _lint
from detflow.llm import DetectionModel, default_model
from detflow.models import LintReport, Overlap, ReviewResult, RuleFormat, Severity
from detflow.overlap import find_overlaps, techniques_from_sigma

_MAX_RULE = 60_000

_REVIEW_SYSTEM = (
    "You are a principal detection engineer reviewing a proposed detection before "
    "it is merged into a detection-content repository. Be rigorous and specific."
)


def _parse_sigma(text: str) -> Dict[str, Any]:
    try:
        import yaml
        parsed = yaml.safe_load(text)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def _extract_json(text: str) -> Optional[dict]:
    if not text:
        return None
    t = text.strip()
    fence = re.search(r"```(?:json)?\s*(.*?)```", t, re.DOTALL)
    if fence:
        t = fence.group(1).strip()
    start, end = t.find("{"), t.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    snippet = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", t[start:end + 1])
    try:
        data = json.loads(snippet)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _build_user_prompt(rule: str, fmt: RuleFormat, overlaps: Sequence[Overlap],
                       extra_context: str = "") -> str:
    if fmt is RuleFormat.CORTEX_XQL:
        source_block = ("This detection was authored DIRECTLY in Cortex XSIAM XQL.\n\n"
                        "XQL DETECTION:\n```\n" + rule[:_MAX_RULE] + "\n```\n\n")
    else:
        source_block = "SIGMA RULE:\n```yaml\n" + rule[:_MAX_RULE] + "\n```\n\n"
    overlap_block = ""
    if overlaps:
        overlap_block = ("EXISTING CATALOG RULES that look related (consider duplication/coverage):\n"
                         + "\n".join(f"  - [{o.source}] {o.name} ({o.reason})" for o in overlaps[:8])
                         + "\n\n")
    ctx = (extra_context.strip() + "\n\n") if extra_context.strip() else ""
    return (
        source_block + ctx + overlap_block +
        "Assess: detection quality, false-positive risk and why, ATT&CK coverage, gaps, "
        "and concrete improvements. Consider whether it overlaps existing catalog rules.\n\n"
        "Respond with ONLY a single JSON object — no fences, no prose — with EXACTLY these keys:\n"
        '  "quality_score": integer 0-100\n'
        '  "severity": "informational"|"low"|"medium"|"high"|"critical"\n'
        '  "false_positive_risk": "low"|"medium"|"high"\n'
        '  "fp_rationale": string — 1-2 sentences\n'
        '  "mitre_techniques": array of ATT&CK technique IDs (e.g. "T1059.001")\n'
        '  "coverage_gaps": array of strings — what this rule will MISS\n'
        '  "strengths": array of strings\n'
        '  "improvements": array of strings — concrete, actionable\n'
        '  "verdict": "approve"|"revise"|"reject"\n'
        '  "summary": string — 2-3 sentence reviewer summary\n'
    )


def _floor(parsed: Mapping[str, Any], fmt: RuleFormat, lint_report: LintReport,
           overlaps: List[Overlap], techniques: List[str]) -> ReviewResult:
    return ReviewResult(
        quality_score=None,
        severity=Severity.coerce(parsed.get("level")),
        false_positive_risk="unknown",
        fp_rationale="",
        mitre_techniques=techniques,
        coverage_gaps=[],
        strengths=[],
        improvements=[],
        verdict="revise",
        summary="Automated review unavailable — manual review recommended.",
        overlaps=overlaps,
        lint=lint_report,
        llm_authored=False,
    )


def review(rule: str, fmt: "RuleFormat | str" = RuleFormat.SIGMA, *,
           catalog: Optional[Sequence[Mapping[str, Any]]] = None,
           techniques: Optional[Sequence[str]] = None,
           extra_context: str = "",
           model: Optional[DetectionModel] = None) -> ReviewResult:
    """Review a detection rule.

    Args:
        rule: The rule text (Sigma YAML or XQL).
        fmt: ``"sigma"`` (default) or ``"cortex-xql"``.
        catalog: Existing rules to check for overlap (see :mod:`detflow.overlap`).
        techniques: Explicit ATT&CK technique IDs for the candidate — used for
            overlap matching when the rule has no Sigma tags (e.g. the XQL lane).
        extra_context: Free-text context to give the reviewer (e.g. a live
            dry-run result: "0 events matched in the last 24h").
        model: A :class:`~detflow.llm.DetectionModel`; defaults to the
            environment model. With none, a deterministic floor is returned.

    Returns a :class:`ReviewResult`. Never raises.
    """
    fmt = RuleFormat.coerce(fmt)
    rule = rule or ""
    parsed = _parse_sigma(rule) if fmt is RuleFormat.SIGMA else {}
    lint_report = _lint(rule, fmt)

    derived = list(techniques) if techniques is not None else techniques_from_sigma(parsed)
    derived = [t.upper() for t in derived]

    meta: Dict[str, Any] = {"title": parsed.get("title") or "", "tags": parsed.get("tags") or []}
    overlaps = find_overlaps(meta, catalog or [], techniques=derived)

    if model is None:
        model = default_model()
    if model is None:
        return _floor(parsed, fmt, lint_report, overlaps, derived)

    prompt = _build_user_prompt(rule, fmt, overlaps, extra_context)
    try:
        raw = model.complete(_REVIEW_SYSTEM, prompt, json=True)
    except Exception:  # noqa: BLE001
        return _floor(parsed, fmt, lint_report, overlaps, derived)
    data = _extract_json(raw)
    if not data:
        return _floor(parsed, fmt, lint_report, overlaps, derived)

    def _lst(key: str) -> List[str]:
        return [str(x).strip() for x in (data.get(key) or []) if str(x).strip()]

    try:
        score: Optional[int] = int(data.get("quality_score"))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        score = None
    llm_tech = [str(t).strip().upper() for t in (data.get("mitre_techniques") or []) if str(t).strip()]

    return ReviewResult(
        quality_score=score,
        severity=Severity.coerce(data.get("severity"), Severity.coerce(parsed.get("level"))),
        false_positive_risk=str(data.get("false_positive_risk") or "unknown").strip().lower(),
        fp_rationale=str(data.get("fp_rationale") or "").strip(),
        mitre_techniques=llm_tech or derived,
        coverage_gaps=_lst("coverage_gaps"),
        strengths=_lst("strengths"),
        improvements=_lst("improvements"),
        verdict=str(data.get("verdict") or "revise").strip().lower(),
        summary=str(data.get("summary") or "").strip(),
        overlaps=overlaps,
        lint=lint_report,
        llm_authored=True,
    )
