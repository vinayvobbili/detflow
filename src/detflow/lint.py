"""Deterministic lint for Sigma rules and Cortex XQL queries.

No network, no LLM, no keys — this is the cheap structural gate you run on every
draft before spending a model call on review. ``lint`` never raises.
"""
from __future__ import annotations

import re
from typing import List

from detflow.models import Finding, LintReport, RuleFormat


def lint(rule: str, fmt: "RuleFormat | str" = RuleFormat.SIGMA) -> LintReport:
    """Lint a detection rule. Dispatches on ``fmt`` (sigma | cortex-xql)."""
    if RuleFormat.coerce(fmt) is RuleFormat.CORTEX_XQL:
        return lint_xql(rule)
    return lint_sigma(rule)


def _verdict(findings: List[Finding]) -> LintReport:
    has_error = any(f.level == "error" for f in findings)
    has_warn = any(f.level == "warn" for f in findings)
    n_err = sum(1 for f in findings if f.level == "error")
    n_warn = sum(1 for f in findings if f.level == "warn")
    if has_error:
        status, summary = "fail", f"{n_err} error(s) — rule is not schema-valid."
    elif has_warn:
        status, summary = "warn", f"Valid, with {n_warn} warning(s)."
    else:
        status, summary = "pass", "Schema-valid."
    return LintReport(status=status, summary=summary, findings=findings)


def lint_sigma(text: str) -> LintReport:
    """Parse + schema-check a Sigma rule against the required structure and a set
    of best-practice warnings. The parsed rule is not returned here — use
    :func:`detflow.parse_sigma` if you need the mapping."""
    text = text or ""
    if not text.strip():
        return LintReport("fail", "Empty rule.",
                          [Finding("error", "No rule content provided.")])
    try:
        import yaml
        parsed = yaml.safe_load(text)
    except Exception as e:  # noqa: BLE001 - report any YAML failure as a finding
        return LintReport("fail", "YAML did not parse.",
                          [Finding("error", f"YAML parse error: {e}")])
    if not isinstance(parsed, dict):
        return LintReport("fail", "Not a Sigma rule.",
                          [Finding("error", "Top level is not a YAML mapping.")])

    findings: List[Finding] = []
    # Required structure.
    for req in ("title", "logsource", "detection"):
        if req not in parsed:
            findings.append(Finding("error", f"Missing required field: {req}"))
    det = parsed.get("detection")
    if isinstance(det, dict):
        if "condition" not in det:
            findings.append(Finding("error", "detection has no 'condition'."))
        if not any(k for k in det if k != "condition"):
            findings.append(Finding("error", "detection has no selection blocks."))
    elif "detection" in parsed:
        findings.append(Finding("error", "'detection' must be a mapping."))

    # Best-practice warnings.
    if not parsed.get("level"):
        findings.append(Finding("warn", "No 'level' (severity) set."))
    if not isinstance(parsed.get("logsource"), dict):
        findings.append(Finding("warn", "logsource should specify product/category/service."))
    if not parsed.get("tags"):
        findings.append(Finding("warn", "No ATT&CK 'tags' — coverage mapping will be weaker."))
    if not parsed.get("description"):
        findings.append(Finding("info", "No description — consider adding one for reviewers."))
    if not parsed.get("id"):
        findings.append(Finding("info", "No 'id' (UUID) — recommended for rule tracking."))

    return _verdict(findings)


def lint_xql(text: str) -> LintReport:
    """Validate a Cortex XSIAM XQL query structurally — it must start with
    ``dataset = <name>`` and look like XQL (pipes/filter), not SQL. This is a
    cheap structural check; only a live tenant can prove the query actually runs.
    """
    text = (text or "").strip()
    if not text:
        return LintReport("fail", "Empty XQL.", [Finding("error", "No query provided.")])
    low = text.lower()
    if not re.search(r"\bdataset\s*=", low):
        return LintReport("fail", "Not valid XQL — it must start with `dataset = <name>`.",
                          [Finding("error", "Missing `dataset = …` stage.")])

    findings: List[Finding] = []
    if re.search(r"\bselect\b.*\bfrom\b", low) or re.search(r"\bfrom\b\s+\w+\s+where\b", low):
        findings.append(Finding("warn", "Looks like SQL — XQL uses `| filter`, not `select/from/where`."))
    if "|" not in text:
        findings.append(Finding("warn", "No pipe stages — a detection usually filters (`| filter …`)."))
    if "| filter" not in low:
        findings.append(Finding("warn", "No `| filter` stage — the query may match everything."))
    if "limit" not in low:
        findings.append(Finding("info", "No `| limit` — fine for a correlation rule, noisy for ad-hoc runs."))

    rep = _verdict(findings)
    if rep.status == "pass":
        rep.summary = "Valid XQL structure."
    elif rep.status == "warn":
        rep.summary = "XQL parsed with advisories."
    return rep
