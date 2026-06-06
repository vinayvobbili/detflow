"""Draft a detection from a plain-English description.

This is the front door: an analyst describes the behavior to catch and a model
drafts a detection — Sigma by default, or a Cortex XSIAM XQL query directly.
The draft is a STARTING POINT; run it through :func:`detflow.lint` and
:func:`detflow.review` before shipping it.

Drafting inherently needs a model (you can't synthesize a rule from prose with
no LLM), so :func:`draft` returns an error result — never an exception — when no
model is configured.
"""
from __future__ import annotations

import re
from typing import Optional

from detflow.llm import DetectionModel, default_model
from detflow.models import DraftResult, RuleFormat

_MAX_DESC = 4000

_SIGMA_SYSTEM = (
    "You are a senior detection engineer. You turn an analyst's plain-English "
    "description into a single, valid Sigma detection rule."
)

_SIGMA_USER = (
    "Turn this into one Sigma rule.\n\nDESCRIPTION:\n{desc}\n\n"
    "Requirements:\n"
    "- Output ONLY the Sigma rule as YAML — no prose, no commentary.\n"
    "- Include: title, a concise description, status (experimental), a logsource "
    "(category and/or product), a detection block (a named selection plus a "
    "condition), level, and tags listing the relevant MITRE ATT&CK technique(s) "
    "as attack.tXXXX.\n"
    "- Use realistic field names for that logsource (e.g. process_creation uses "
    "Image, CommandLine, ParentImage).\n"
    "- Be specific enough to avoid obvious false positives; do NOT invent "
    "indicators the description does not support.\n"
)

_XQL_SYSTEM = (
    "You are a senior detection engineer authoring a Cortex XSIAM XQL correlation "
    "query directly from an analyst's plain-English description."
)

_XQL_USER = (
    "Write one Cortex XSIAM XQL query for this.\n\nDESCRIPTION:\n{desc}\n\n"
    "XQL STRUCTURE (mandatory — this is XQL, NOT SQL):\n"
    "  Every query MUST start with `dataset = <name>` and chain stages with pipes:\n"
    "    `| filter <predicate>`  `| fields <a, b, c>`  `| limit <n>`\n"
    "  NEVER use SQL keywords (no from / where / select). Use `filter`, not `where`.\n"
    "  Worked example:\n"
    "    dataset = xdr_data\n"
    "    | filter event_type = ENUM.PROCESS and action_process_image_name contains \"powershell\"\n"
    "    | fields agent_hostname, action_process_image_command_line, actor_effective_username\n"
    "    | limit 100\n\n"
    "Rules:\n"
    "- Pick the most appropriate dataset (e.g. xdr_data for endpoint/process telemetry).\n"
    "- Use ONLY valid XQL operators. XQL has NO startswith/endswith — use regex `~=` with `^`/`$`,\n"
    "  `=`/`!=` for exact, `contains` for substring, `in (\"a\",\"b\")` for sets.\n"
    "- Be specific enough to avoid obvious false positives; do NOT invent indicators the\n"
    "  description does not support.\n"
    "- Respond with ONLY the XQL query text — no prose, no code fences, no commentary.\n"
)


def _extract_yaml(text: str) -> str:
    if not text:
        return ""
    t = text.strip()
    fence = re.search(r"```(?:ya?ml)?\s*(.*?)```", t, re.DOTALL)
    return fence.group(1).strip() if fence else t


def _extract_xql(text: str) -> str:
    if not text:
        return ""
    fence = re.search(r"```(?:xql|sql)?\s*(.*?)```", text, re.DOTALL)
    return (fence.group(1) if fence else text).strip()


def draft(description: str, fmt: "RuleFormat | str" = RuleFormat.SIGMA, *,
          model: Optional[DetectionModel] = None) -> DraftResult:
    """Draft a detection from a plain-English ``description``.

    Args:
        description: What to detect, in plain English.
        fmt: ``"sigma"`` (default) or ``"cortex-xql"``.
        model: A :class:`~detflow.llm.DetectionModel`. Defaults to
            :func:`~detflow.llm.default_model` (from the environment).

    Returns a :class:`DraftResult`; ``.ok`` is False with ``.error`` set when no
    model is configured or the model returns nothing usable. Never raises.
    """
    fmt = RuleFormat.coerce(fmt)
    description = (description or "").strip()
    if not description:
        return DraftResult(fmt, error="Describe the behavior you want to detect.")
    description = description[:_MAX_DESC]

    if model is None:
        model = default_model()
    if model is None:
        return DraftResult(fmt, error="No model configured — set DETFLOW_LLM_* or pass model=.")

    if fmt is RuleFormat.CORTEX_XQL:
        system, user = _XQL_SYSTEM, _XQL_USER.format(desc=description)
    else:
        system, user = _SIGMA_SYSTEM, _SIGMA_USER.format(desc=description)

    try:
        raw = model.complete(system, user)
    except Exception as e:  # noqa: BLE001 - surface as a result, not an exception
        return DraftResult(fmt, error=f"Drafting failed: {type(e).__name__}: {e}")

    note = "Drafted from plain text — review and edit before shipping."
    if fmt is RuleFormat.CORTEX_XQL:
        xql = _extract_xql(raw)
        if not re.search(r"\bdataset\s*=", xql.lower()):
            return DraftResult(fmt, error="The model did not return a usable XQL query — try rephrasing.")
        return DraftResult(fmt, rule=xql, notes=[note])

    sigma = _extract_yaml(raw)
    if not sigma or "detection" not in sigma:
        return DraftResult(fmt, error="The model did not return a usable Sigma rule — try rephrasing.")
    return DraftResult(fmt, rule=sigma, notes=[note])
