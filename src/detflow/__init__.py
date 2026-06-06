"""detflow — a detection-engineering copilot.

Draft detections from plain English and review them like a senior detection
engineer. Two formats: vendor-neutral **Sigma** and **Cortex XSIAM XQL**.

Quick start::

    from detflow import draft, review, lint

    # 1. Draft from plain English (needs a model — see detflow.llm)
    d = draft("powershell launched with an encoded command by a Word macro")
    print(d.rule)                      # the Sigma YAML

    # 2. Lint it — deterministic, no model, never raises
    print(lint(d.rule).status)         # pass | warn | fail

    # 3. Review it like a senior engineer, deduped against your catalog
    catalog = [{"name": "Encoded PowerShell", "source": "edr",
                "techniques": ["T1059.001"]}]
    r = review(d.rule, catalog=catalog)
    print(r.quality_score, r.false_positive_risk, r.verdict)
    for o in r.overlaps:
        print("overlaps:", o.name, "—", o.reason)

The model is pluggable: set ``DETFLOW_LLM_API_KEY`` / ``DETFLOW_LLM_BASE_URL`` /
``DETFLOW_LLM_MODEL`` for any OpenAI-compatible endpoint, or pass ``model=`` —
including a LangChain failover chain via :class:`detflow.llm.LangChainModel`.
"""
from detflow.draft import draft
from detflow.lint import lint, lint_sigma, lint_xql
from detflow.llm import (
    DetectionModel,
    LangChainModel,
    OpenAIChatModel,
    default_model,
)
from detflow.models import (
    DraftResult,
    Finding,
    LintReport,
    Overlap,
    ReviewResult,
    RuleFormat,
    Severity,
)
from detflow.overlap import find_overlaps, techniques_from_sigma
from detflow.review import review

__version__ = "0.1.0"

__all__ = [
    # Verbs
    "draft",
    "lint",
    "lint_sigma",
    "lint_xql",
    "review",
    "find_overlaps",
    "techniques_from_sigma",
    # Models / config
    "DetectionModel",
    "OpenAIChatModel",
    "LangChainModel",
    "default_model",
    # Result types
    "DraftResult",
    "LintReport",
    "Finding",
    "ReviewResult",
    "Overlap",
    "RuleFormat",
    "Severity",
    "__version__",
]
