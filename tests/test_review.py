"""Review tests — fake model for the LLM path, floor for the no-model path."""
import json

from detflow import review
from detflow.models import Severity

SIGMA = """\
title: Encoded PowerShell
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: ' -enc '
  condition: selection
level: high
tags:
  - attack.t1059.001
"""

CATALOG = [{"name": "Encoded PowerShell Command", "source": "edr", "techniques": ["T1059.001"]}]

REVIEW_JSON = json.dumps({
    "quality_score": 78,
    "severity": "high",
    "false_positive_risk": "medium",
    "fp_rationale": "Admins legitimately use -enc.",
    "mitre_techniques": ["T1059.001"],
    "coverage_gaps": ["Misses -encodedcommand long form"],
    "strengths": ["Specific to encoded command flag"],
    "improvements": ["Also match -e and -ec abbreviations"],
    "verdict": "revise",
    "summary": "Solid starting point; broaden the flag matching.",
})


class FakeModel:
    name = "fake:test"

    def __init__(self, response, raise_exc=None):
        self._response = response
        self._raise = raise_exc

    def complete(self, system, user, *, json=False):
        if self._raise:
            raise self._raise
        return self._response


def test_review_with_model_parses_assessment():
    res = review(SIGMA, catalog=CATALOG, model=FakeModel(REVIEW_JSON))
    assert res.llm_authored
    assert res.quality_score == 78
    assert res.severity is Severity.HIGH
    assert res.false_positive_risk == "medium"
    assert res.verdict == "revise"
    assert res.improvements


def test_review_surfaces_catalog_overlap():
    res = review(SIGMA, catalog=CATALOG, model=FakeModel(REVIEW_JSON))
    assert res.overlaps
    assert res.overlaps[0].name == "Encoded PowerShell Command"


def test_review_floor_without_model():
    res = review(SIGMA, catalog=CATALOG, model=None)
    assert not res.llm_authored
    assert res.quality_score is None
    assert res.verdict == "revise"
    # floor still lints + dedups
    assert res.lint is not None and res.lint.ok
    assert res.overlaps


def test_review_bad_model_output_falls_to_floor():
    res = review(SIGMA, catalog=CATALOG, model=FakeModel("not json at all"))
    assert not res.llm_authored
    assert res.lint is not None


def test_review_model_error_falls_to_floor():
    res = review(SIGMA, model=FakeModel(None, raise_exc=RuntimeError("boom")))
    assert not res.llm_authored


def test_review_xql_lane_uses_explicit_techniques():
    xql = 'dataset = xdr_data\n| filter action_process_image_name contains "powershell"\n| limit 100'
    res = review(xql, fmt="cortex-xql", catalog=CATALOG, techniques=["T1059.001"],
                 model=FakeModel(REVIEW_JSON))
    assert res.lint is not None and res.lint.ok
    assert res.overlaps  # matched via explicit technique
    assert res.llm_authored


def test_review_to_dict_is_serializable():
    res = review(SIGMA, catalog=CATALOG, model=FakeModel(REVIEW_JSON))
    blob = json.dumps(res.to_dict())
    assert "quality_score" in blob
