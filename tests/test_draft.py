"""Draft tests — a fake model stands in for the LLM (no network)."""
from detflow import draft
from detflow.models import RuleFormat

SIGMA_OUT = """```yaml
title: Encoded PowerShell from Office
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
```"""

XQL_OUT = 'dataset = xdr_data\n| filter action_process_image_name contains "powershell"\n| limit 100'


class FakeModel:
    name = "fake:test"

    def __init__(self, response, raise_exc=None):
        self._response = response
        self._raise = raise_exc
        self.calls = []

    def complete(self, system, user, *, json=False):
        self.calls.append({"system": system, "user": user, "json": json})
        if self._raise:
            raise self._raise
        return self._response


def test_draft_sigma_strips_fence():
    res = draft("powershell encoded command from office macro", model=FakeModel(SIGMA_OUT))
    assert res.ok
    assert res.fmt is RuleFormat.SIGMA
    assert res.rule.startswith("title:")
    assert "detection:" in res.rule


def test_draft_xql_lane():
    res = draft("powershell process", fmt="cortex-xql", model=FakeModel(XQL_OUT))
    assert res.ok
    assert res.fmt is RuleFormat.CORTEX_XQL
    assert res.rule.lower().startswith("dataset =")


def test_draft_without_model_is_error_not_exception():
    res = draft("something", model=None)  # default_model() returns None with no env
    assert not res.ok
    assert "No model configured" in res.error


def test_draft_empty_description():
    res = draft("   ", model=FakeModel(SIGMA_OUT))
    assert not res.ok
    assert "Describe" in res.error


def test_draft_model_error_is_captured():
    res = draft("x", model=FakeModel(None, raise_exc=RuntimeError("boom")))
    assert not res.ok
    assert "boom" in res.error


def test_draft_unusable_output():
    res = draft("x", model=FakeModel("I cannot help with that."))
    assert not res.ok
