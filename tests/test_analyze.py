"""Analyze tests — fake model for the LLM path, error result for the no-model path."""
import json

from detflow import (
    analyze,
    audience_options,
    to_brief_markdown,
    to_navigator_layer,
    to_stix_bundle,
)
from detflow.models import Severity

REPORT = (
    "A critical remote code execution flaw (CVE-2024-12345) in AcmeServer lets an "
    "unauthenticated attacker send a crafted HTTP request to the /upload endpoint, "
    "drop a webshell, and run PowerShell to download a second-stage payload."
)

GOOD_SIGMA = """\
title: Suspicious Upload Webshell
logsource:
  category: webserver
detection:
  selection:
    uri|contains: '/upload'
  condition: selection
level: high
tags:
  - attack.t1190
"""

ANALYSIS_JSON = json.dumps({
    "title": "AcmeServer RCE webshell drop",
    "severity": "critical",
    "confidence": "High",
    "tlp": "AMBER",
    "overview": "Unauthenticated RCE in AcmeServer enabling webshell deployment.",
    "techniques": [
        {"technique_id": "T1059.001", "technique_name": "PowerShell",
         "tactic": "Execution", "evidence": "second-stage via PowerShell",
         "confidence": "Medium", "order": 2},
        {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application",
         "tactic": "Initial Access", "evidence": "crafted HTTP to /upload",
         "confidence": "High", "order": 1},
    ],
    "detection_rules": [
        {"rule_type": "sigma", "rule_name": "Suspicious Upload Webshell",
         "rule_content": GOOD_SIGMA, "description": "Detects writes to /upload",
         "related_technique": "T1190"},
        {"rule_type": "suricata", "rule_name": "Acme upload exploit",
         "rule_content": 'alert http any any -> any any (msg:"acme"; sid:1;)',
         "description": "network exploit", "related_technique": "T1190"},
    ],
    "threat_actor_name": None,
    "threat_actor_confidence": None,
    "brief": {
        "threat_action": "Unauthenticated RCE under active exploitation.",
        "attack_overview": "Attacker uploads a webshell then pivots.",
        "detection_focus": "Watch webserver upload paths and PowerShell spawns.",
        "recommended_actions": ["Patch AcmeServer", "Hunt for webshells", "Block the endpoint"],
    },
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


def test_analyze_parses_full_package():
    an = analyze(REPORT, model=FakeModel(ANALYSIS_JSON))
    assert an.ok and an.llm_authored
    assert an.severity is Severity.CRITICAL
    assert an.tlp == "AMBER"
    # techniques sorted by kill-chain order (Initial Access before Execution)
    assert [t.technique_id for t in an.techniques] == ["T1190", "T1059.001"]
    assert len(an.rules) == 2
    assert an.brief.recommended_actions


def test_analyze_lints_sigma_rules_in_place():
    an = analyze(REPORT, model=FakeModel(ANALYSIS_JSON))
    sigma = [r for r in an.rules if r.rule_type == "sigma"][0]
    suricata = [r for r in an.rules if r.rule_type == "suricata"][0]
    assert sigma.lint is not None and sigma.lint.ok   # valid Sigma lints clean
    assert suricata.lint is None                       # non-Sigma rules are not linted


def test_analyze_merges_cves_from_text_and_args():
    an = analyze(REPORT, cves=["CVE-2024-9999"], model=FakeModel(ANALYSIS_JSON))
    # explicit CVE first, then the one parsed out of the report text
    assert an.cves == ["CVE-2024-9999", "CVE-2024-12345"]


def test_analyze_no_model_returns_error_not_exception():
    an = analyze(REPORT, model=None)
    assert not an.ok
    assert an.error and "model" in an.error.lower()


def test_analyze_empty_report():
    an = analyze("   ", model=FakeModel(ANALYSIS_JSON))
    assert not an.ok and an.error


def test_analyze_bad_json_returns_error():
    an = analyze(REPORT, model=FakeModel("not json"))
    assert not an.ok and an.error


def test_analyze_model_error_is_caught():
    an = analyze(REPORT, model=FakeModel(None, raise_exc=RuntimeError("boom")))
    assert not an.ok and "boom" in an.error


def test_stix_bundle_is_well_formed_and_deterministic():
    an = analyze(REPORT, model=FakeModel(ANALYSIS_JSON))
    b1 = to_stix_bundle(an, producer="acme-soc")
    b2 = to_stix_bundle(an, producer="acme-soc")
    assert b1["type"] == "bundle"
    assert b1["id"] == b2["id"]  # deterministic ids
    types = [o["type"] for o in b1["objects"]]
    assert "identity" in types and "vulnerability" in types
    assert "attack-pattern" in types and "indicator" in types and "report" in types
    ident = [o for o in b1["objects"] if o["type"] == "identity"][0]
    assert ident["name"] == "acme-soc"


def test_navigator_layer_scopes_techniques():
    an = analyze(REPORT, model=FakeModel(ANALYSIS_JSON))
    layer = to_navigator_layer(an)
    assert layer["domain"] == "enterprise-attack"
    ids = {t["techniqueID"] for t in layer["techniques"]}
    assert ids == {"T1190", "T1059.001"}


def test_brief_markdown_renders_sections():
    an = analyze(REPORT, model=FakeModel(ANALYSIS_JSON))
    md = to_brief_markdown(an)
    assert md.startswith("# AcmeServer RCE webshell drop")
    assert "MITRE ATT&CK Techniques" in md
    assert "Detection Rules" in md
    assert "CVE-2024-12345" in md


def test_analysis_to_dict_is_serializable():
    an = analyze(REPORT, model=FakeModel(ANALYSIS_JSON))
    blob = json.dumps(an.to_dict())
    assert "techniques" in blob and "summary" in blob


def test_audience_changes_brief_label():
    an = analyze(REPORT, audience="leadership", model=FakeModel(ANALYSIS_JSON))
    assert an.brief.audience == "leadership"
    assert an.brief.audience_label == "Leadership"


def test_audience_options_default_first():
    opts = audience_options()
    assert opts[0]["key"] == "dr"
    assert {"key", "label"} <= set(opts[0])
