"""Lint tests — deterministic, offline."""
from detflow import lint, lint_sigma, lint_xql

VALID_SIGMA = """\
title: Encoded PowerShell
id: 7e1f0b2a-0000-4000-8000-000000000001
status: experimental
description: Detects powershell with an encoded command
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: \\powershell.exe
    CommandLine|contains: ' -enc '
  condition: selection
level: high
tags:
  - attack.t1059.001
"""


def test_valid_sigma_passes():
    rep = lint_sigma(VALID_SIGMA)
    assert rep.status == "pass"
    assert rep.ok


def test_missing_required_fields_fail():
    rep = lint_sigma("title: x\n")  # no logsource / detection
    assert rep.status == "fail"
    assert not rep.ok
    assert any("detection" in f.message for f in rep.findings)


def test_bad_yaml_fails_gracefully():
    rep = lint_sigma("::: not yaml :::\n  - [")
    assert rep.status == "fail"


def test_sigma_without_tags_warns():
    no_tags = VALID_SIGMA.replace("tags:\n  - attack.t1059.001\n", "")
    rep = lint_sigma(no_tags)
    assert rep.status in ("warn", "pass")
    assert any("ATT&CK" in f.message for f in rep.findings)


def test_xql_requires_dataset():
    rep = lint_xql("| filter x = 1")
    assert rep.status == "fail"
    assert any("dataset" in f.message for f in rep.findings)


def test_valid_xql_passes():
    rep = lint_xql('dataset = xdr_data\n| filter action_process_image_name contains "ps"\n| limit 100')
    assert rep.status == "pass"


def test_xql_sql_shape_warns():
    rep = lint_xql("dataset = xdr_data select foo from bar where x = 1")
    assert rep.status == "warn"


def test_lint_dispatches_on_format():
    assert lint('dataset = x | filter a = "b"', "cortex-xql").ok
    assert lint(VALID_SIGMA, "sigma").ok
