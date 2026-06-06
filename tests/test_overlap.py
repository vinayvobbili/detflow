"""Overlap tests — deterministic dedup against a supplied catalog."""
from detflow import find_overlaps, techniques_from_sigma

CATALOG = [
    {"name": "Encoded PowerShell Command", "source": "edr", "techniques": ["T1059.001"]},
    {"name": "Suspicious WMI Process Call Create", "source": "sigma", "techniques": ["T1047"]},
    {"name": "Totally Unrelated Login Anomaly", "source": "siem", "techniques": ["T1078"]},
]


def test_shared_technique_is_flagged():
    rule = {"title": "Detect base64 encoded shell", "tags": ["attack.t1059.001"]}
    hits = find_overlaps(rule, CATALOG)
    assert hits
    assert hits[0].name == "Encoded PowerShell Command"
    assert "T1059.001" in hits[0].reason


def test_name_token_overlap_is_flagged():
    rule = {"title": "Suspicious WMI Process spawned", "tags": []}
    hits = find_overlaps(rule, CATALOG)
    assert any(h.name == "Suspicious WMI Process Call Create" for h in hits)


def test_no_overlap_returns_empty():
    rule = {"title": "Brand new unrelated thing", "tags": ["attack.t1555"]}
    assert find_overlaps(rule, CATALOG) == []


def test_explicit_techniques_override_for_xql_lane():
    # XQL has no Sigma tags — pass techniques explicitly.
    rule = {"title": "xql detection on xdr_data"}
    hits = find_overlaps(rule, CATALOG, techniques=["T1047"])
    assert any(h.name == "Suspicious WMI Process Call Create" for h in hits)


def test_techniques_from_sigma_parses_tags():
    assert techniques_from_sigma({"tags": ["attack.t1059.001", "attack.t1047", "foo"]}) == \
        ["T1059.001", "T1047"]


def test_empty_catalog_is_safe():
    assert find_overlaps({"title": "x", "tags": ["attack.t1059"]}, []) == []
