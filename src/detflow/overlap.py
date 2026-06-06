"""Catalog overlap — surface existing detections that cover the same ground.

A detection-as-code workflow accumulates rules fast; the cheapest win is not
shipping the same coverage twice. :func:`find_overlaps` does a deterministic
dedup of a candidate detection against a catalog you supply (your existing rule
inventory, exported from whatever platforms you run) by shared ATT&CK technique
and strong title-token overlap. No network, no LLM.

The catalog is a list of plain dicts — bring your own from any platform::

    catalog = [
        {"name": "Encoded PowerShell", "source": "crowdstrike",
         "techniques": ["T1059.001"]},
        {"name": "Suspicious WMI process call create", "source": "sigma",
         "techniques": ["T1047"]},
    ]
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Mapping, Optional, Sequence

from detflow.models import Overlap


def tokens(s: str) -> set:
    """Title tokens worth comparing — lowercase words longer than 3 chars."""
    return {w for w in re.split(r"[^a-z0-9]+", (s or "").lower()) if len(w) > 3}


def techniques_from_sigma(parsed: Mapping[str, Any]) -> List[str]:
    """Pull ATT&CK technique IDs (e.g. ``T1059.001``) from a parsed Sigma rule's
    ``tags`` (``attack.tXXXX[.XXX]``)."""
    out: List[str] = []
    for tag in (parsed.get("tags") or []):
        m = re.match(r"attack\.(t\d{4}(?:\.\d{3})?)", str(tag).strip().lower())
        if m:
            out.append(m.group(1).upper())
    return out


def _norm_catalog(catalog: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    rules: List[Dict[str, Any]] = []
    for r in catalog or []:
        name = str(r.get("name") or "").strip()
        if not name:
            continue
        rules.append({
            "name": name,
            "source": str(r.get("source") or r.get("platform") or "catalog"),
            "techniques": [str(t).upper() for t in (r.get("techniques")
                                                    or r.get("mitre_techniques") or [])],
            "tokens": tokens(name),
        })
    return rules


def find_overlaps(
    rule: Mapping[str, Any],
    catalog: Sequence[Mapping[str, Any]],
    *,
    techniques: Optional[Sequence[str]] = None,
    limit: int = 8,
) -> List[Overlap]:
    """Return catalog rules that share an ATT&CK technique or a strong title-token
    overlap with ``rule``.

    Args:
        rule: A mapping with at least a ``title``/``name``; if it carries Sigma
            ``tags`` they're used for technique matching.
        catalog: Existing rules to compare against (see module docstring).
        techniques: Explicit technique IDs for the candidate (overrides any
            derived from ``rule``'s Sigma tags) — handy for the XQL lane where
            there are no Sigma tags.
        limit: Cap on the number of overlaps returned (highest score first).
    """
    title = str(rule.get("title") or rule.get("name") or "")
    cand_tokens = tokens(title)
    cand_tech = set(t.upper() for t in (techniques if techniques is not None
                                        else techniques_from_sigma(rule)))

    hits: List[Overlap] = []
    for r in _norm_catalog(catalog):
        shared_tech = cand_tech & set(r["techniques"])
        shared_tok = cand_tokens & r["tokens"]
        if not shared_tech and len(shared_tok) < 2:
            continue
        why = []
        if shared_tech:
            why.append("ATT&CK " + ", ".join(sorted(shared_tech)))
        if len(shared_tok) >= 2:
            why.append("name overlap: " + ", ".join(sorted(shared_tok)[:4]))
        hits.append(Overlap(name=r["name"], source=r["source"], reason="; ".join(why),
                            score=len(shared_tech) * 2 + len(shared_tok)))
    hits.sort(key=lambda h: h.score, reverse=True)
    return hits[:limit]
