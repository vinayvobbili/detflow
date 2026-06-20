"""detflow command line — draft, lint, and review detections from a terminal.

    detflow draft "powershell with an encoded command from a word macro"
    detflow draft "..." --format cortex-xql
    detflow lint rule.yml
    detflow review rule.yml --catalog catalog.json
    detflow analyze advisory.txt --export brief
    detflow analyze advisory.txt --export stix --cve CVE-2024-1234

Drafting/review/analyze use the environment model (DETFLOW_LLM_*); lint is offline.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from detflow import (
    analyze,
    draft,
    lint,
    review,
    to_brief_markdown,
    to_navigator_layer,
    to_stix_bundle,
)
from detflow.models import RuleFormat


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _load_catalog(path: Optional[str]) -> list:
    if not path:
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else data.get("rules", [])
    except Exception as e:  # noqa: BLE001
        print(f"warning: could not read catalog {path}: {e}", file=sys.stderr)
        return []


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="detflow", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_draft = sub.add_parser("draft", help="draft a detection from plain English")
    p_draft.add_argument("description", help="what to detect, in plain English")
    p_draft.add_argument("--format", "-f", default="sigma", choices=["sigma", "cortex-xql"])

    p_lint = sub.add_parser("lint", help="lint a rule file (offline)")
    p_lint.add_argument("path", help="path to the rule, or - for stdin")
    p_lint.add_argument("--format", "-f", default="sigma", choices=["sigma", "cortex-xql"])

    p_rev = sub.add_parser("review", help="review a rule file")
    p_rev.add_argument("path", help="path to the rule, or - for stdin")
    p_rev.add_argument("--format", "-f", default="sigma", choices=["sigma", "cortex-xql"])
    p_rev.add_argument("--catalog", "-c", help="JSON catalog of existing rules for overlap")
    p_rev.add_argument("--json", action="store_true", help="emit the full result as JSON")

    p_an = sub.add_parser("analyze", help="analyze a threat report into a detection package")
    p_an.add_argument("path", help="path to the report text, or - for stdin")
    p_an.add_argument("--cve", action="append", default=[],
                      help="anchor CVE id (repeatable); CVEs in the text are added automatically")
    p_an.add_argument("--audience", "-a", default="dr",
                      choices=["dr", "soc", "purple_team", "red_team", "leadership", "general"],
                      help="who the intelligence brief is written for")
    p_an.add_argument("--export", "-e", choices=["brief", "stix", "navigator", "json"],
                      help="emit an export artifact instead of the human summary")

    args = parser.parse_args(argv)

    if args.cmd == "draft":
        res = draft(args.description, RuleFormat.coerce(args.format))
        if not res.ok:
            print(f"error: {res.error}", file=sys.stderr)
            return 1
        print(res.rule)
        return 0

    if args.cmd == "lint":
        rep = lint(_read(args.path), RuleFormat.coerce(args.format))
        print(f"{rep.status.upper()}: {rep.summary}")
        for f in rep.findings:
            print(f"  {f.level}: {f.message}")
        return 0 if rep.ok else 1

    if args.cmd == "review":
        rev = review(_read(args.path), RuleFormat.coerce(args.format),
                     catalog=_load_catalog(args.catalog))
        if args.json:
            print(json.dumps(rev.to_dict(), indent=2))
            return 0
        score = rev.quality_score if rev.quality_score is not None else "—"
        print(f"Quality {score}/100 · FP risk {rev.false_positive_risk} · verdict {rev.verdict}")
        if rev.summary:
            print(rev.summary)
        for o in rev.overlaps:
            print(f"  overlaps: [{o.source}] {o.name} — {o.reason}")
        for i in rev.improvements:
            print(f"  improve: {i}")
        return 0

    if args.cmd == "analyze":
        an = analyze(_read(args.path), cves=args.cve, audience=args.audience)
        if not an.ok:
            print(f"error: {an.error}", file=sys.stderr)
            return 1
        if args.export == "stix":
            print(json.dumps(to_stix_bundle(an), indent=2))
        elif args.export == "navigator":
            print(json.dumps(to_navigator_layer(an), indent=2))
        elif args.export == "brief":
            print(to_brief_markdown(an))
        elif args.export == "json":
            print(json.dumps(an.to_dict(), indent=2))
        else:
            print(an.summary)
            if an.overview:
                print("\n" + an.overview)
            for t in an.techniques:
                print(f"  {t.technique_id} {t.technique_name} ({t.tactic}, {t.confidence})")
            for r in an.rules:
                lint_bit = f" — lint {r.lint.status}" if r.lint else ""
                print(f"  rule: [{r.rule_type}] {r.rule_name}{lint_bit}")
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
