# Changelog

All notable changes to detflow are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to
[Semantic Versioning](https://semver.org/).

## [0.2.0]

CTI → detection package. detflow now works in both directions: from plain
English to a rule (draft), and from a raw threat report to a full detection
package (analyze).

### Added
- `analyze(report, cves=..., audience=..., model=...)` — turn a threat report
  (CVE advisory, CTI writeup, IOC/TTP dump) into a grounded `ThreatAnalysis`:
  tactic-ordered ATT&CK techniques with evidence + confidence, generated
  **Sigma + YARA + Suricata** rules (Sigma linted in place via `lint_sigma`),
  severity/TLP, and an audience-targeted intelligence brief. Treats the report
  as untrusted input (prompt-injection hardening); never raises.
- Exports: `to_stix_bundle()` (STIX 2.1, deterministic IDs), `to_navigator_layer()`
  (ATT&CK Navigator v4.5), `to_brief_markdown()`, and `audience_options()`.
- New result types: `ThreatAnalysis`, `ThreatTechnique`, `GeneratedRule`,
  `IntelBrief`.
- CLI: `detflow analyze <file> [--cve …] [--audience …] [--export brief|stix|navigator|json]`.

## [0.1.0]

Initial release.

### Added
- `draft(description, fmt)` — draft a detection from plain English, as
  vendor-neutral **Sigma** or **Cortex XSIAM XQL**.
- `lint(rule, fmt)` — deterministic, offline structural lint for Sigma rules and
  XQL queries (`lint_sigma`, `lint_xql`).
- `find_overlaps(rule, catalog)` — deduplicate a candidate detection against a
  catalog you supply, by shared ATT&CK technique and title-token overlap.
- `review(rule, fmt, catalog=...)` — senior-engineer review: quality score,
  false-positive risk, ATT&CK coverage, gaps, strengths, improvements, and an
  approve/revise/reject verdict, with a deterministic floor when no model is set.
- Pluggable models: `OpenAIChatModel`, `default_model()` from `DETFLOW_LLM_*`,
  and `LangChainModel` to wrap any LangChain chat model (including a
  `langchain-failover` chain).
- `detflow` CLI: `draft`, `lint`, `review`.
