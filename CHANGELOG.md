# Changelog

All notable changes to detflow are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to
[Semantic Versioning](https://semver.org/).

## [0.1.0] — unreleased

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
