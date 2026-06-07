# detflow

**A detection-engineering copilot.** Draft detections from plain English and
review them like a senior detection engineer — in vendor-neutral **Sigma** or
**Cortex XSIAM XQL**. Offline-safe, model-agnostic, and built to drop into a
detection-as-code pipeline.

> **Background:** [detflow: A Detection-Engineering Copilot You Can pip install](https://vinayvobbili.github.io/posts/detflow-detection-engineering-copilot/) — why I built it, and the design behind the draft / lint / overlap / review flow.

```python
from detflow import draft, lint, review

# 1. Draft from plain English
d = draft("powershell launched with an encoded command by a Word macro")
print(d.rule)                     # → a Sigma rule

# 2. Lint it (deterministic, no model, never raises)
print(lint(d.rule).status)        # → pass | warn | fail

# 3. Review it like a senior engineer, deduped against your rule catalog
catalog = [{"name": "Encoded PowerShell", "source": "edr", "techniques": ["T1059.001"]}]
r = review(d.rule, catalog=catalog)
print(r.quality_score, r.false_positive_risk, r.verdict)
for o in r.overlaps:
    print("already covered by:", o.name, "—", o.reason)
```

## Why

The Sigma ecosystem is strong at *compiling* rules (pySigma) and *running* them,
but the authoring and review steps are still manual. detflow fills that gap:

- **Draft** — describe a behavior in plain English, get a valid rule back. No
  blank page.
- **Lint** — a fast, offline structural gate before you spend a model call.
- **Overlap** — don't ship the same coverage twice; dedup against the rules you
  already run.
- **Review** — a structured, senior-engineer assessment: quality, false-positive
  risk *and why*, ATT&CK coverage, gaps, concrete improvements, and a verdict.

It's the human-in-the-loop front end of a detection-as-code workflow: draft →
lint → review → (you) merge.

## Install

```bash
pip install detflow            # core: lint + overlap (stdlib + PyYAML)
pip install "detflow[llm]"     # + drafting/review via any OpenAI-compatible endpoint
pip install "detflow[langchain]"  # + bring your own LangChain model / failover chain
```

## Models

detflow is model-agnostic. A model is anything with
`complete(system, user, *, json=False) -> str`. Three ways to supply one:

**From the environment** (any OpenAI-compatible endpoint):

```bash
export DETFLOW_LLM_API_KEY=sk-...
export DETFLOW_LLM_BASE_URL=https://api.openai.com/v1   # or a local vLLM/Ollama
export DETFLOW_LLM_MODEL=gpt-4o-mini
```

```python
from detflow import draft
draft("encoded powershell from an office macro")   # picks up the env model
```

**Explicitly:**

```python
from detflow import review
from detflow.llm import OpenAIChatModel
review(rule, model=OpenAIChatModel(api_key="sk-...", model="gpt-4o-mini"))
```

**With failover** — wrap a [`langchain-failover`](https://pypi.org/project/langchain-failover/)
chain so a primary-model outage transparently falls back to a secondary:

```python
from langchain_failover import FailoverChatModel
from langchain_openai import ChatOpenAI
from detflow.llm import LangChainModel
from detflow import draft

chain = FailoverChatModel(models=[ChatOpenAI(model="gpt-4o-mini"), local_llm])
draft("...", model=LangChainModel(chain))
```

## The two formats

- **Sigma** (default) — vendor-neutral YAML; portable across SIEMs.
- **Cortex XSIAM XQL** (`fmt="cortex-xql"`) — author straight in XQL when you
  want full control on that platform.

```python
draft("rare parent spawning powershell", fmt="cortex-xql")
review(my_xql, fmt="cortex-xql", techniques=["T1059.001"], catalog=catalog)
```

## CLI

```bash
detflow draft "powershell with an encoded command from a word macro"
detflow draft "..." --format cortex-xql
detflow lint rule.yml
detflow review rule.yml --catalog catalog.json --json
```

## Design

- **Never raises.** `lint`, `find_overlaps`, and `review` always return a result;
  `draft` returns an error result (not an exception) when no model is configured.
- **Deterministic core.** Lint and overlap need no network and no keys; review
  degrades to a deterministic floor (lint + overlap + parsed metadata) with no
  model.
- **Bring your own catalog.** Overlap compares against a plain list of dicts you
  export from whatever platforms you run — no platform lock-in.

## License

MIT © Vinay Vobbilichetty
