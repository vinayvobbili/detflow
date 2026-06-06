"""Model abstraction for the drafting + review paths.

detflow is model-agnostic. A "model" is anything with a ``complete`` method::

    def complete(self, system: str, user: str, *, json: bool = False) -> str: ...

Three ways to get one:

* :class:`OpenAIChatModel` — a thin client for any OpenAI-compatible chat
  endpoint (OpenAI, Azure OpenAI, a local vLLM/Ollama server, a gateway).
  Needs ``pip install "detflow[llm]"``.
* :func:`default_model` — build one from the environment (``DETFLOW_LLM_API_KEY``
  / ``DETFLOW_LLM_BASE_URL`` / ``DETFLOW_LLM_MODEL``), or ``None`` if unset.
* :class:`LangChainModel` — wrap any LangChain chat model. This is how you give
  detflow a failover chain (e.g. langchain-failover's FailoverChatModel) so a
  primary-model outage transparently falls back to a secondary.

The deterministic core (lint, overlap) never needs a model; drafting requires
one; review uses one when present and falls back to a deterministic floor.
"""
from __future__ import annotations

import json as _json
import os
from typing import Any, Mapping, Optional

try:  # typing-only; the Protocol is not required at runtime on 3.9
    from typing import Protocol, runtime_checkable
except ImportError:  # pragma: no cover
    Protocol = object  # type: ignore

    def runtime_checkable(cls):  # type: ignore
        return cls


@runtime_checkable
class DetectionModel(Protocol):
    """Structural type for a chat model detflow can call."""

    name: str

    def complete(self, system: str, user: str, *, json: bool = False) -> str:
        """Return the assistant's text for a (system, user) prompt. When ``json``
        is True the caller wants a single JSON object back (the model should be
        asked for / constrained to JSON)."""
        ...


class OpenAIChatModel:
    """Minimal client for any OpenAI-compatible ``/chat/completions`` endpoint."""

    def __init__(self, api_key: Optional[str] = None, *, base_url: str = "https://api.openai.com/v1",
                 model: str = "gpt-4o-mini", temperature: float = 0.15, timeout: float = 90.0):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.temperature = temperature
        self.timeout = timeout
        self.name = f"openai:{model}"

    def complete(self, system: str, user: str, *, json: bool = False) -> str:
        import requests  # local import so the core stays stdlib-only

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        body: dict = {
            "model": self.model,
            "temperature": self.temperature,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
        }
        if json:
            body["response_format"] = {"type": "json_object"}
        resp = requests.post(f"{self.base_url}/chat/completions", headers=headers,
                             data=_json.dumps(body), timeout=self.timeout)
        resp.raise_for_status()
        data = resp.json()
        return (data.get("choices") or [{}])[0].get("message", {}).get("content", "") or ""


class LangChainModel:
    """Adapt any LangChain chat model to the :class:`DetectionModel` shape.

    Pass a failover chain here to make detflow resilient::

        from langchain_failover import FailoverChatModel
        from langchain_openai import ChatOpenAI
        from detflow.llm import LangChainModel

        chain = FailoverChatModel(models=[ChatOpenAI(model="gpt-4o-mini"), local_llm])
        model = LangChainModel(chain)
    """

    def __init__(self, chat_model: Any, *, name: Optional[str] = None):
        self._llm = chat_model
        self.name = name or f"langchain:{type(chat_model).__name__}"

    def complete(self, system: str, user: str, *, json: bool = False) -> str:
        try:
            from langchain_core.messages import HumanMessage, SystemMessage
            messages = [SystemMessage(content=system), HumanMessage(content=user)]
        except Exception:  # pragma: no cover - very old langchain
            messages = [("system", system), ("human", user)]
        result = self._llm.invoke(messages)
        return getattr(result, "content", None) or (result if isinstance(result, str) else "")


def default_model(env: Optional[Mapping[str, str]] = None) -> Optional["DetectionModel"]:
    """Build an :class:`OpenAIChatModel` from the environment, or return ``None``.

    Reads ``DETFLOW_LLM_API_KEY``, ``DETFLOW_LLM_BASE_URL``, ``DETFLOW_LLM_MODEL``.
    Returns ``None`` when neither a key nor a base URL is set, so callers can
    treat "no model configured" as a normal, non-error state.
    """
    env = env if env is not None else os.environ
    key = env.get("DETFLOW_LLM_API_KEY")
    base = env.get("DETFLOW_LLM_BASE_URL")
    model = env.get("DETFLOW_LLM_MODEL")
    if not key and not base:
        return None
    kwargs: dict = {}
    if key:
        kwargs["api_key"] = key
    if base:
        kwargs["base_url"] = base
    if model:
        kwargs["model"] = model
    return OpenAIChatModel(**kwargs)
