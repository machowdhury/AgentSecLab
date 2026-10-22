"""Model client for the Loan Desk agent: Ollama /api/chat with schema-constrained JSON output.

The benchmark (docs/reviews/batch2/model_benchmark.json) found grammar-constrained `format`
output far more reliable than native `tools` on every installed model, so proposals use it.
This module only produces text; it never authorises or executes anything.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from typing import Protocol

import requests

from agentsec.loan_desk.tools import TOOLS

RECOMMENDATIONS = ("PROCEED_TO_UNDERWRITER", "NEEDS_MORE_INFORMATION", "NOT_RECOMMENDED")
REPLY_SCHEMA = {
    "type": "object",
    "properties": {
        "action": {"type": "string", "enum": ["tool", "final"]},
        "tool": {"type": "string", "enum": sorted(TOOLS)},
        "arguments": {"type": "object"},
        "summary": {"type": "string"},
        "recommendation": {"type": "string", "enum": list(RECOMMENDATIONS)},
    },
    "required": ["action"],
}


@dataclass(frozen=True)
class ModelReply:
    text: str
    tokens_in: int = 0
    tokens_out: int = 0
    model: str = ""
    latency_ms: int = 0
    error_type: str | None = None
    error_message: str | None = None

    @property
    def ok(self) -> bool:
        return self.error_type is None


class ChatModel(Protocol):
    name: str
    source: str  # "model" for real inference; anything else is labelled as not model-driven

    def chat(self, messages: list[dict]) -> ModelReply: ...


def configured_model_name(default: str) -> str:
    return os.environ.get("LOANDESK_MODEL", "").strip() or default


class OllamaChat:
    source = "model"

    def __init__(self, base_url: str, name: str, *, timeout: int = 60) -> None:
        self.base_url, self.name, self.timeout = base_url.rstrip("/"), name, timeout

    def available(self) -> tuple[bool, str | None]:
        """Probe the same endpoint chat() uses, so the status shown can never disagree with the run."""
        try:
            r = requests.get(f"{self.base_url}/api/tags", timeout=3)
            names = [m.get("name", "") for m in r.json().get("models", [])]
        except (requests.RequestException, ValueError):
            return False, "Ollama is not reachable from AcmeBank."
        if r.status_code != 200:
            return False, "Ollama returned an error."
        want = self.name if ":" in self.name else self.name + ":latest"
        return (True, None) if want in names else (False, f"Ollama is reachable but model {self.name!r} is not installed.")

    def chat(self, messages: list[dict]) -> ModelReply:
        t0 = time.monotonic()
        try:
            r = requests.post(
                f"{self.base_url}/api/chat",
                json={"model": self.name, "messages": messages, "stream": False, "format": REPLY_SCHEMA,
                      "options": {"temperature": 0.2, "num_predict": 300}},
                timeout=self.timeout,
            )
            if r.status_code == 404:
                return ModelReply("", error_type="model_not_found", error_message=f"Ollama has no model {self.name!r}")
            r.raise_for_status()
            body = r.json()
        except requests.Timeout:
            return ModelReply("", error_type="timeout", error_message=f"no reply within {self.timeout}s")
        except (requests.RequestException, ValueError) as exc:
            return ModelReply("", error_type="connection_error", error_message=type(exc).__name__)
        return ModelReply(
            text=str((body.get("message") or {}).get("content", "")),
            tokens_in=int(body.get("prompt_eval_count") or 0), tokens_out=int(body.get("eval_count") or 0),
            model=str(body.get("model") or self.name), latency_ms=int((time.monotonic() - t0) * 1000),
        )


def parse_reply(text: str) -> tuple[str, dict] | tuple[None, str]:
    """('tool'|'final', data) or (None, reason). Pure parsing: no authority is decided here."""
    try:
        doc = json.loads(text)
    except (TypeError, json.JSONDecodeError):
        return None, "reply_not_json"
    if not isinstance(doc, dict) or doc.get("action") not in ("tool", "final"):
        return None, "missing_or_unknown_action"
    if doc["action"] == "final":
        rec = doc.get("recommendation")
        if rec not in RECOMMENDATIONS or not isinstance(doc.get("summary"), str) or len(doc["summary"].strip()) < 30:
            return None, "final_missing_summary_or_recommendation"
        return "final", {"summary": doc["summary"].strip()[:600], "recommendation": rec}
    if doc.get("tool") not in TOOLS:
        return None, "unknown_tool"
    if not isinstance(doc.get("arguments"), dict):
        return None, "arguments_not_object"
    return "tool", {"tool": doc["tool"], "arguments": doc["arguments"]}
