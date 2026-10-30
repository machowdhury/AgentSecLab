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

from agentsec import model_identity
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
    executed: dict | None = None   # what Ollama said answered (name) and whether it matches the request; None for test doubles

    @property
    def ok(self) -> bool:
        return self.error_type is None


class ChatModel(Protocol):
    name: str
    source: str  # "model" for real inference; anything else is labelled as not model-driven

    def chat(self, messages: list[dict]) -> ModelReply: ...


# Approved default (Batch 2 whole-loop benchmark: docs/reviews/batch2/agent_loop_benchmark.json). Override with LOANDESK_MODEL.
DEFAULT_MODEL = model_identity.default_for("loan_desk")
RUNTIME_OPTIONS = {"temperature": 0.2, "num_predict": 300, "format": "json-schema(REPLY_SCHEMA)"}


def configured_model_name() -> str:
    return model_identity.requested_or_raw("loan_desk")[0]      # LOANDESK_MODEL, else the role default: the one canonical resolver (a malformed name is refused at call time)


class OllamaChat:
    source = "model"

    def __init__(self, base_url: str, name: str, *, timeout: int = 60) -> None:
        self.base_url, self.name, self.timeout = base_url.rstrip("/"), name, timeout
        self._cache = model_identity.ResolutionCache()

    def resolution(self) -> model_identity.Resolution:
        """What Ollama has installed under EXACTLY this model's name. Never a family or prefix match."""
        return self._cache.get(self.base_url, self.name)

    def identity(self) -> dict:
        """Requested versus resolved model identity as Ollama reports it (the digest pins what actually runs). Safe to call when Ollama is down:
        it then says why instead of returning a digest. The older keys (name, digest, size_bytes, family, parameter_size, quantization, runtime) are unchanged."""
        res = model_identity.resolve(self.base_url, self.name)
        out = {"requested": self.name, "identity_status": res.identity_status, "ollama_version": res.ollama_version, "runtime": RUNTIME_OPTIONS}
        if res.ok:
            out.update(name=res.name, digest=res.digest, size_bytes=res.size_bytes, family=res.family, parameter_size=res.parameter_size,
                       quantization=res.quantization)
        return out

    def readiness(self) -> dict:
        """First-run readiness: what is reachable, what is installed, and the exact manual fix. Never downloads anything."""
        try:
            want = model_identity.normalize(self.name)
        except model_identity.ModelConfigError as exc:
            return {"model": self.name[:200], "ollama_reachable": False, "model_installed": False, "installed_models": [],
                    "fix": {"kind": "invalid_model_name", "command": None, "where": "LOANDESK_MODEL in .env", "note": str(exc)}}
        out = {"model": want, "ollama_reachable": False, "model_installed": False, "installed_models": [], "fix": None}
        try:
            r = requests.get(f"{self.base_url}/api/tags", timeout=3)
        except requests.RequestException:
            out["fix"] = {"kind": "start_ollama", "command": "ollama serve",
                          "where": "on the machine that should run Ollama (or start the Ollama app)",
                          "note": "AcmeBank reaches Ollama through OLLAMA_BASE_URL in .env. Nothing is downloaded by the lab."}
            return out
        names: list[str] = []
        bad = r.status_code != 200
        if not bad:
            try:
                listed = r.json().get("models", [])
                if not isinstance(listed, list):
                    raise TypeError("models is not a list")
                names = [str(m.get("name", "")) for m in listed if isinstance(m, dict)]
            except (ValueError, AttributeError, TypeError):
                bad = True                                  # a payload that is not an Ollama model list is an Ollama problem, never a crash here
        if bad:
            out["fix"] = {"kind": "ollama_error", "command": None, "where": None, "note": "Ollama answered with an error or an unreadable model list. Check its log."}
            return out
        out.update(ollama_reachable=True, installed_models=sorted(names)[:20], model_installed=want in {_safe_norm(n) for n in names})
        if not out["model_installed"]:
            out["fix"] = {"kind": "pull_model", "command": f"ollama pull {want}", "where": "on the machine that runs the Ollama AcmeBank is configured to use",
                          "note": "The lab never downloads models for you. If the pull fails with a certificate error (x509), "
                                  "use your organisation's approved certificate process; do not disable TLS verification."}
        return out

    def available(self) -> tuple[bool, str | None]:
        """Probe the same endpoint chat() uses, so the status shown can never disagree with the run."""
        res = self.resolution()
        if res.status == model_identity.INVALID:
            return False, res.detail
        if res.status in (model_identity.UNREACHABLE, model_identity.ERROR):
            return False, "Ollama is not reachable from AcmeBank."
        if not res.ok:
            return False, f"Ollama is reachable but model {self.name!r} is not installed."
        return True, None

    def preflight(self) -> "ModelReply | None":
        """The refusal chat() would return when the requested model is not installed or its name is invalid, without sending anything; None otherwise.
        Unreachable Ollama stays a connection outcome of chat()."""
        res = self.resolution()
        if res.status not in (model_identity.NOT_INSTALLED, model_identity.INVALID):
            return None
        code = "model_not_found" if res.status == model_identity.NOT_INSTALLED else "model_config_invalid"
        return ModelReply("", error_type=code, error_message=res.detail[:300])

    def chat(self, messages: list[dict]) -> ModelReply:
        t0 = time.monotonic()
        res = self.resolution()
        if not res.ok:   # fail closed: never send the conversation to a model other than the one requested
            code = {model_identity.NOT_INSTALLED: "model_not_found", model_identity.INVALID: "model_config_invalid"}.get(res.status, "connection_error")
            return ModelReply("", error_type=code, error_message=res.detail[:300] if code != "connection_error" else "Ollama is not reachable")
        try:
            r = requests.post(
                f"{self.base_url}/api/chat",
                json={"model": self.name, "messages": messages, "stream": False, "format": REPLY_SCHEMA,
                      "options": {"temperature": RUNTIME_OPTIONS["temperature"], "num_predict": RUNTIME_OPTIONS["num_predict"]}},
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
        answered = body.get("model")
        executed = {"response_model": answered if isinstance(answered, str) and answered.strip() else None, "name_matches_requested": model_identity.response_matches(self.name, answered)}
        if executed["name_matches_requested"] is False:   # a different model answered: its text is discarded, not used as the requested model's
            return ModelReply("", model=str(answered), error_type="model_identity_mismatch", executed=executed,
                              error_message=f"requested {self.name!r} but Ollama reports {str(answered)[:80]!r}")
        return ModelReply(
            text=str((body.get("message") or {}).get("content", "")),
            tokens_in=int(body.get("prompt_eval_count") or 0), tokens_out=int(body.get("eval_count") or 0),
            model=str(body.get("model") or self.name), latency_ms=int((time.monotonic() - t0) * 1000), executed=executed,
        )


def _safe_norm(name: str) -> str:
    try:
        return model_identity.normalize(name)
    except model_identity.ModelConfigError:
        return ""


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
