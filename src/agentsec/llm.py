"""Ollama HTTP client. Attack Service must not import and call this."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

import requests

from agentsec.settings import Settings, get_settings


@dataclass(frozen=True)
class LLMResult:
    text: str
    input_tokens: int
    output_tokens: int
    model: str
    latency_ms: float
    error_type: str | None = None
    error_message: str | None = None

    @property
    def ok(self) -> bool:
        return self.error_type is None


class LLMClient(Protocol):
    def health(self) -> bool: ...

    def generate(
        self,
        *,
        agent_id: str,
        system_prompt: str,
        user_message: str,
        temperature: float,
        max_tokens: int,
    ) -> LLMResult: ...


class OllamaClient:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    def health(self) -> bool:
        try:
            response = requests.get(f"{self.settings.ollama_base_url}/api/tags", timeout=5)
            if response.status_code != 200:
                return False
            models = [item.get("name", "") for item in response.json().get("models", [])]
            target = self.settings.ollama_model.split(":")[0]
            return any(target in name for name in models)
        except requests.RequestException:
            return False

    def generate(
        self,
        *,
        agent_id: str,
        system_prompt: str,
        user_message: str,
        temperature: float,
        max_tokens: int,
    ) -> LLMResult:
        del agent_id
        prompt = f"[SYSTEM]\n{system_prompt}\n\n[USER]\n{user_message}\n\n[ASSISTANT]"
        try:
            response = requests.post(
                f"{self.settings.ollama_base_url}/api/generate",
                json={
                    "model": self.settings.ollama_model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": temperature,
                        "num_predict": max_tokens,
                        "stop": ["[USER]", "[SYSTEM]"],
                    },
                },
                timeout=120,
            )
            response.raise_for_status()
            payload = response.json()
        except requests.Timeout as exc:
            return LLMResult(
                text="",
                input_tokens=0,
                output_tokens=0,
                model=self.settings.ollama_model,
                latency_ms=120000,
                error_type="timeout",
                error_message=str(exc)[:500],
            )
        except requests.RequestException as exc:
            return LLMResult(
                text="",
                input_tokens=0,
                output_tokens=0,
                model=self.settings.ollama_model,
                latency_ms=0,
                error_type="connection_error",
                error_message=str(exc)[:500],
            )

        text = str(payload.get("response", "")).strip()
        input_tokens = int(payload.get("prompt_eval_count") or 0)
        output_tokens = int(payload.get("eval_count") or 0)
        model = str(payload.get("model") or self.settings.ollama_model)
        total_ns = int(payload.get("total_duration") or 0)
        latency_ms = round(total_ns / 1_000_000, 2) if total_ns else 0.0
        return LLMResult(
            text=text,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            model=model,
            latency_ms=latency_ms,
        )


@dataclass
class StubLLM:
    """Deterministic stand-in. Security proofs use this spy, not live Ollama."""

    calls: list[dict] = field(default_factory=list)
    responses: dict[str, str] = field(default_factory=dict)
    default_text: str = '{"ok": true, "summary": "standard applicant"}'
    healthy: bool = True
    error_type: str | None = None
    error_message: str | None = None

    @property
    def call_count(self) -> int:
        return len(self.calls)

    def health(self) -> bool:
        return self.healthy

    def generate(
        self,
        *,
        agent_id: str,
        system_prompt: str,
        user_message: str,
        temperature: float,
        max_tokens: int,
    ) -> LLMResult:
        self.calls.append(
            {
                "agent_id": agent_id,
                "system_prompt": system_prompt,
                "user_message": user_message,
                "temperature": temperature,
                "max_tokens": max_tokens,
            }
        )
        if self.error_type:
            return LLMResult(
                text="",
                input_tokens=0,
                output_tokens=0,
                model="stub-model",
                latency_ms=0,
                error_type=self.error_type,
                error_message=self.error_message or self.error_type,
            )
        text = self.responses.get(agent_id, self.default_text)
        return LLMResult(
            text=text,
            input_tokens=12,
            output_tokens=8,
            model="stub-model",
            latency_ms=1,
        )


@dataclass
class CountingLLM:
    """Spying boundary: proves whether the inner LLM client was called."""

    inner: LLMClient
    calls: list[dict] = field(default_factory=list)

    @property
    def call_count(self) -> int:
        return len(self.calls)

    def health(self) -> bool:
        return self.inner.health()

    def generate(
        self,
        *,
        agent_id: str,
        system_prompt: str,
        user_message: str,
        temperature: float,
        max_tokens: int,
    ) -> LLMResult:
        self.calls.append(
            {
                "agent_id": agent_id,
                "system_prompt": system_prompt,
                "user_message": user_message,
                "temperature": temperature,
                "max_tokens": max_tokens,
            }
        )
        return self.inner.generate(
            agent_id=agent_id,
            system_prompt=system_prompt,
            user_message=user_message,
            temperature=temperature,
            max_tokens=max_tokens,
        )
