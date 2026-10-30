"""What a challenge module provides. Scenario engines are the EXISTING ones (loan_desk, mcp pipelines); a module only drives them
in-process with a CTF-owned MemorySink and decides success from the events that run recorded."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

from agentsec.ctf.registry import Challenge

POSTURES = ("baseline", "hardened")   # baseline = the intentionally weak lab posture; hardened = the control that should hold


class ParamError(ValueError):
    """code is a fixed, safe machine string."""


@dataclass(frozen=True)
class Verdict:
    ok: bool
    summary: str
    checks: tuple[tuple[str, bool], ...] = field(default_factory=tuple)

    def public(self) -> dict:
        return {"ok": self.ok, "summary": self.summary, "checks": [{"check": c, "passed": p} for c, p in self.checks]}


class Scenario(Protocol):
    challenge: Challenge

    def validate(self, params: object, prior_steps: list[str]) -> dict: ...
    def execute(self, params: dict, step_index: int) -> tuple[str, dict]: ...      # -> (run_id, bundle)
    def verify(self, bundles: list[dict]) -> Verdict: ...                           # pure function of recorded events
    def materials(self) -> dict: ...                                                # server-rendered, non-answer reading material


def strict_params(params: object, allowed: dict[str, Callable[[Any], Any]]) -> dict:
    """Exactly the allowed keys, each coerced/validated by its function (which raises ParamError). Unknown or missing keys are errors."""
    if not isinstance(params, dict) or set(params) != set(allowed):
        raise ParamError("bad_parameters")
    return {k: fn(params[k]) for k, fn in allowed.items()}


def posture(value: object) -> str:
    if value not in POSTURES:
        raise ParamError("bad_posture")
    return value  # type: ignore[return-value]
