"""CTRL-INPUT-001: inspect untrusted text before the LLM call (INV-008)."""

from __future__ import annotations

import re
from dataclasses import dataclass

CONTROL_ID = "CTRL-INPUT-001"

# Lab-owned injection signatures. These are teaching strings, not a product IPS.
_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions", re.IGNORECASE),
        "ignore_previous_instructions",
    ),
    (
        re.compile(r"disregard\s+(your|all|the)\s+(system\s+)?(prompt|instructions)", re.IGNORECASE),
        "disregard_instructions",
    ),
    (
        re.compile(r"you\s+are\s+now\s+(dan|unrestricted|jailbroken)", re.IGNORECASE),
        "persona_override",
    ),
    (
        re.compile(r"override\s+(the\s+)?(credit|risk|compliance)\s+(decision|agent|check)", re.IGNORECASE),
        "override_agent",
    ),
    (
        re.compile(r"reveal\s+(your\s+)?(system\s+)?prompt", re.IGNORECASE),
        "prompt_exfil",
    ),
)


@dataclass(frozen=True)
class ControlResult:
    control_id: str
    decision: str
    reason: str
    matched_rule: str | None
    profile: str

    @property
    def blocks_llm(self) -> bool:
        return self.decision in ("DENY", "ERROR")


def match_injection_rule(text: str) -> str | None:
    for pattern, rule_id in _RULES:
        if pattern.search(text):
            return rule_id
    return None


def inspect_input(text: str, profile: str) -> ControlResult:
    """Run before Ollama. Missing/empty input is ERROR in defended (fail closed)."""
    if not isinstance(text, str):
        return ControlResult(
            control_id=CONTROL_ID,
            decision="ERROR",
            reason="malformed_input",
            matched_rule=None,
            profile=profile,
        )

    stripped = text.strip()
    if not stripped:
        decision = "ERROR" if profile == "defended" else "ALLOW"
        reason = "empty_input" if profile == "defended" else "vulnerable_profile_fail_open:empty_input"
        return ControlResult(
            control_id=CONTROL_ID,
            decision=decision,
            reason=reason,
            matched_rule=None,
            profile=profile,
        )

    rule = match_injection_rule(stripped)
    if rule is None:
        return ControlResult(
            control_id=CONTROL_ID,
            decision="ALLOW",
            reason="benign_loan_request",
            matched_rule=None,
            profile=profile,
        )

    if profile == "vulnerable":
        return ControlResult(
            control_id=CONTROL_ID,
            decision="ALLOW",
            reason=f"vulnerable_profile_fail_open:{rule}",
            matched_rule=rule,
            profile=profile,
        )

    return ControlResult(
        control_id=CONTROL_ID,
        decision="DENY",
        reason="input_pattern_matched",
        matched_rule=rule,
        profile=profile,
    )
