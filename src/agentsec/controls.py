"""CTRL-INPUT-001: lightweight REFERENCE input inspection before the LLM call (INV-008).

This is a lab teaching control. It is not production prompt-injection protection.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

CONTROL_ID = "CTRL-INPUT-001"
CONTROL_TYPE = "input_inspection"

# Lab-owned injection signatures. Teaching strings, not a product IPS.
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
    control_type: str
    decision: str
    reason: str
    matched_rule: str | None
    profile: str
    error_stage: str | None = None

    @property
    def blocks_llm(self) -> bool:
        return self.decision in ("DENY", "ERROR")


def match_injection_rule(text: str) -> str | None:
    for pattern, rule_id in _RULES:
        if pattern.search(text):
            return rule_id
    return None


def inspect_input(text: str, profile: str) -> ControlResult:
    """Run before Ollama. Empty/malformed is ERROR in both profiles (not a labeled fail-open)."""
    if not isinstance(text, str):
        return ControlResult(
            control_id=CONTROL_ID,
            control_type=CONTROL_TYPE,
            decision="ERROR",
            reason="malformed_input",
            matched_rule=None,
            profile=profile,
            error_stage="schema_validation",
        )

    stripped = text.strip()
    if not stripped:
        return ControlResult(
            control_id=CONTROL_ID,
            control_type=CONTROL_TYPE,
            decision="ERROR",
            reason="empty_input",
            matched_rule=None,
            profile=profile,
            error_stage="schema_validation",
        )

    rule = match_injection_rule(stripped)
    if rule is None:
        return ControlResult(
            control_id=CONTROL_ID,
            control_type=CONTROL_TYPE,
            decision="ALLOW",
            reason="benign_loan_request",
            matched_rule=None,
            profile=profile,
        )

    if profile == "vulnerable":
        return ControlResult(
            control_id=CONTROL_ID,
            control_type=CONTROL_TYPE,
            decision="ALLOW",
            reason=(
                "vulnerable_profile_fail_open:"
                "CTRL-INPUT-001 is a lightweight lab reference control and "
                f"intentionally returns ALLOW (fail-open) for matched rule {rule}"
            ),
            matched_rule=rule,
            profile=profile,
        )

    return ControlResult(
        control_id=CONTROL_ID,
        control_type=CONTROL_TYPE,
        decision="DENY",
        reason="input_pattern_matched",
        matched_rule=rule,
        profile=profile,
    )


def evaluate_input_control(text: str, profile: str, inspect_fn=inspect_input) -> ControlResult:
    """Fail closed if control evaluation itself raises."""
    try:
        return inspect_fn(text, profile)
    except Exception as exc:
        return ControlResult(
            control_id=CONTROL_ID,
            control_type=CONTROL_TYPE,
            decision="ERROR",
            reason=f"control_evaluation_failure:{type(exc).__name__}",
            matched_rule=None,
            profile=profile,
            error_stage="control_evaluation",
        )
