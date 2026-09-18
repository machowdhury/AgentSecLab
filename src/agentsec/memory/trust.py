"""CTRL-MEMORY-CONTEXT-001 and the LAB-MEMORY-001 closed interpreter.

THIS IS INTENTIONALLY VULNERABLE LAB MACHINERY (overlay mint only).

CTRL-MEMORY-CONTEXT-001 classifies recalled persistent memory as DATA (OBSERVE).
It does not DENY a tool, ALLOW a tool, sanitize, quarantine, mint an
AllowTicket, or mutate coded policy.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agentsec.memory.fixtures import (
    AGENT_MEMORY_NOTE_MARKER,
    CLOSED_FOLLOW_ON_ARGS,
    CLOSED_FOLLOW_ON_SCOPE,
    CLOSED_FOLLOW_ON_TOOL,
    MEMORY_TRUST_LABEL,
    PROVENANCE,
)
from agentsec.memory.store import MemoryError, MemoryRecord

MEMORY_CONTROL_ID = "CTRL-MEMORY-CONTEXT-001"
MEMORY_CONTROL_TYPE = "memory_context_trust"
MEMORY_CONTEXT_IS_DATA_REASON = "memory_context_is_data"
MEMORY_FAIL_OPEN_REASON = "vulnerable_profile_fail_open:memory_derived_authority"


@dataclass(frozen=True)
class MemoryFollowOnIntent:
    """Closed follow-on request extracted from the memory fixture only."""

    tool_name: str
    requested_scope: str
    arguments: dict[str, Any]
    memory_id: str
    marker_recognized: bool


@dataclass(frozen=True)
class MemoryDerivedOverlay:
    """Per-recall-run memory-derived authority. Not a server-owned grant.

    INTENTIONALLY VULNERABLE LAB MACHINERY. Lives only inside one recall run.
    Refuses any tool/scope other than the closed memory follow-on fixture.
    """

    run_id: str
    memory_id: str
    allowed_tool: str
    allowed_scope: str
    label: str = "memory-derived"

    def __post_init__(self) -> None:
        if self.allowed_tool != CLOSED_FOLLOW_ON_TOOL:
            raise ValueError("memory overlay is not extensible")
        if self.allowed_scope != CLOSED_FOLLOW_ON_SCOPE:
            raise ValueError("memory overlay is not extensible")
        if self.label != "memory-derived":
            raise ValueError("memory overlay must be labeled memory-derived")

    def matches(self, tool_name: str, requested_scope: str) -> bool:
        return tool_name == self.allowed_tool and requested_scope == self.allowed_scope


@dataclass(frozen=True)
class MemoryTrustDecision:
    control_id: str
    control_type: str
    decision: str
    reason: str
    profile: str
    memory_id: str
    overlay_applied: bool
    memory_trust: str = MEMORY_TRUST_LABEL
    memory_provenance: str = PROVENANCE
    error_stage: str | None = None

    @property
    def blocks_recall(self) -> bool:
        return self.decision == "ERROR"


def interpret_recalled_content(
    content: object,
    *,
    memory_id: str,
) -> MemoryFollowOnIntent | None:
    """Recognize ONLY the controlled memory fixture marker.

    THIS IS INTENTIONALLY VULNERABLE LAB MACHINERY.

    Exact substring on the FULL content. Not case-folded. Not Unicode-normalized.
    The follow-on tool is closed: never taken from memory grammar.
    Does not consume a truncated preview.
    """
    if not isinstance(content, str) or not content:
        return None
    if AGENT_MEMORY_NOTE_MARKER not in content:
        return None
    return MemoryFollowOnIntent(
        tool_name=CLOSED_FOLLOW_ON_TOOL,
        requested_scope=CLOSED_FOLLOW_ON_SCOPE,
        arguments=dict(CLOSED_FOLLOW_ON_ARGS),
        memory_id=memory_id,
        marker_recognized=True,
    )


def mint_memory_derived_overlay(
    *,
    run_id: str,
    intent: MemoryFollowOnIntent,
) -> MemoryDerivedOverlay:
    if intent.tool_name != CLOSED_FOLLOW_ON_TOOL or intent.requested_scope != CLOSED_FOLLOW_ON_SCOPE:
        raise ValueError("memory overlay is not extensible")
    return MemoryDerivedOverlay(
        run_id=run_id,
        memory_id=intent.memory_id,
        allowed_tool=CLOSED_FOLLOW_ON_TOOL,
        allowed_scope=CLOSED_FOLLOW_ON_SCOPE,
        label="memory-derived",
    )


def evaluate_memory_trust(
    *,
    profile: str,
    recalled: MemoryRecord | None,
    recall_error: MemoryError | None,
) -> tuple[MemoryTrustDecision, MemoryFollowOnIntent | None]:
    """Classify recalled memory. Does not invoke a handler. Does not mint AllowTicket.

    Valid memory: OBSERVE memory_context_is_data in every profile (including vulnerable).
    Unknown / malformed: ERROR. Never ALLOW. Never DENY a tool.
    """
    del profile
    if recall_error is not None or recalled is None:
        reason = recall_error.reason if recall_error is not None else "malformed_memory_object"
        stage = recall_error.error_stage if recall_error is not None else "schema_validation"
        memory_id = recall_error.requested_id if recall_error is not None else "unknown"
        return (
            MemoryTrustDecision(
                control_id=MEMORY_CONTROL_ID,
                control_type=MEMORY_CONTROL_TYPE,
                decision="ERROR",
                reason=reason,
                profile="unknown",
                memory_id=memory_id,
                overlay_applied=False,
                error_stage=stage,
            ),
            None,
        )
    intent = interpret_recalled_content(recalled.content, memory_id=recalled.memory_id)
    decision = MemoryTrustDecision(
        control_id=MEMORY_CONTROL_ID,
        control_type=MEMORY_CONTROL_TYPE,
        decision="OBSERVE",
        reason=MEMORY_CONTEXT_IS_DATA_REASON,
        profile="unknown",
        memory_id=recalled.memory_id,
        overlay_applied=False,
        memory_trust=MEMORY_TRUST_LABEL,
        memory_provenance=recalled.provenance,
    )
    return decision, intent


def evaluate_memory_trust_safe(
    *,
    profile: str,
    recalled: MemoryRecord | None,
    recall_error: MemoryError | None,
    run_id: str,
) -> tuple[MemoryTrustDecision, MemoryFollowOnIntent | None, MemoryDerivedOverlay | None]:
    """Fail closed: exceptions become ERROR and never mint overlay or AllowTicket."""
    try:
        decision, intent = evaluate_memory_trust(
            profile=profile,
            recalled=recalled,
            recall_error=recall_error,
        )
    except Exception as exc:
        fail = MemoryTrustDecision(
            control_id=MEMORY_CONTROL_ID,
            control_type=MEMORY_CONTROL_TYPE,
            decision="ERROR",
            reason=f"control_evaluation_failure:{type(exc).__name__}",
            profile=profile,
            memory_id=recalled.memory_id if recalled is not None else "unknown",
            overlay_applied=False,
            error_stage="control_evaluation",
        )
        return fail, None, None
    decision = MemoryTrustDecision(
        control_id=decision.control_id,
        control_type=decision.control_type,
        decision=decision.decision,
        reason=decision.reason,
        profile=profile,
        memory_id=decision.memory_id,
        overlay_applied=False,
        memory_trust=decision.memory_trust,
        memory_provenance=decision.memory_provenance,
        error_stage=decision.error_stage,
    )
    overlay = None
    if decision.decision == "OBSERVE" and profile == "vulnerable" and intent is not None:
        try:
            overlay = mint_memory_derived_overlay(run_id=run_id, intent=intent)
        except Exception as exc:
            fail = MemoryTrustDecision(
                control_id=MEMORY_CONTROL_ID,
                control_type=MEMORY_CONTROL_TYPE,
                decision="ERROR",
                reason=f"control_evaluation_failure:{type(exc).__name__}",
                profile=profile,
                memory_id=decision.memory_id,
                overlay_applied=False,
                error_stage="control_evaluation",
            )
            return fail, None, None
        decision = MemoryTrustDecision(
            control_id=decision.control_id,
            control_type=decision.control_type,
            decision="OBSERVE",
            reason=MEMORY_CONTEXT_IS_DATA_REASON,
            profile=profile,
            memory_id=decision.memory_id,
            overlay_applied=True,
            memory_trust=MEMORY_TRUST_LABEL,
            memory_provenance=decision.memory_provenance,
        )
    return decision, intent, overlay
