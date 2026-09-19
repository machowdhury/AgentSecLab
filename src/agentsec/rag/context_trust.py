"""CTRL-RAG-CONTEXT-001 and the LAB-RAG-001 closed interpreter.

THIS IS INTENTIONALLY VULNERABLE LAB MACHINERY (overlay mint only).

CTRL-RAG-CONTEXT-001 classifies retrieved context as DATA (OBSERVE).
It does not DENY a tool, ALLOW a tool, sanitize, quarantine, mint an
AllowTicket, or mutate coded policy.

Valid NORMAL and MALICIOUS documents always OBSERVE retrieved_context_is_data,
including ATTACK. The vulnerable path may mint a temporary per-run overlay
for ONE closed follow-on tool. Overlay is consulted only by CTRL-MCP-001.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agentsec.rag.fixtures import (
    AGENT_NOTE_MARKER,
    CLOSED_FOLLOW_ON_ARGS,
    CLOSED_FOLLOW_ON_SCOPE,
    CLOSED_FOLLOW_ON_TOOL,
    CONTEXT_TRUST_LABEL,
    PROVENANCE,
)
from agentsec.rag.retriever import RetrievedContext, RetrievalError

CONTEXT_CONTROL_ID = "CTRL-RAG-CONTEXT-001"
CONTEXT_CONTROL_TYPE = "rag_context_trust"
RETRIEVED_CONTEXT_IS_DATA_REASON = "retrieved_context_is_data"
RAG_FAIL_OPEN_REASON = "vulnerable_profile_fail_open:retrieved_context_derived_authority"


@dataclass(frozen=True)
class ContextFollowOnIntent:
    """Closed follow-on request extracted from the RAG fixture only."""

    tool_name: str
    requested_scope: str
    arguments: dict[str, Any]
    document_id: str
    marker_recognized: bool


@dataclass(frozen=True)
class ContextDerivedOverlay:
    """Per-run retrieved-context-derived authority. Not a server-owned grant.

    INTENTIONALLY VULNERABLE LAB MACHINERY. Lives only inside one run.
    Refuses any tool/scope other than the closed RAG follow-on fixture.
    """

    run_id: str
    document_id: str
    allowed_tool: str
    allowed_scope: str
    label: str = "context-derived"

    def __post_init__(self) -> None:
        if self.allowed_tool != CLOSED_FOLLOW_ON_TOOL:
            raise ValueError("RAG overlay is not extensible")
        if self.allowed_scope != CLOSED_FOLLOW_ON_SCOPE:
            raise ValueError("RAG overlay is not extensible")
        if self.label != "context-derived":
            raise ValueError("RAG overlay must be labeled context-derived")

    def matches(self, tool_name: str, requested_scope: str) -> bool:
        return tool_name == self.allowed_tool and requested_scope == self.allowed_scope


@dataclass(frozen=True)
class ContextTrustDecision:
    control_id: str
    control_type: str
    decision: str
    reason: str
    profile: str
    document_id: str
    overlay_applied: bool
    context_trust: str = CONTEXT_TRUST_LABEL
    context_provenance: str = PROVENANCE
    error_stage: str | None = None

    @property
    def blocks_retrieve(self) -> bool:
        return self.decision == "ERROR"


def interpret_retrieved_content(
    content: object,
    *,
    document_id: str,
) -> ContextFollowOnIntent | None:
    """Recognize ONLY the controlled RAG fixture marker.

    THIS IS INTENTIONALLY VULNERABLE LAB MACHINERY.

    Not a general prompt parser. Not a command parser. Not a tool dispatcher.
    Exact substring on the FULL content. Not case-folded. Not Unicode-normalized.
    The follow-on tool is closed: never taken from document grammar.
    Does not consume a truncated preview.
    """
    if not isinstance(content, str) or not content:
        return None
    if AGENT_NOTE_MARKER not in content:
        return None
    return ContextFollowOnIntent(
        tool_name=CLOSED_FOLLOW_ON_TOOL,
        requested_scope=CLOSED_FOLLOW_ON_SCOPE,
        arguments=dict(CLOSED_FOLLOW_ON_ARGS),
        document_id=document_id,
        marker_recognized=True,
    )


def mint_context_derived_overlay(
    *,
    run_id: str,
    intent: ContextFollowOnIntent,
) -> ContextDerivedOverlay:
    if intent.tool_name != CLOSED_FOLLOW_ON_TOOL or intent.requested_scope != CLOSED_FOLLOW_ON_SCOPE:
        raise ValueError("RAG overlay is not extensible")
    return ContextDerivedOverlay(
        run_id=run_id,
        document_id=intent.document_id,
        allowed_tool=CLOSED_FOLLOW_ON_TOOL,
        allowed_scope=CLOSED_FOLLOW_ON_SCOPE,
        label="context-derived",
    )


def evaluate_context_trust(
    *,
    profile: str,
    retrieved: RetrievedContext | None,
    retrieval_error: RetrievalError | None,
) -> tuple[ContextTrustDecision, ContextFollowOnIntent | None]:
    """Classify retrieved context. Does not invoke a handler. Does not mint AllowTicket.

    Valid document: OBSERVE retrieved_context_is_data in every profile (including vulnerable).
    Unknown / malformed: ERROR. Never ALLOW. Never DENY a tool.
    """
    del profile  # classification is profile-independent; overlay mint is separate
    if retrieval_error is not None or retrieved is None:
        reason = retrieval_error.reason if retrieval_error is not None else "malformed_retrieval_object"
        stage = retrieval_error.error_stage if retrieval_error is not None else "schema_validation"
        document_id = retrieval_error.requested_id if retrieval_error is not None else "unknown"
        return (
            ContextTrustDecision(
                control_id=CONTEXT_CONTROL_ID,
                control_type=CONTEXT_CONTROL_TYPE,
                decision="ERROR",
                reason=reason,
                profile="unknown",
                document_id=document_id,
                overlay_applied=False,
                error_stage=stage,
            ),
            None,
        )
    intent = interpret_retrieved_content(retrieved.content, document_id=retrieved.document_id)
    decision = ContextTrustDecision(
        control_id=CONTEXT_CONTROL_ID,
        control_type=CONTEXT_CONTROL_TYPE,
        decision="OBSERVE",
        reason=RETRIEVED_CONTEXT_IS_DATA_REASON,
        profile="unknown",
        document_id=retrieved.document_id,
        overlay_applied=False,
        context_trust=CONTEXT_TRUST_LABEL,
        context_provenance=retrieved.provenance,
    )
    return decision, intent


def evaluate_context_trust_safe(
    *,
    profile: str,
    retrieved: RetrievedContext | None,
    retrieval_error: RetrievalError | None,
    run_id: str,
) -> tuple[ContextTrustDecision, ContextFollowOnIntent | None, ContextDerivedOverlay | None]:
    """Fail closed: exceptions become ERROR and never mint overlay or AllowTicket."""
    try:
        decision, intent = evaluate_context_trust(
            profile=profile,
            retrieved=retrieved,
            retrieval_error=retrieval_error,
        )
    except Exception as exc:
        fail = ContextTrustDecision(
            control_id=CONTEXT_CONTROL_ID,
            control_type=CONTEXT_CONTROL_TYPE,
            decision="ERROR",
            reason=f"control_evaluation_failure:{type(exc).__name__}",
            profile=profile,
            document_id=retrieved.document_id if retrieved is not None else "unknown",
            overlay_applied=False,
            error_stage="control_evaluation",
        )
        return fail, None, None
    decision = ContextTrustDecision(
        control_id=decision.control_id,
        control_type=decision.control_type,
        decision=decision.decision,
        reason=decision.reason,
        profile=profile,
        document_id=decision.document_id,
        overlay_applied=False,
        context_trust=decision.context_trust,
        context_provenance=decision.context_provenance,
        error_stage=decision.error_stage,
    )
    overlay = None
    if decision.decision == "OBSERVE" and profile == "vulnerable" and intent is not None:
        try:
            overlay = mint_context_derived_overlay(run_id=run_id, intent=intent)
        except Exception as exc:
            fail = ContextTrustDecision(
                control_id=CONTEXT_CONTROL_ID,
                control_type=CONTEXT_CONTROL_TYPE,
                decision="ERROR",
                reason=f"control_evaluation_failure:{type(exc).__name__}",
                profile=profile,
                document_id=decision.document_id,
                overlay_applied=False,
                error_stage="control_evaluation",
            )
            return fail, None, None
        decision = ContextTrustDecision(
            control_id=decision.control_id,
            control_type=decision.control_type,
            decision="OBSERVE",
            reason=RETRIEVED_CONTEXT_IS_DATA_REASON,
            profile=profile,
            document_id=decision.document_id,
            overlay_applied=True,
            context_trust=CONTEXT_TRUST_LABEL,
            context_provenance=decision.context_provenance,
        )
    return decision, intent, overlay
