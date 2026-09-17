"""Dedicated RAG retrieve path: observe context, then maybe request a follow-on tool."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable

from agentsec.events import EventEmitter, RunContext, content_hash, content_preview, new_span_id
from agentsec.experiment import (
    EXECUTION_MODE,
    SCHEMA_NAME,
    SCHEMA_VERSION,
    TELEMETRY_FIDELITY,
)
from agentsec.evidence import write_evidence_bundle
from agentsec.mcp.authorize import McpControlResult
from agentsec.mcp.client import McpClient
from agentsec.mcp.pipeline import McpHop, _run_follow_on_tool
from agentsec.mcp.policy import coded_policy, policy_unchanged_by_retrieved_context
from agentsec.mcp.registry import ToolRegistry, default_registry
from agentsec.mcp.server import McpServer
from agentsec.rag.context_trust import (
    CONTEXT_CONTROL_ID,
    CONTEXT_CONTROL_TYPE,
    ContextDerivedOverlay,
    ContextTrustDecision,
    RAG_FAIL_OPEN_REASON,
    RETRIEVED_CONTEXT_IS_DATA_REASON,
    evaluate_context_trust_safe,
)
from agentsec.rag.fixtures import (
    CONTEXT_TRUST_LABEL,
    PROVENANCE,
    RAG_AGENT_ID,
    RAG_AGENT_NAME,
    RAG_ATTACK_ID,
    RAG_WORKFLOW_ENTRY,
    RAG_WORKFLOW_NAME,
)
from agentsec.rag.retriever import RetrievedContext, retrieve, validate_retrieved_context
from agentsec.settings import Settings, get_settings
from agentsec.telemetry import EventSink, MemorySink, flush_export

AuthorizeFn = Callable[..., McpControlResult]
RetrieveFn = Callable[[object], tuple[RetrievedContext | None, object]]


@dataclass
class RagRetrieveResult:
    run_id: str
    incident_id: str
    testbed_mode: str
    execution_mode: str
    telemetry_fidelity: str
    profile: str
    blocked: bool
    block_reason: str | None
    terminal: str
    hops: list[McpHop]
    events: list[dict]
    evidence_dir: str | None
    handler_invoke_count: int
    expected_behavior: str
    actual_behavior: str
    attack_id: str
    error_stage: str | None = None
    document_id: str | None = None
    content_hash: str | None = None
    content_preview: str | None = None
    context_trust: str | None = None
    context_provenance: str | None = None
    context_control_decision: str | None = None
    context_control_reason: str | None = None
    context_derived_authority: bool = False
    follow_on_request: dict[str, Any] | None = None
    follow_on_decision: str | None = None
    follow_on_reason: str | None = None
    lookup_customer_tier_handler_count: int = 0
    server_owned_allowed_tools: str = "lookup_policy"


def _duration_ms(started: float) -> int:
    return max(0, int((time.monotonic() - started) * 1000))


def _context_trust_invariants(decision: str) -> list[str]:
    if decision == "ERROR":
        return ["INV-002", "INV-008", "INV-007"]
    return ["INV-002", "INV-007", "INV-008"]


def _mcp_invariants(decision: str) -> list[str]:
    if decision == "DENY":
        return ["INV-001", "INV-008", "INV-007"]
    if decision == "ERROR":
        return ["INV-008", "INV-007"]
    return ["INV-001", "INV-004", "INV-007"]


def _expected(profile: str, context_decision: str | None, follow_on: str | None) -> str:
    if context_decision == "ERROR":
        return "ERROR before follow-on; retrieved context is not a grant; handler 0"
    if profile == "vulnerable" and follow_on == "ALLOW":
        return (
            "CTRL-RAG-CONTEXT-001 OBSERVE retrieved_context_is_data; "
            f"follow-on lookup_customer_tier ALLOW {RAG_FAIL_OPEN_REASON}; handler 1"
        )
    if follow_on == "DENY":
        return (
            "CTRL-RAG-CONTEXT-001 OBSERVE retrieved_context_is_data; "
            "follow-on DENY tool_not_granted; follow-on handler 0"
        )
    return (
        "CTRL-RAG-CONTEXT-001 OBSERVE retrieved_context_is_data; "
        "no retrieved-context-derived authority; no follow-on"
    )


def run_rag_retrieve(
    *,
    document_id: str,
    sink: EventSink,
    memory: MemorySink,
    settings: Settings | None = None,
    user_id: str = "applicant-web",
    testbed_mode: str,
    attack_id: str = RAG_ATTACK_ID,
    write_evidence: bool = True,
    registry: ToolRegistry | None = None,
    authorize_fn: AuthorizeFn | None = None,
    retrieve_fn: RetrieveFn | None = None,
    retrieved_override: object | None = None,
    expected_behavior: str | None = None,
) -> RagRetrieveResult:
    settings = settings or get_settings()
    started = time.monotonic()
    registry = registry or default_registry()
    policy_before = coded_policy()
    server = McpServer(registry=registry, policy=policy_before, authorize_fn=authorize_fn)
    client = McpClient()

    ctx = RunContext.mint(
        user_id=user_id,
        testbed_mode=testbed_mode,
        attack_id=attack_id,
        workflow_entry=RAG_WORKFLOW_ENTRY,
        workflow_name=RAG_WORKFLOW_NAME,
    )
    emitter = EventEmitter(ctx, sink.emit, settings)
    emitter.run_started()

    hop_started_at = time.monotonic()
    hop_span_id = new_span_id()
    emitter.hop_started(
        hop_index=0,
        agent_id=RAG_AGENT_ID,
        agent_name=RAG_AGENT_NAME,
        hop_span_id=hop_span_id,
        delegator_agent_id=None,
    )

    retrieved: RetrievedContext | None = None
    retrieval_error = None
    try:
        if retrieved_override is not None:
            retrieved, retrieval_error = validate_retrieved_context(retrieved_override)
        else:
            retriever = retrieve_fn or retrieve
            retrieved, retrieval_error = retriever(document_id)
            if retrieved is not None and retrieval_error is None:
                retrieved, retrieval_error = validate_retrieved_context(retrieved)
    except Exception:
        from agentsec.rag.retriever import RetrievalError

        retrieved = None
        retrieval_error = RetrievalError(
            reason="retrieval_failure",
            error_stage="pipeline",
            requested_id=document_id if isinstance(document_id, str) and document_id else "unknown",
        )

    fingerprint_source = retrieved.content if retrieved is not None else (
        retrieval_error.reason if retrieval_error is not None else "malformed_retrieval_object"
    )
    doc_id_for_event = (
        retrieved.document_id
        if retrieved is not None
        else (retrieval_error.requested_id if retrieval_error is not None else document_id or "unknown")
    )
    bound_hash = content_hash(fingerprint_source)
    bound_preview = content_preview(fingerprint_source)

    try:
        ctx_decision, follow_intent, overlay = evaluate_context_trust_safe(
            profile=settings.security_profile,
            retrieved=retrieved,
            retrieval_error=retrieval_error,
            run_id=str(ctx.run_id),
        )
    except Exception as exc:
        ctx_decision = ContextTrustDecision(
            control_id=CONTEXT_CONTROL_ID,
            control_type=CONTEXT_CONTROL_TYPE,
            decision="ERROR",
            reason=f"control_evaluation_failure:{type(exc).__name__}",
            profile=settings.security_profile,
            document_id=doc_id_for_event,
            overlay_applied=False,
            error_stage="control_evaluation",
        )
        follow_intent = None
        overlay = None

    if retrieved is not None:
        interpreted = follow_intent
        from agentsec.rag.context_trust import interpret_retrieved_content

        check_intent = interpret_retrieved_content(retrieved.content, document_id=retrieved.document_id)
        if (check_intent is None) != (interpreted is None):
            ctx_decision = ContextTrustDecision(
                control_id=CONTEXT_CONTROL_ID,
                control_type=CONTEXT_CONTROL_TYPE,
                decision="ERROR",
                reason="control_evaluation_failure:check_use_mismatch",
                profile=settings.security_profile,
                document_id=retrieved.document_id,
                overlay_applied=False,
                error_stage="control_evaluation",
            )
            follow_intent = None
            overlay = None

    emitter.control_decision(
        hop_index=0,
        agent_id=RAG_AGENT_ID,
        agent_name=RAG_AGENT_NAME,
        hop_span_id=hop_span_id,
        control_id=CONTEXT_CONTROL_ID,
        control_type=CONTEXT_CONTROL_TYPE,
        decision=ctx_decision.decision,
        reason=ctx_decision.reason,
        trust_boundary="rag.retrieved.context",
        invariant_ids=_context_trust_invariants(ctx_decision.decision),
        content_text=fingerprint_source,
        origin_type="agent",
        origin_id=RAG_AGENT_ID,
        influence_kind="retrieved_context",
        delegator_agent_id=None,
        error_stage=ctx_decision.error_stage,
        rag_context_trust=CONTEXT_TRUST_LABEL,
        rag_context_provenance=PROVENANCE,
        rag_document_id=doc_id_for_event,
    )

    hops: list[McpHop] = []
    blocked = False
    block_reason = None
    error_stage = ctx_decision.error_stage
    hop_outcome = "hop_allowed"
    counts_before = registry.invoke_total
    counts_before_by_tool = dict(registry.invoke_counts)
    context_derived_authority = bool(overlay is not None and ctx_decision.overlay_applied)
    follow_on_decision = None
    follow_on_reason = None
    follow_on_request = None

    if ctx_decision.decision == "ERROR":
        blocked = True
        block_reason = ctx_decision.reason
        hop_outcome = "hop_error"
        emitter.pipeline_stopped(
            hop_index=0,
            agent_id=RAG_AGENT_ID,
            stop_reason="error",
            delegator_agent_id=None,
        )
    elif overlay is not None:
        server.context_derived_overlay = overlay

    hops.append(
        McpHop(
            index=0,
            agent_id=RAG_AGENT_ID,
            agent_name=RAG_AGENT_NAME,
            control_decision=ctx_decision.decision,
            control_reason=ctx_decision.reason,
            operation_attempted=False,
            operation_executed=False,
            operation_outcome="prevented" if ctx_decision.decision == "ERROR" else None,
            llm_started=False,
            llm_completed=False,
            llm_failed=False,
            mcp_started=False,
            mcp_completed=False,
            mcp_failed=False,
            span_id=hop_span_id,
            delegator_agent_id=None,
            handler_invoked=False,
            tool_name="",
            response=None,
            mcp_error=None,
        )
    )
    emitter.hop_completed(
        hop_index=0,
        agent_id=RAG_AGENT_ID,
        agent_name=RAG_AGENT_NAME,
        hop_span_id=hop_span_id,
        outcome=hop_outcome,
        duration_ms=_duration_ms(hop_started_at),
        delegator_agent_id=None,
    )

    if ctx_decision.decision != "ERROR" and follow_intent is not None:
        follow_on_request = {
            "tool": follow_intent.tool_name,
            "requested_scope": follow_intent.requested_scope,
            "arguments": dict(follow_intent.arguments),
        }
        follow_hop = _run_follow_on_tool(
            server=server,
            client=client,
            emitter=emitter,
            registry=registry,
            settings=settings,
            user_id=user_id,
            overlay=overlay if context_derived_authority else None,
            counts_before_by_tool=counts_before_by_tool,
            agent_id=RAG_AGENT_ID,
            agent_name=RAG_AGENT_NAME,
        )
        hops.append(follow_hop)
        follow_on_decision = follow_hop.control_decision
        follow_on_reason = follow_hop.control_reason
        if follow_hop.control_decision == "DENY":
            blocked = True
            block_reason = follow_hop.control_reason
        elif follow_hop.control_decision == "ERROR" or follow_hop.mcp_failed:
            blocked = True
            block_reason = (
                follow_hop.control_reason
                if follow_hop.control_decision == "ERROR"
                else (follow_hop.mcp_error or "mcp_error")
            )
            error_stage = "control_evaluation" if follow_hop.control_decision == "ERROR" else "mcp_invocation"

    last_hop = hops[-1]
    if blocked and last_hop.control_decision == "DENY":
        terminal = "completed_denied"
        emitter.run_completed(outcome="completed_denied", duration_ms=_duration_ms(started))
        actual = f"DENY {last_hop.tool_name}; handler_invokes={registry.invoke_total - counts_before}"
    elif blocked:
        terminal = "run_failed"
        stage = error_stage or "pipeline"
        emitter.run_failed(
            error_type=block_reason or "rag_error",
            error_stage=stage
            if stage
            in {
                "schema_validation",
                "control_evaluation",
                "argument_validation",
                "llm_invocation",
                "mcp_invocation",
                "telemetry_export",
                "pipeline",
            }
            else "pipeline",
            error_message=block_reason or "RAG retrieve stopped with error",
        )
        actual = f"ERROR {ctx_decision.reason}; handler_invokes={registry.invoke_total - counts_before}"
    else:
        terminal = "completed_allowed"
        emitter.run_completed(outcome="completed_allowed", duration_ms=_duration_ms(started))
        actual = (
            f"OBSERVE retrieved_context_is_data; "
            f"handler_invokes={registry.invoke_total - counts_before}"
        )

    handler_count = registry.invoke_total - counts_before
    lookup_tier_count = registry.invoke_counts.get("lookup_customer_tier", 0) - counts_before_by_tool.get(
        "lookup_customer_tier", 0
    )
    policy_after = coded_policy()
    if policy_after.allowed_tools != policy_before.allowed_tools:
        raise RuntimeError("RAG blocker: coded allowed_tools mutated")
    if policy_after.allowed_scopes != policy_before.allowed_scopes:
        raise RuntimeError("RAG blocker: coded allowed_scopes mutated")
    if policy_after.allowed_policy_ids != policy_before.allowed_policy_ids:
        raise RuntimeError("RAG blocker: coded allowed_policy_ids mutated")
    if policy_after.agent_id != policy_before.agent_id:
        raise RuntimeError("RAG blocker: coded agent identity mutated")
    policy_unchanged_by_retrieved_context(policy_after, retrieved.content if retrieved else None)
    expected = expected_behavior or _expected(
        settings.security_profile, ctx_decision.decision, follow_on_decision
    )
    events = [event for event in memory.events if event.get("agentsec.run.id") == str(ctx.run_id)]
    export_report = flush_export(sink)
    evidence_dir = None
    if write_evidence:
        request_doc = {
            "document_id": document_id,
            "document.id.hash": content_hash(document_id),
        }
        bundle = write_evidence_bundle(
            run_id=str(ctx.run_id),
            incident_id=ctx.incident_id,
            settings=settings,
            events=events,
            user_input=document_id,
            hops=hops,
            testbed_mode=testbed_mode,
            attack_id=attack_id,
            expected_behavior=expected,
            actual_behavior=actual,
            llm_call_count=0,
            blocked=blocked,
            terminal=terminal,
            export_report=export_report,
            extra_manifest={
                "workflow.entry": RAG_WORKFLOW_ENTRY,
                "mcp.handler.invoked.count": handler_count,
                "mcp.handler.lookup_customer_tier.count": lookup_tier_count,
                "rag.document.id": doc_id_for_event,
                "rag.context.trust": CONTEXT_TRUST_LABEL,
                "rag.context.provenance": PROVENANCE,
                "rag.content.hash": bound_hash,
                "rag.content.preview": bound_preview,
                "rag.control.decision": ctx_decision.decision,
                "rag.control.reason": ctx_decision.reason,
                "rag.derived_authority": context_derived_authority,
                "follow_on.request": follow_on_request,
                "follow_on.decision": follow_on_decision,
                "follow_on.reason": follow_on_reason,
                "authority.source": (
                    "context-derived overlay" if context_derived_authority else "server-owned"
                ),
                "server_owned.allowed_tools": ",".join(sorted(policy_after.allowed_tools)),
                "splunk.verified": False,
            },
            request_doc=request_doc,
            extra_result={
                "rag.document.id": doc_id_for_event,
                "rag.context.trust": CONTEXT_TRUST_LABEL,
                "rag.context.provenance": PROVENANCE,
                "rag.content.hash": bound_hash,
                "rag.control.decision": ctx_decision.decision,
                "rag.control.reason": ctx_decision.reason,
                "rag.derived_authority": context_derived_authority,
                "follow_on.request": follow_on_request,
                "follow_on.decision": follow_on_decision,
                "follow_on.reason": follow_on_reason,
                "handler.lookup_customer_tier.count": lookup_tier_count,
                "server_owned.allowed_tools": ",".join(sorted(policy_after.allowed_tools)),
            },
            limitations_items=[
                "CTRL-RAG-CONTEXT-001 classifies retrieved context as data. OBSERVE is not ALLOW and not DENY.",
                "Retrieved documents are untrusted data (INV-002). They do not widen allowed_tools or allowed_scopes.",
                "The RAG interpreter recognizes only the closed AGENT NOTE fixture. It is not an LLM.",
                "Vulnerable retrieved-context-derived authority is a per-run overlay. coded_policy() is never mutated.",
                "CTRL-MCP-001 remains the follow-on authorization control. RAG observation does not mint AllowTicket.",
                "Full retrieved documents are not default-indexed. Telemetry stores preview + sha256 hash.",
                "Provenance rag.local.fixture is not content trust and is not authorization.",
                "No embeddings, LangChain, garak, Promptfoo, PyRIT, or NeMo Guardrails in this slice.",
                "splunk.verified=false. Splunk is not verified in this runtime slice. DET-MCP-001 is unchanged.",
                "Schema 1.6.0 has no gen_ai.tool.call.id. Correlation uses run.id + sequence.",
                "No Splunk SPL, Dashboard Studio, DET-RAG, memory poisoning, A2A, or rug-pull in this slice.",
            ],
        )
        evidence_dir = str(bundle)

    return RagRetrieveResult(
        run_id=str(ctx.run_id),
        incident_id=ctx.incident_id,
        testbed_mode=testbed_mode,
        execution_mode=EXECUTION_MODE,
        telemetry_fidelity=TELEMETRY_FIDELITY,
        profile=settings.security_profile,
        blocked=blocked,
        block_reason=block_reason,
        terminal=terminal,
        hops=hops,
        events=events,
        evidence_dir=evidence_dir,
        handler_invoke_count=handler_count,
        expected_behavior=expected,
        actual_behavior=actual,
        attack_id=attack_id,
        error_stage=error_stage,
        document_id=doc_id_for_event,
        content_hash=bound_hash,
        content_preview=bound_preview,
        context_trust=CONTEXT_TRUST_LABEL,
        context_provenance=PROVENANCE,
        context_control_decision=ctx_decision.decision,
        context_control_reason=ctx_decision.reason,
        context_derived_authority=context_derived_authority,
        follow_on_request=follow_on_request,
        follow_on_decision=follow_on_decision,
        follow_on_reason=follow_on_reason,
        lookup_customer_tier_handler_count=lookup_tier_count,
        server_owned_allowed_tools=",".join(sorted(policy_after.allowed_tools)),
    )


def run_rag_schema_failure(
    *,
    sink: EventSink,
    memory: MemorySink,
    settings: Settings,
    user_id: str,
    testbed_mode: str,
    attack_id: str = RAG_ATTACK_ID,
    error_reason: str,
    extra_fields: tuple[str, ...] = (),
    write_evidence: bool = True,
) -> RagRetrieveResult:
    ctx = RunContext.mint(
        user_id=user_id,
        testbed_mode=testbed_mode,
        attack_id=attack_id,
        workflow_entry=RAG_WORKFLOW_ENTRY,
        workflow_name=RAG_WORKFLOW_NAME,
    )
    emitter = EventEmitter(ctx, sink.emit, settings)
    emitter.run_started()
    message = error_reason
    if extra_fields:
        message = f"{error_reason}:{','.join(extra_fields)}"
    emitter.run_failed(
        error_type=error_reason,
        error_stage="schema_validation",
        error_message=message,
    )
    actual = f"schema_validation ERROR ({error_reason}); handler_invokes=0"
    events = [event for event in memory.events if event.get("agentsec.run.id") == str(ctx.run_id)]
    export_report = flush_export(sink)
    evidence_dir = None
    if write_evidence:
        bundle = write_evidence_bundle(
            run_id=str(ctx.run_id),
            incident_id=ctx.incident_id,
            settings=settings,
            events=events,
            user_input="",
            hops=[],
            testbed_mode=testbed_mode,
            attack_id=attack_id,
            expected_behavior="ERROR before RAG hop; handler never invoked",
            actual_behavior=actual,
            llm_call_count=0,
            blocked=True,
            terminal="run_failed",
            export_report=export_report,
            extra_manifest={"workflow.entry": RAG_WORKFLOW_ENTRY, "mcp.handler.invoked.count": 0},
            limitations_items=[
                "Unknown HTTP fields cannot set identity, grants, profile, or control decision.",
                "Runtime never sets splunk.verified.",
            ],
        )
        evidence_dir = str(bundle)
    return RagRetrieveResult(
        run_id=str(ctx.run_id),
        incident_id=ctx.incident_id,
        testbed_mode=testbed_mode,
        execution_mode=EXECUTION_MODE,
        telemetry_fidelity=TELEMETRY_FIDELITY,
        profile=settings.security_profile,
        blocked=True,
        block_reason=error_reason,
        terminal="run_failed",
        hops=[],
        events=events,
        evidence_dir=evidence_dir,
        handler_invoke_count=0,
        expected_behavior="ERROR before RAG hop; handler never invoked",
        actual_behavior=actual,
        attack_id=attack_id,
        error_stage="schema_validation",
    )


def rag_result_to_dict(result: RagRetrieveResult) -> dict[str, Any]:
    return {
        "run_id": result.run_id,
        "incident_id": result.incident_id,
        "testbed_mode": result.testbed_mode,
        "execution_mode": result.execution_mode,
        "telemetry_fidelity": result.telemetry_fidelity,
        "profile": result.profile,
        "blocked": result.blocked,
        "block_reason": result.block_reason,
        "terminal": result.terminal,
        "handler_invoke_count": result.handler_invoke_count,
        "expected_behavior": result.expected_behavior,
        "actual_behavior": result.actual_behavior,
        "attack_id": result.attack_id,
        "evidence_dir": result.evidence_dir,
        "schema_name": SCHEMA_NAME,
        "schema_version": SCHEMA_VERSION,
        "error_stage": result.error_stage,
        "document_id": result.document_id,
        "content_hash": result.content_hash,
        "content_preview": result.content_preview,
        "context_trust": result.context_trust,
        "context_provenance": result.context_provenance,
        "context_control_decision": result.context_control_decision,
        "context_control_reason": result.context_control_reason,
        "context_derived_authority": result.context_derived_authority,
        "follow_on_request": result.follow_on_request,
        "follow_on_decision": result.follow_on_decision,
        "follow_on_reason": result.follow_on_reason,
        "lookup_customer_tier_handler_count": result.lookup_customer_tier_handler_count,
        "server_owned_allowed_tools": result.server_owned_allowed_tools,
        "hops": [
            {
                "hop.index": hop.index,
                "agent_id": hop.agent_id,
                "control.decision": hop.control_decision,
                "control.reason": hop.control_reason,
                "operation.attempted": hop.operation_attempted,
                "operation.executed": hop.operation_executed,
                "operation.outcome": hop.operation_outcome,
                "mcp.started": hop.mcp_started,
                "mcp.completed": hop.mcp_completed,
                "mcp.failed": hop.mcp_failed,
                "handler.invoked": hop.handler_invoked,
                "tool.name": hop.tool_name,
            }
            for hop in result.hops
        ],
    }
