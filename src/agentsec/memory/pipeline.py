"""Dedicated memory write/recall path: persist data, observe at recall, then maybe request a follow-on tool."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
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
from agentsec.mcp.policy import coded_policy, policy_unchanged_by_memory
from agentsec.mcp.registry import ToolRegistry, default_registry
from agentsec.mcp.server import McpServer
from agentsec.memory.fixtures import (
    MEMORY_AGENT_ID,
    MEMORY_AGENT_NAME,
    MEMORY_ATTACK_ID,
    MEMORY_RECALL_ENTRY,
    MEMORY_TRUST_LABEL,
    MEMORY_WORKFLOW_NAME,
    MEMORY_WRITE_ENTRY,
    PROVENANCE,
)
from agentsec.memory.store import InProcessMemoryStore, MemoryError, MemoryRecord
from agentsec.memory.trust import (
    MEMORY_CONTEXT_IS_DATA_REASON,
    MEMORY_CONTROL_ID,
    MEMORY_CONTROL_TYPE,
    MEMORY_FAIL_OPEN_REASON,
    MemoryDerivedOverlay,
    MemoryTrustDecision,
    evaluate_memory_trust_safe,
    interpret_recalled_content,
)
from agentsec.settings import Settings, get_settings
from agentsec.telemetry import EventSink, MemorySink, flush_export

AuthorizeFn = Callable[..., McpControlResult]


@dataclass
class MemoryWriteResult:
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
    expected_behavior: str
    actual_behavior: str
    attack_id: str
    memory_id: str | None = None
    content_hash: str | None = None
    content_preview: str | None = None
    memory_provenance: str | None = None
    writer_agent_id: str | None = None
    source_run_id: str | None = None
    error_stage: str | None = None


@dataclass
class MemoryRecallResult:
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
    memory_id: str | None = None
    content_hash: str | None = None
    content_preview: str | None = None
    memory_trust: str | None = None
    memory_provenance: str | None = None
    source_run_id: str | None = None
    writer_agent_id: str | None = None
    memory_control_decision: str | None = None
    memory_control_reason: str | None = None
    memory_derived_authority: bool = False
    overlay_run_id: str | None = None
    follow_on_request: dict[str, Any] | None = None
    follow_on_decision: str | None = None
    follow_on_reason: str | None = None
    lookup_customer_tier_handler_count: int = 0
    server_owned_allowed_tools: str = "lookup_policy"
    recalled_snapshot: MemoryRecord | None = None


def _duration_ms(started: float) -> int:
    return max(0, int((time.monotonic() - started) * 1000))


def _memory_invariants(decision: str) -> list[str]:
    if decision == "ERROR":
        return ["INV-003", "INV-008", "INV-007"]
    return ["INV-003", "INV-002", "INV-007", "INV-008"]


def _expected_write(decision: str | None) -> str:
    if decision == "ERROR":
        return "ERROR before persist; memory is not a grant; no follow-on"
    return "memory write succeeds; no follow-on; persistence is not trust"


def _expected_recall(profile: str, memory_decision: str | None, follow_on: str | None) -> str:
    if memory_decision == "ERROR":
        return "ERROR before follow-on; recalled memory is not a grant; handler 0"
    if profile == "vulnerable" and follow_on == "ALLOW":
        return (
            "CTRL-MEMORY-CONTEXT-001 OBSERVE memory_context_is_data; "
            f"follow-on lookup_customer_tier ALLOW {MEMORY_FAIL_OPEN_REASON}; handler 1"
        )
    if follow_on == "DENY":
        return (
            "CTRL-MEMORY-CONTEXT-001 OBSERVE memory_context_is_data; "
            "follow-on DENY tool_not_granted; follow-on handler 0"
        )
    return (
        "CTRL-MEMORY-CONTEXT-001 OBSERVE memory_context_is_data; "
        "no memory-derived authority; no follow-on"
    )


def run_memory_write(
    *,
    memory_id: str,
    store: InProcessMemoryStore,
    sink: EventSink,
    memory: MemorySink,
    settings: Settings | None = None,
    user_id: str = "applicant-web",
    testbed_mode: str,
    attack_id: str = MEMORY_ATTACK_ID,
    write_evidence: bool = True,
    write_obj: object | None = None,
) -> MemoryWriteResult:
    settings = settings or get_settings()
    started = time.monotonic()
    ctx = RunContext.mint(
        user_id=user_id,
        testbed_mode=testbed_mode,
        attack_id=attack_id,
        workflow_entry=MEMORY_WRITE_ENTRY,
        workflow_name=MEMORY_WORKFLOW_NAME,
    )
    emitter = EventEmitter(ctx, sink.emit, settings)
    emitter.run_started()
    hop_started_at = time.monotonic()
    hop_span_id = new_span_id()
    emitter.hop_started(
        hop_index=0,
        agent_id=MEMORY_AGENT_ID,
        agent_name=MEMORY_AGENT_NAME,
        hop_span_id=hop_span_id,
        delegator_agent_id=None,
    )

    record: MemoryRecord | None = None
    write_error: MemoryError | None = None
    try:
        if write_obj is not None:
            record, write_error = store.write(
                write_obj,
                writer_agent_id=MEMORY_AGENT_ID,
                source_run_id=str(ctx.run_id),
            )
        else:
            record, write_error = store.write_fixture(
                memory_id,
                writer_agent_id=MEMORY_AGENT_ID,
                source_run_id=str(ctx.run_id),
            )
    except Exception:
        record = None
        write_error = MemoryError(
            reason="write_failure",
            error_stage="pipeline",
            requested_id=memory_id if isinstance(memory_id, str) and memory_id else "unknown",
        )

    hops: list[McpHop] = []
    blocked = False
    block_reason = None
    error_stage = write_error.error_stage if write_error is not None else None
    bound_hash = None
    bound_preview = None
    provenance = None
    writer = None
    source_run_id = None
    stored_id = memory_id if isinstance(memory_id, str) and memory_id else "unknown"

    if write_error is not None or record is None:
        blocked = True
        block_reason = write_error.reason if write_error is not None else "malformed_memory_write"
        error_stage = write_error.error_stage if write_error is not None else "schema_validation"
        stored_id = write_error.requested_id if write_error is not None else stored_id
        hop_outcome = "hop_error"
        emitter.pipeline_stopped(
            hop_index=0,
            agent_id=MEMORY_AGENT_ID,
            stop_reason="error",
            delegator_agent_id=None,
        )
    else:
        stored_id = record.memory_id
        bound_hash = record.content_hash
        bound_preview = content_preview(record.content)
        provenance = record.provenance
        writer = record.writer_agent_id
        source_run_id = record.source_run_id
        hop_outcome = "hop_allowed"
        emitter.memory_written(
            hop_index=0,
            agent_id=MEMORY_AGENT_ID,
            agent_name=MEMORY_AGENT_NAME,
            hop_span_id=hop_span_id,
            memory_id=record.memory_id,
            provenance=record.provenance,
            source_run_id=record.source_run_id,
            content_text=record.content,
            writer_agent_id=record.writer_agent_id,
        )

    hops.append(
        McpHop(
            index=0,
            agent_id=MEMORY_AGENT_ID,
            agent_name=MEMORY_AGENT_NAME,
            control_decision="ERROR" if blocked else "OBSERVE",
            control_reason=block_reason or "memory_write_persisted",
            operation_attempted=False,
            operation_executed=False,
            operation_outcome="prevented" if blocked else None,
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
        agent_id=MEMORY_AGENT_ID,
        agent_name=MEMORY_AGENT_NAME,
        hop_span_id=hop_span_id,
        outcome=hop_outcome,
        duration_ms=_duration_ms(hop_started_at),
        delegator_agent_id=None,
    )

    if blocked:
        terminal = "run_failed"
        stage = error_stage or "pipeline"
        emitter.run_failed(
            error_type=block_reason or "memory_write_error",
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
            error_message=block_reason or "Memory write stopped with error",
        )
        actual = f"ERROR {block_reason}; handler_invokes=0"
    else:
        terminal = "completed_allowed"
        emitter.run_completed(outcome="completed_allowed", duration_ms=_duration_ms(started))
        actual = "memory write succeeds; handler_invokes=0"

    expected = _expected_write("ERROR" if blocked else "OK")
    events = [event for event in memory.events if event.get("agentsec.run.id") == str(ctx.run_id)]
    export_report = flush_export(sink)
    evidence_dir = None
    if write_evidence:
        bundle = write_evidence_bundle(
            run_id=str(ctx.run_id),
            incident_id=ctx.incident_id,
            settings=settings,
            events=events,
            user_input=stored_id,
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
                "workflow.entry": MEMORY_WRITE_ENTRY,
                "memory.write.run.id": str(ctx.run_id),
                "memory.id": stored_id,
                "memory.content.hash": bound_hash,
                "memory.content.preview": bound_preview,
                "memory.provenance": provenance,
                "memory.writer.agent.id": writer,
                "memory.source_run_id": source_run_id,
                "mcp.handler.lookup_customer_tier.count": 0,
                "splunk.verified": False,
            },
            request_doc={"memory_id": stored_id, "memory.id.hash": content_hash(stored_id)},
            extra_result={
                "memory.id": stored_id,
                "memory.content.hash": bound_hash,
                "memory.provenance": provenance,
                "memory.source_run_id": source_run_id,
                "handler.lookup_customer_tier.count": 0,
            },
            limitations_items=_memory_limitations(),
        )
        evidence_dir = str(bundle)

    return MemoryWriteResult(
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
        expected_behavior=expected,
        actual_behavior=actual,
        attack_id=attack_id,
        memory_id=stored_id,
        content_hash=bound_hash,
        content_preview=bound_preview,
        memory_provenance=provenance,
        writer_agent_id=writer,
        source_run_id=source_run_id,
        error_stage=error_stage,
    )


def run_memory_recall(
    *,
    memory_id: str,
    store: InProcessMemoryStore,
    sink: EventSink,
    memory: MemorySink,
    settings: Settings | None = None,
    user_id: str = "applicant-web",
    testbed_mode: str,
    attack_id: str = MEMORY_ATTACK_ID,
    write_evidence: bool = True,
    registry: ToolRegistry | None = None,
    authorize_fn: AuthorizeFn | None = None,
    recalled_override: object | None = None,
    expected_behavior: str | None = None,
) -> MemoryRecallResult:
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
        workflow_entry=MEMORY_RECALL_ENTRY,
        workflow_name=MEMORY_WORKFLOW_NAME,
    )
    emitter = EventEmitter(ctx, sink.emit, settings)
    emitter.run_started()

    hop_started_at = time.monotonic()
    hop_span_id = new_span_id()
    emitter.hop_started(
        hop_index=0,
        agent_id=MEMORY_AGENT_ID,
        agent_name=MEMORY_AGENT_NAME,
        hop_span_id=hop_span_id,
        delegator_agent_id=None,
    )

    recalled: MemoryRecord | None = None
    recall_error: MemoryError | None = None
    try:
        if recalled_override is not None:
            if isinstance(recalled_override, MemoryRecord):
                recalled, recall_error = recalled_override, None
            else:
                recalled, recall_error = None, MemoryError(
                    reason="malformed_memory_object",
                    requested_id=memory_id if isinstance(memory_id, str) and memory_id else "unknown",
                )
        else:
            recalled, recall_error = store.recall(memory_id)
    except Exception:
        recalled = None
        recall_error = MemoryError(
            reason="recall_failure",
            error_stage="pipeline",
            requested_id=memory_id if isinstance(memory_id, str) and memory_id else "unknown",
        )

    snapshot = recalled
    fingerprint_source = snapshot.content if snapshot is not None else (
        recall_error.reason if recall_error is not None else "malformed_memory_object"
    )
    memory_id_for_event = (
        snapshot.memory_id
        if snapshot is not None
        else (recall_error.requested_id if recall_error is not None else memory_id or "unknown")
    )
    bound_hash = content_hash(fingerprint_source) if snapshot is not None else content_hash(fingerprint_source)
    bound_preview = content_preview(fingerprint_source)
    source_run_id = snapshot.source_run_id if snapshot is not None else None
    writer = snapshot.writer_agent_id if snapshot is not None else None
    provenance = snapshot.provenance if snapshot is not None else PROVENANCE

    try:
        mem_decision, follow_intent, overlay = evaluate_memory_trust_safe(
            profile=settings.security_profile,
            recalled=snapshot,
            recall_error=recall_error,
            run_id=str(ctx.run_id),
        )
    except Exception as exc:
        mem_decision = MemoryTrustDecision(
            control_id=MEMORY_CONTROL_ID,
            control_type=MEMORY_CONTROL_TYPE,
            decision="ERROR",
            reason=f"control_evaluation_failure:{type(exc).__name__}",
            profile=settings.security_profile,
            memory_id=memory_id_for_event,
            overlay_applied=False,
            error_stage="control_evaluation",
        )
        follow_intent = None
        overlay = None

    if snapshot is not None:
        check_intent = interpret_recalled_content(snapshot.content, memory_id=snapshot.memory_id)
        if (check_intent is None) != (follow_intent is None):
            mem_decision = MemoryTrustDecision(
                control_id=MEMORY_CONTROL_ID,
                control_type=MEMORY_CONTROL_TYPE,
                decision="ERROR",
                reason="control_evaluation_failure:check_use_mismatch",
                profile=settings.security_profile,
                memory_id=snapshot.memory_id,
                overlay_applied=False,
                error_stage="control_evaluation",
            )
            follow_intent = None
            overlay = None
        elif check_intent is not None and follow_intent is not None:
            if (
                check_intent.tool_name != follow_intent.tool_name
                or check_intent.requested_scope != follow_intent.requested_scope
            ):
                mem_decision = MemoryTrustDecision(
                    control_id=MEMORY_CONTROL_ID,
                    control_type=MEMORY_CONTROL_TYPE,
                    decision="ERROR",
                    reason="control_evaluation_failure:check_use_mismatch",
                    profile=settings.security_profile,
                    memory_id=snapshot.memory_id,
                    overlay_applied=False,
                    error_stage="control_evaluation",
                )
                follow_intent = None
                overlay = None

    if overlay is not None and overlay.run_id != str(ctx.run_id):
        mem_decision = MemoryTrustDecision(
            control_id=MEMORY_CONTROL_ID,
            control_type=MEMORY_CONTROL_TYPE,
            decision="ERROR",
            reason="control_evaluation_failure:overlay_run_mismatch",
            profile=settings.security_profile,
            memory_id=memory_id_for_event,
            overlay_applied=False,
            error_stage="control_evaluation",
        )
        follow_intent = None
        overlay = None

    if snapshot is not None and mem_decision.decision != "ERROR":
        emitter.memory_recalled(
            hop_index=0,
            agent_id=MEMORY_AGENT_ID,
            agent_name=MEMORY_AGENT_NAME,
            hop_span_id=hop_span_id,
            memory_id=snapshot.memory_id,
            provenance=snapshot.provenance,
            trust=MEMORY_TRUST_LABEL,
            source_run_id=snapshot.source_run_id,
            content_text=snapshot.content,
            reader_agent_id=MEMORY_AGENT_ID,
        )

    emitter.control_decision(
        hop_index=0,
        agent_id=MEMORY_AGENT_ID,
        agent_name=MEMORY_AGENT_NAME,
        hop_span_id=hop_span_id,
        control_id=MEMORY_CONTROL_ID,
        control_type=MEMORY_CONTROL_TYPE,
        decision=mem_decision.decision,
        reason=mem_decision.reason,
        trust_boundary="agent.memory.store",
        invariant_ids=_memory_invariants(mem_decision.decision),
        content_text=fingerprint_source,
        origin_type="agent",
        origin_id=MEMORY_AGENT_ID,
        influence_kind="recalled_memory",
        delegator_agent_id=None,
        error_stage=mem_decision.error_stage,
        memory_id=memory_id_for_event,
        memory_trust=MEMORY_TRUST_LABEL,
        memory_provenance=provenance,
        memory_source_run_id=source_run_id,
    )

    hops: list[McpHop] = []
    blocked = False
    block_reason = None
    error_stage = mem_decision.error_stage
    hop_outcome = "hop_allowed"
    counts_before = registry.invoke_total
    counts_before_by_tool = dict(registry.invoke_counts)
    memory_derived_authority = bool(
        overlay is not None and mem_decision.overlay_applied and overlay.run_id == str(ctx.run_id)
    )
    follow_on_decision = None
    follow_on_reason = None
    follow_on_request = None

    if mem_decision.decision == "ERROR":
        blocked = True
        block_reason = mem_decision.reason
        hop_outcome = "hop_error"
        emitter.pipeline_stopped(
            hop_index=0,
            agent_id=MEMORY_AGENT_ID,
            stop_reason="error",
            delegator_agent_id=None,
        )
    elif overlay is not None and memory_derived_authority:
        server.memory_derived_overlay = overlay

    hops.append(
        McpHop(
            index=0,
            agent_id=MEMORY_AGENT_ID,
            agent_name=MEMORY_AGENT_NAME,
            control_decision=mem_decision.decision,
            control_reason=mem_decision.reason,
            operation_attempted=False,
            operation_executed=False,
            operation_outcome="prevented" if mem_decision.decision == "ERROR" else None,
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
        agent_id=MEMORY_AGENT_ID,
        agent_name=MEMORY_AGENT_NAME,
        hop_span_id=hop_span_id,
        outcome=hop_outcome,
        duration_ms=_duration_ms(hop_started_at),
        delegator_agent_id=None,
    )

    if mem_decision.decision != "ERROR" and follow_intent is not None:
        follow_on_request = {
            "tool": follow_intent.tool_name,
            "requested_scope": follow_intent.requested_scope,
            "arguments": dict(follow_intent.arguments),
        }
        bound_overlay = overlay if memory_derived_authority else None
        follow_hop = _run_follow_on_tool(
            server=server,
            client=client,
            emitter=emitter,
            registry=registry,
            settings=settings,
            user_id=user_id,
            overlay=bound_overlay,
            counts_before_by_tool=counts_before_by_tool,
            agent_id=MEMORY_AGENT_ID,
            agent_name=MEMORY_AGENT_NAME,
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
            error_type=block_reason or "memory_error",
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
            error_message=block_reason or "Memory recall stopped with error",
        )
        actual = f"ERROR {mem_decision.reason}; handler_invokes={registry.invoke_total - counts_before}"
    else:
        terminal = "completed_allowed"
        emitter.run_completed(outcome="completed_allowed", duration_ms=_duration_ms(started))
        actual = (
            f"OBSERVE memory_context_is_data; "
            f"handler_invokes={registry.invoke_total - counts_before}"
        )

    handler_count = registry.invoke_total - counts_before
    lookup_tier_count = registry.invoke_counts.get("lookup_customer_tier", 0) - counts_before_by_tool.get(
        "lookup_customer_tier", 0
    )
    policy_after = coded_policy()
    if policy_after.allowed_tools != policy_before.allowed_tools:
        raise RuntimeError("memory blocker: coded allowed_tools mutated")
    if policy_after.allowed_scopes != policy_before.allowed_scopes:
        raise RuntimeError("memory blocker: coded allowed_scopes mutated")
    if policy_after.allowed_policy_ids != policy_before.allowed_policy_ids:
        raise RuntimeError("memory blocker: coded allowed_policy_ids mutated")
    if policy_after.agent_id != policy_before.agent_id:
        raise RuntimeError("memory blocker: coded agent identity mutated")
    policy_unchanged_by_memory(policy_after, snapshot.content if snapshot else None)
    expected = expected_behavior or _expected_recall(
        settings.security_profile, mem_decision.decision, follow_on_decision
    )
    events = [event for event in memory.events if event.get("agentsec.run.id") == str(ctx.run_id)]
    export_report = flush_export(sink)
    evidence_dir = None
    if write_evidence:
        request_doc = {
            "memory_id": memory_id,
            "memory.id.hash": content_hash(memory_id),
        }
        bundle = write_evidence_bundle(
            run_id=str(ctx.run_id),
            incident_id=ctx.incident_id,
            settings=settings,
            events=events,
            user_input=memory_id,
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
                "workflow.entry": MEMORY_RECALL_ENTRY,
                "memory.write.run.id": source_run_id,
                "memory.recall.run.id": str(ctx.run_id),
                "mcp.handler.invoked.count": handler_count,
                "mcp.handler.lookup_customer_tier.count": lookup_tier_count,
                "memory.id": memory_id_for_event,
                "memory.trust": MEMORY_TRUST_LABEL,
                "memory.provenance": provenance,
                "memory.content.hash": bound_hash,
                "memory.content.preview": bound_preview,
                "memory.source_run_id": source_run_id,
                "memory.writer.agent.id": writer,
                "memory.control.decision": mem_decision.decision,
                "memory.control.reason": mem_decision.reason,
                "memory.derived_authority": memory_derived_authority,
                "follow_on.request": follow_on_request,
                "follow_on.decision": follow_on_decision,
                "follow_on.reason": follow_on_reason,
                "authority.source": (
                    "memory-derived overlay" if memory_derived_authority else "server-owned"
                ),
                "server_owned.allowed_tools": ",".join(sorted(policy_after.allowed_tools)),
                "splunk.verified": False,
            },
            request_doc=request_doc,
            extra_result={
                "memory.id": memory_id_for_event,
                "memory.trust": MEMORY_TRUST_LABEL,
                "memory.provenance": provenance,
                "memory.content.hash": bound_hash,
                "memory.source_run_id": source_run_id,
                "memory.control.decision": mem_decision.decision,
                "memory.control.reason": mem_decision.reason,
                "memory.derived_authority": memory_derived_authority,
                "follow_on.request": follow_on_request,
                "follow_on.decision": follow_on_decision,
                "follow_on.reason": follow_on_reason,
                "handler.lookup_customer_tier.count": lookup_tier_count,
                "server_owned.allowed_tools": ",".join(sorted(policy_after.allowed_tools)),
            },
            limitations_items=_memory_limitations(),
        )
        evidence_dir = str(bundle)

    return MemoryRecallResult(
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
        memory_id=memory_id_for_event,
        content_hash=bound_hash,
        content_preview=bound_preview,
        memory_trust=MEMORY_TRUST_LABEL,
        memory_provenance=provenance,
        source_run_id=source_run_id,
        writer_agent_id=writer,
        memory_control_decision=mem_decision.decision,
        memory_control_reason=mem_decision.reason,
        memory_derived_authority=memory_derived_authority,
        overlay_run_id=overlay.run_id if overlay is not None and memory_derived_authority else None,
        follow_on_request=follow_on_request,
        follow_on_decision=follow_on_decision,
        follow_on_reason=follow_on_reason,
        lookup_customer_tier_handler_count=lookup_tier_count,
        server_owned_allowed_tools=",".join(sorted(policy_after.allowed_tools)),
        recalled_snapshot=snapshot,
    )


def run_memory_schema_failure(
    *,
    sink: EventSink,
    memory: MemorySink,
    settings: Settings,
    user_id: str,
    testbed_mode: str,
    workflow_entry: str,
    attack_id: str = MEMORY_ATTACK_ID,
    error_reason: str,
    extra_fields: tuple[str, ...] = (),
    write_evidence: bool = True,
) -> MemoryWriteResult:
    ctx = RunContext.mint(
        user_id=user_id,
        testbed_mode=testbed_mode,
        attack_id=attack_id,
        workflow_entry=workflow_entry,
        workflow_name=MEMORY_WORKFLOW_NAME,
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
            expected_behavior="ERROR before memory hop; handler never invoked",
            actual_behavior=actual,
            llm_call_count=0,
            blocked=True,
            terminal="run_failed",
            export_report=export_report,
            extra_manifest={"workflow.entry": workflow_entry, "mcp.handler.invoked.count": 0, "splunk.verified": False},
            limitations_items=[
                "Unknown HTTP fields cannot set identity, grants, profile, or control decision.",
                "Runtime never sets splunk.verified.",
            ],
        )
        evidence_dir = str(bundle)
    return MemoryWriteResult(
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
        expected_behavior="ERROR before memory hop; handler never invoked",
        actual_behavior=actual,
        attack_id=attack_id,
        error_stage="schema_validation",
    )


def write_memory_specimen_pack(
    *,
    label: str,
    write: MemoryWriteResult,
    recall: MemoryRecallResult,
    settings: Settings,
) -> Path:
    root = settings.artifacts_dir / f"lab-memory-001-{label}-{recall.run_id}"
    root.mkdir(parents=True, exist_ok=True)
    combined = list(write.events) + list(recall.events)
    events_path = root / "events.jsonl"
    with events_path.open("w", encoding="utf-8") as handle:
        for event in combined:
            handle.write(json.dumps(event, separators=(",", ":")) + "\n")
    manifest = {
        "schema.name": SCHEMA_NAME,
        "schema.version": SCHEMA_VERSION,
        "lab.id": settings.lab_id,
        "attack.id": MEMORY_ATTACK_ID,
        "label": label,
        "memory.write.run.id": write.run_id,
        "memory.recall.run.id": recall.run_id,
        "memory.id": recall.memory_id,
        "memory.content.hash": recall.content_hash,
        "memory.provenance": recall.memory_provenance,
        "memory.trust": recall.memory_trust,
        "write.profile": write.profile,
        "recall.profile": recall.profile,
        "write.mode": write.testbed_mode,
        "recall.mode": recall.testbed_mode,
        "follow_on.request": recall.follow_on_request,
        "follow_on.decision": recall.follow_on_decision,
        "follow_on.reason": recall.follow_on_reason,
        "mcp.handler.lookup_customer_tier.count": recall.lookup_customer_tier_handler_count,
        "splunk.verified": False,
        "write.evidence_dir": write.evidence_dir,
        "recall.evidence_dir": recall.evidence_dir,
    }
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    export_doc = {
        "otlp.attempted": False,
        "otlp.ok": False,
        "splunk.verified": False,
        "note": "Phase 11B local validation only. Splunk ingest is Phase 11C.",
    }
    (root / "export.json").write_text(json.dumps(export_doc, indent=2) + "\n", encoding="utf-8")
    (root / "limitations.json").write_text(
        json.dumps({"items": _memory_limitations()}, indent=2) + "\n", encoding="utf-8"
    )
    (root / "request.json").write_text(
        json.dumps(
            {
                "write.memory_id": write.memory_id,
                "recall.memory_id": recall.memory_id,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (root / "result.json").write_text(
        json.dumps(
            {
                "write.run.id": write.run_id,
                "recall.run.id": recall.run_id,
                "memory.content.hash": recall.content_hash,
                "follow_on": recall.follow_on_request,
                "follow_on.decision": recall.follow_on_decision,
                "handler.lookup_customer_tier.count": recall.lookup_customer_tier_handler_count,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return root


def memory_write_result_to_dict(result: MemoryWriteResult) -> dict[str, Any]:
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
        "expected_behavior": result.expected_behavior,
        "actual_behavior": result.actual_behavior,
        "attack_id": result.attack_id,
        "evidence_dir": result.evidence_dir,
        "schema_name": SCHEMA_NAME,
        "schema_version": SCHEMA_VERSION,
        "error_stage": result.error_stage,
        "memory_id": result.memory_id,
        "content_hash": result.content_hash,
        "content_preview": result.content_preview,
        "memory_provenance": result.memory_provenance,
        "source_run_id": result.source_run_id,
        "lookup_customer_tier_handler_count": 0,
    }


def memory_recall_result_to_dict(result: MemoryRecallResult) -> dict[str, Any]:
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
        "memory_id": result.memory_id,
        "content_hash": result.content_hash,
        "content_preview": result.content_preview,
        "memory_trust": result.memory_trust,
        "memory_provenance": result.memory_provenance,
        "source_run_id": result.source_run_id,
        "memory_control_decision": result.memory_control_decision,
        "memory_control_reason": result.memory_control_reason,
        "memory_derived_authority": result.memory_derived_authority,
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


def _memory_limitations() -> list[str]:
    return [
        "CTRL-MEMORY-CONTEXT-001 classifies recalled memory as data. OBSERVE is not ALLOW and not DENY.",
        "Persisted memory is untrusted data (INV-003). It does not widen allowed_tools or allowed_scopes.",
        "The memory interpreter recognizes only the closed AGENT MEMORY NOTE fixture. It is not an LLM.",
        "Vulnerable memory-derived authority is a per-recall-run overlay. coded_policy() is never mutated.",
        "CTRL-MCP-001 remains the follow-on authorization control. Memory observation does not mint AllowTicket.",
        "Full memory bodies are not default-indexed. Telemetry stores preview + sha256 hash.",
        "Provenance agentsec.memory.fixture is not content trust and is not authorization.",
        "No embeddings, LangChain, LangGraph, vector database, or Agent Memory Guard in this slice.",
        "splunk.verified=false. Splunk is not verified in this runtime slice. DET-MCP-001 is unchanged.",
        "Schema 1.7.0 has no session.id. Correlation uses memory.id + content.hash + source_run_id + run.id.",
        "No Splunk SPL, Dashboard Studio, DET-MEMORY, A2A, identity/delegation, or rug-pull in this slice.",
    ]
