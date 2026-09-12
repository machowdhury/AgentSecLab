"""Dedicated MCP invoke path: authorize on the server, then maybe execute the handler."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Callable

from agentsec.events import EventEmitter, RunContext, content_hash, content_preview, new_span_id
from agentsec.experiment import (
    EXECUTION_MODE,
    MCP_WORKFLOW_ENTRY,
    MCP_WORKFLOW_NAME,
    SCHEMA_NAME,
    SCHEMA_VERSION,
    TELEMETRY_FIDELITY,
)
from agentsec.evidence import write_evidence_bundle
from agentsec.mcp.authorize import McpControlResult
from agentsec.mcp.client import McpClient
from agentsec.mcp.policy import MCP_AGENT_ID, MCP_AGENT_NAME, coded_policy
from agentsec.mcp.registry import ToolRegistry, default_registry
from agentsec.mcp.server import McpServer
from agentsec.settings import Settings, get_settings
from agentsec.telemetry import EventSink, MemorySink, flush_export

AuthorizeFn = Callable[..., McpControlResult]


@dataclass
class McpHop:
    index: int
    agent_id: str
    agent_name: str
    control_decision: str
    control_reason: str
    operation_attempted: bool
    operation_executed: bool
    operation_outcome: str | None
    llm_started: bool
    llm_completed: bool
    llm_failed: bool
    mcp_started: bool
    mcp_completed: bool
    mcp_failed: bool
    span_id: str
    delegator_agent_id: str | None
    handler_invoked: bool
    tool_name: str
    response: dict[str, Any] | None = None
    mcp_error: str | None = None


@dataclass
class McpInvokeResult:
    run_id: str
    incident_id: str
    testbed_mode: str
    execution_mode: str
    telemetry_fidelity: str
    profile: str
    blocked: bool
    block_reason: str | None
    terminal: str
    final_output: dict[str, Any] | None
    hops: list[McpHop]
    events: list[dict]
    evidence_dir: str | None
    handler_invoke_count: int
    expected_behavior: str
    actual_behavior: str
    attack_id: str
    error_stage: str | None = None
    result_trust: str = "untrusted_data"
    result_provenance: str = "mcp.tool.handler"


def _duration_ms(started: float) -> int:
    return max(0, int((time.monotonic() - started) * 1000))


def _invariants(decision: str) -> list[str]:
    if decision == "DENY":
        return ["INV-001", "INV-008", "INV-007"]
    if decision == "ERROR":
        return ["INV-008", "INV-007"]
    return ["INV-001", "INV-004", "INV-007"]


def _expected(attack_id: str, profile: str, decision: str | None = None) -> str:
    if attack_id == "MCP-001":
        return "ALLOW lookup_policy; handler executes; result is untrusted data"
    if attack_id == "MCP-002" and profile == "defended":
        return "DENY lookup_customer_tier; attempted=false, executed=false, outcome=prevented; handler does not begin"
    if attack_id == "MCP-002" and profile == "vulnerable":
        return "labeled ALLOW fail-open for known ungranted tool; handler executes"
    if decision == "ERROR":
        return "ERROR before handler; executed=false"
    return "MCP invoke"


def run_mcp_invoke(
    *,
    tool: str,
    arguments: dict[str, Any],
    requested_scope: str,
    sink: EventSink,
    memory: MemorySink,
    settings: Settings | None = None,
    user_id: str = "applicant-web",
    testbed_mode: str,
    attack_id: str,
    write_evidence: bool = True,
    registry: ToolRegistry | None = None,
    authorize_fn: AuthorizeFn | None = None,
    expected_behavior: str | None = None,
) -> McpInvokeResult:
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
        workflow_entry=MCP_WORKFLOW_ENTRY,
        workflow_name=MCP_WORKFLOW_NAME,
    )
    emitter = EventEmitter(ctx, sink.emit, settings)
    emitter.run_started()

    hop_started_at = time.monotonic()
    hop_span_id = new_span_id()
    emitter.hop_started(
        hop_index=0,
        agent_id=MCP_AGENT_ID,
        agent_name=MCP_AGENT_NAME,
        hop_span_id=hop_span_id,
        delegator_agent_id=None,
    )

    rpc = client.tools_call(name=tool, arguments=arguments)
    decision = server.authorize(
        rpc,
        profile=settings.security_profile,
        requested_scope=requested_scope,
        coded_agent_id=MCP_AGENT_ID,
    )
    control = decision.control
    content = json.dumps({"tool": tool, "arguments": arguments, "requested_scope": requested_scope}, sort_keys=True)
    emitter.control_decision(
        hop_index=0,
        agent_id=MCP_AGENT_ID,
        agent_name=MCP_AGENT_NAME,
        hop_span_id=hop_span_id,
        control_id=control.control_id,
        control_type=control.control_type,
        decision=control.decision,
        reason=control.reason,
        trust_boundary="acmebank.mcp.authorize",
        invariant_ids=_invariants(control.decision),
        content_text=content,
        origin_type="user",
        origin_id=user_id,
        influence_kind="tool_request",
        delegator_agent_id=None,
        error_stage=control.error_stage,
        tool_name=control.tool_name,
        mcp_method="tools/call",
        requested_scope=control.requested_scope,
        allowed_scope=control.allowed_scope,
    )

    mcp_started = False
    mcp_completed = False
    mcp_failed = False
    attempted = False
    executed = False
    outcome: str | None = None
    payload: dict[str, Any] | None = None
    mcp_error = None
    hop_outcome = "hop_allowed"
    blocked = False
    block_reason = None
    error_stage = control.error_stage
    counts_before = registry.invoke_total

    if control.blocks_tool:
        blocked = True
        block_reason = control.reason
        outcome = "prevented"
        hop_outcome = "hop_denied" if control.decision == "DENY" else "hop_error"
        emitter.pipeline_stopped(
            hop_index=0,
            agent_id=MCP_AGENT_ID,
            stop_reason="denied" if control.decision == "DENY" else "error",
            delegator_agent_id=None,
        )
    else:
        mcp_span_id = new_span_id()
        exec_started = time.monotonic()
        emitter.mcp_started(
            hop_index=0,
            agent_id=MCP_AGENT_ID,
            agent_name=MCP_AGENT_NAME,
            hop_span_id=hop_span_id,
            mcp_span_id=mcp_span_id,
            tool_name=decision.tool_name,
            delegator_agent_id=None,
        )
        mcp_started = True
        attempted = True
        executed = True
        execution = server.execute(decision.ticket)
        if not execution.ok:
            blocked = True
            block_reason = execution.error_type or "mcp_error"
            mcp_error = execution.error_type
            mcp_failed = True
            outcome = "error"
            hop_outcome = "hop_error"
            error_stage = "mcp_invocation"
            emitter.mcp_failed(
                hop_index=0,
                agent_id=MCP_AGENT_ID,
                agent_name=MCP_AGENT_NAME,
                hop_span_id=hop_span_id,
                mcp_span_id=mcp_span_id,
                tool_name=decision.tool_name,
                error_type=execution.error_type or "mcp_error",
                error_message=execution.error_message or execution.error_type or "mcp_error",
                delegator_agent_id=None,
            )
            emitter.pipeline_stopped(
                hop_index=0,
                agent_id=MCP_AGENT_ID,
                stop_reason="error",
                delegator_agent_id=None,
            )
        else:
            mcp_completed = True
            outcome = "success"
            payload = execution.payload
            result_text = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            emitter.mcp_completed(
                hop_index=0,
                agent_id=MCP_AGENT_ID,
                agent_name=MCP_AGENT_NAME,
                hop_span_id=hop_span_id,
                mcp_span_id=mcp_span_id,
                tool_name=decision.tool_name,
                duration_ms=_duration_ms(exec_started),
                result_text=result_text,
                delegator_agent_id=None,
            )

    hop = McpHop(
        index=0,
        agent_id=MCP_AGENT_ID,
        agent_name=MCP_AGENT_NAME,
        control_decision=control.decision,
        control_reason=control.reason,
        operation_attempted=attempted,
        operation_executed=executed,
        operation_outcome=outcome,
        llm_started=False,
        llm_completed=False,
        llm_failed=False,
        mcp_started=mcp_started,
        mcp_completed=mcp_completed,
        mcp_failed=mcp_failed,
        span_id=hop_span_id,
        delegator_agent_id=None,
        handler_invoked=registry.invoke_total > counts_before,
        tool_name=decision.tool_name or tool,
        response=payload,
        mcp_error=mcp_error,
    )
    emitter.hop_completed(
        hop_index=0,
        agent_id=MCP_AGENT_ID,
        agent_name=MCP_AGENT_NAME,
        hop_span_id=hop_span_id,
        outcome=hop_outcome,
        duration_ms=_duration_ms(hop_started_at),
        delegator_agent_id=None,
    )

    if blocked and control.decision == "DENY":
        terminal = "completed_denied"
        emitter.run_completed(outcome="completed_denied", duration_ms=_duration_ms(started))
        actual = f"DENY {hop.tool_name}; handler_invokes={registry.invoke_total - counts_before}"
    elif blocked:
        terminal = "run_failed"
        stage = error_stage or "pipeline"
        emitter.run_failed(
            error_type=block_reason or "mcp_error",
            error_stage=stage if stage in {
                "schema_validation",
                "control_evaluation",
                "argument_validation",
                "llm_invocation",
                "mcp_invocation",
                "telemetry_export",
                "pipeline",
            } else "pipeline",
            error_message=block_reason or "MCP invoke stopped with error",
        )
        actual = f"ERROR {hop.tool_name}; handler_invokes={registry.invoke_total - counts_before}"
    else:
        terminal = "completed_allowed"
        emitter.run_completed(outcome="completed_allowed", duration_ms=_duration_ms(started))
        actual = f"ALLOW {hop.tool_name}; handler_invokes={registry.invoke_total - counts_before}"

    handler_count = registry.invoke_total - counts_before
    expected = expected_behavior or _expected(attack_id, settings.security_profile, control.decision)
    events = [event for event in memory.events if event.get("agentsec.run.id") == str(ctx.run_id)]
    export_report = flush_export(sink)
    evidence_dir = None
    if write_evidence:
        request_doc = {
            "tool": tool,
            "requested_scope": requested_scope,
            "arguments.hash": content_hash(content),
            "arguments.preview": content_preview(content),
        }
        bundle = write_evidence_bundle(
            run_id=str(ctx.run_id),
            incident_id=ctx.incident_id,
            settings=settings,
            events=events,
            user_input=content,
            hops=[hop],
            testbed_mode=testbed_mode,
            attack_id=attack_id,
            expected_behavior=expected,
            actual_behavior=actual,
            llm_call_count=0,
            blocked=blocked,
            terminal=terminal,
            export_report=export_report,
            extra_manifest={
                "workflow.entry": MCP_WORKFLOW_ENTRY,
                "mcp.handler.invoked.count": handler_count,
                "mcp.tool.name": hop.tool_name,
                "result.trust": "untrusted_data",
            },
            request_doc=request_doc,
            extra_result={
                "mcp.started": hop.mcp_started,
                "mcp.completed": hop.mcp_completed,
                "mcp.failed": hop.mcp_failed,
                "handler.invoked": hop.handler_invoked,
                "result.trust": "untrusted_data",
                "result.provenance": "mcp.tool.handler",
                "tool.result": payload,
            },
            limitations_items=[
                "CTRL-MCP-001 is a lab allow-list, not production MCP IAM.",
                "Tools are deterministic in-memory fixtures. No shell, filesystem writes, or network.",
                "JSON-RPC tools/call is real; transport is in-process (not stdio or Streamable HTTP).",
                "Tool results are untrusted data (INV-002). They do not widen allowed_tools.",
                "operation.executed=true on mcp.* means the tool handler began, not that it succeeded.",
                "Runtime never sets collector.observed, hec.ok, or splunk.verified.",
                "No Splunk SPL, Dashboard Studio, MCP-003+, A2A, RAG, memory, or Cisco overlay in this slice.",
            ],
        )
        evidence_dir = str(bundle)

    return McpInvokeResult(
        run_id=str(ctx.run_id),
        incident_id=ctx.incident_id,
        testbed_mode=testbed_mode,
        execution_mode=EXECUTION_MODE,
        telemetry_fidelity=TELEMETRY_FIDELITY,
        profile=settings.security_profile,
        blocked=blocked,
        block_reason=block_reason,
        terminal=terminal,
        final_output=payload,
        hops=[hop],
        events=events,
        evidence_dir=evidence_dir,
        handler_invoke_count=handler_count,
        expected_behavior=expected,
        actual_behavior=actual,
        attack_id=attack_id,
        error_stage=error_stage,
    )


def run_mcp_schema_failure(
    *,
    sink: EventSink,
    memory: MemorySink,
    settings: Settings,
    user_id: str,
    testbed_mode: str,
    attack_id: str,
    error_reason: str,
    extra_fields: tuple[str, ...] = (),
    write_evidence: bool = True,
    registry: ToolRegistry | None = None,
) -> McpInvokeResult:
    del registry
    ctx = RunContext.mint(
        user_id=user_id,
        testbed_mode=testbed_mode,
        attack_id=attack_id,
        workflow_entry=MCP_WORKFLOW_ENTRY,
        workflow_name=MCP_WORKFLOW_NAME,
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
            expected_behavior="ERROR before MCP hop; handler never invoked",
            actual_behavior=actual,
            llm_call_count=0,
            blocked=True,
            terminal="run_failed",
            export_report=export_report,
            extra_manifest={"workflow.entry": MCP_WORKFLOW_ENTRY, "mcp.handler.invoked.count": 0},
            limitations_items=[
                "Unknown HTTP fields cannot set identity, grants, profile, or control decision.",
                "Runtime never sets splunk.verified.",
            ],
        )
        evidence_dir = str(bundle)
    return McpInvokeResult(
        run_id=str(ctx.run_id),
        incident_id=ctx.incident_id,
        testbed_mode=testbed_mode,
        execution_mode=EXECUTION_MODE,
        telemetry_fidelity=TELEMETRY_FIDELITY,
        profile=settings.security_profile,
        blocked=True,
        block_reason=error_reason,
        terminal="run_failed",
        final_output=None,
        hops=[],
        events=events,
        evidence_dir=evidence_dir,
        handler_invoke_count=0,
        expected_behavior="ERROR before MCP hop; handler never invoked",
        actual_behavior=actual,
        attack_id=attack_id,
        error_stage="schema_validation",
    )


def mcp_result_to_dict(result: McpInvokeResult) -> dict[str, Any]:
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
        "final_output": result.final_output,
        "handler_invoke_count": result.handler_invoke_count,
        "expected_behavior": result.expected_behavior,
        "actual_behavior": result.actual_behavior,
        "attack_id": result.attack_id,
        "evidence_dir": result.evidence_dir,
        "schema_name": SCHEMA_NAME,
        "schema_version": SCHEMA_VERSION,
        "error_stage": result.error_stage,
        "result_trust": result.result_trust,
        "result_provenance": result.result_provenance,
        "hops": [
            {
                "hop.index": hop.index,
                "agent_id": hop.agent_id,
                "agent_name": hop.agent_name,
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
                "delegator.agent.id": hop.delegator_agent_id,
                "span_id": hop.span_id,
            }
            for hop in result.hops
        ],
    }
