"""LAB-MCP-006 runner: coded Credit→Compliance delegation, then maybe deputy MCP."""

from __future__ import annotations

import json
import time
from typing import Any, Callable

from agentsec.events import EventEmitter, RunContext, content_hash, content_preview, new_span_id
from agentsec.experiment import (
    EXECUTION_MODE,
    MCP_WORKFLOW_ENTRY,
    MCP_WORKFLOW_NAME,
    TELEMETRY_FIDELITY,
)
from agentsec.evidence import write_evidence_bundle
from agentsec.mcp.client import McpClient
from agentsec.mcp.delegation import (
    CODED_CALLER_ID,
    CODED_CALLER_NAME,
    CODED_DELEGATOR_ID,
    CODED_DEPUTY_ID,
    CODED_DEPUTY_NAME,
    CONTROL_ERROR_REASON,
    CONTROL_ID,
    CONTROL_TYPE,
    DELEGATED_SCOPES,
    DELEGATED_TOOLS,
    DELEGATION_DENIED_REASON,
    DELEGATION_GRANTED_REASON,
    DEPUTY_AMBIENT_SCOPES,
    DEPUTY_AMBIENT_TOOLS,
    DelegationRequest,
    bind_deputy_call,
    coded_delegation_request,
    delegated_policy,
    evaluate_delegation_safe,
    grant_snapshot,
    policy_for_authority_source,
)
from agentsec.mcp.pipeline import McpHop, McpInvokeResult, _duration_ms, _invariants
from agentsec.mcp.policy import ALLOWED_POLICY_IDS, ALLOWED_SCOPES, ALLOWED_TOOLS, coded_policy
from agentsec.mcp.registry import ToolRegistry, default_registry
from agentsec.mcp.server import McpServer
from agentsec.settings import Settings, get_settings
from agentsec.telemetry import EventSink, MemorySink, flush_export

EvaluateFn = Callable[..., Any]


def _emit_agent_id(value: object) -> str:
    if isinstance(value, str) and value.strip():
        return value
    return "unknown"


def _emit_agent_name(agent_id: str, *, coded_id: str, coded_name: str) -> str:
    if agent_id == coded_id:
        return coded_name
    return agent_id


def _delegation_invariants(decision: str) -> list[str]:
    if decision == "DENY":
        return ["INV-001", "INV-008", "INV-007"]
    if decision == "ERROR":
        return ["INV-008", "INV-005", "INV-007"]
    return ["INV-001", "INV-004", "INV-007"]


def _expected_mcp006(profile: str, decision: str, tool: str) -> str:
    if decision == "ERROR":
        return "ERROR before deputy MCP; executed=false; handler 0"
    if decision == "DENY":
        return (
            f"DENY {tool} {DELEGATION_DENIED_REASON}; attempted=false, executed=false, "
            "outcome=prevented; deputy MCP does not begin"
        )
    if profile == "vulnerable" and tool == "lookup_customer_tier":
        return (
            f"ALLOW {tool} {CONTROL_ID} ambient deputy substitution; "
            "CTRL-MCP-001 still runs; handler 1"
        )
    return f"ALLOW {tool} {DELEGATION_GRANTED_REASON}; CTRL-MCP-001; handler 1"


def run_mcp_006_invoke(
    *,
    tool: str,
    arguments: dict[str, Any],
    requested_scope: str,
    sink: EventSink,
    memory: MemorySink,
    settings: Settings | None = None,
    user_id: str = "applicant-web",
    testbed_mode: str,
    write_evidence: bool = True,
    registry: ToolRegistry | None = None,
    request: DelegationRequest | None = None,
    evaluate_fn: EvaluateFn | None = None,
    expected_behavior: str | None = None,
    mutate_request_after_allow: Callable[[DelegationRequest], None] | None = None,
) -> McpInvokeResult:
    """Coded caller/deputy. HTTP JSON cannot set identities or grants."""
    settings = settings or get_settings()
    started = time.monotonic()
    registry = registry or default_registry()
    snapshot_before = grant_snapshot()
    coded_before = coded_policy()
    client = McpClient()
    del_request = request or coded_delegation_request(
        tool=tool,
        arguments=arguments,
        requested_scope=requested_scope,
        principal_id=user_id,
    )

    ctx = RunContext.mint(
        user_id=user_id,
        testbed_mode=testbed_mode,
        attack_id="MCP-006",
        workflow_entry=MCP_WORKFLOW_ENTRY,
        workflow_name=MCP_WORKFLOW_NAME,
    )
    emitter = EventEmitter(ctx, sink.emit, settings)
    emitter.run_started()

    caller_emit_id = _emit_agent_id(del_request.caller_agent_id)
    caller_emit_name = _emit_agent_name(caller_emit_id, coded_id=CODED_CALLER_ID, coded_name=CODED_CALLER_NAME)
    deputy_emit_id = _emit_agent_id(del_request.deputy_agent_id)

    hop0_started_at = time.monotonic()
    hop0_span = new_span_id()
    emitter.hop_started(
        hop_index=0,
        agent_id=caller_emit_id,
        agent_name=caller_emit_name,
        hop_span_id=hop0_span,
        delegator_agent_id=None,
    )

    control = evaluate_delegation_safe(
        request=del_request,
        profile=settings.security_profile,
        evaluate_fn=evaluate_fn,
    )
    content = json.dumps(
        {
            "caller": caller_emit_id,
            "deputy": deputy_emit_id,
            "tool": control.tool_name,
            "requested_scope": control.requested_scope,
            "authority_source": control.authority_source,
            "delegated_tools": ",".join(sorted(DELEGATED_TOOLS)),
        },
        sort_keys=True,
    )
    emitter.control_decision(
        hop_index=0,
        agent_id=caller_emit_id,
        agent_name=caller_emit_name,
        hop_span_id=hop0_span,
        control_id=CONTROL_ID,
        control_type=CONTROL_TYPE,
        decision=control.decision,
        reason=control.reason,
        trust_boundary="acmebank.mcp.authorize",
        invariant_ids=_delegation_invariants(control.decision),
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
        resource_id=control.resource_id,
        allowed_resource_ids=delegated_policy().allowed_policy_ids_wire(),
        authority_source=control.authority_source,
    )

    hop0_outcome = "hop_allowed"
    blocked = False
    block_reason = None
    error_stage = control.error_stage
    hops: list[McpHop] = []
    counts_before = registry.invoke_total
    counts_before_by_tool = dict(registry.invoke_counts)

    if control.blocks_deputy:
        blocked = True
        block_reason = control.reason
        hop0_outcome = "hop_denied" if control.decision == "DENY" else "hop_error"
        emitter.pipeline_stopped(
            hop_index=0,
            agent_id=caller_emit_id,
            stop_reason="denied" if control.decision == "DENY" else "error",
            delegator_agent_id=None,
        )

    hop0 = McpHop(
        index=0,
        agent_id=caller_emit_id,
        agent_name=caller_emit_name,
        control_decision=control.decision,
        control_reason=control.reason,
        operation_attempted=False,
        operation_executed=False,
        operation_outcome="prevented" if control.blocks_deputy else None,
        llm_started=False,
        llm_completed=False,
        llm_failed=False,
        mcp_started=False,
        mcp_completed=False,
        mcp_failed=False,
        span_id=hop0_span,
        delegator_agent_id=None,
        handler_invoked=False,
        tool_name=control.tool_name,
    )
    hops.append(hop0)
    emitter.hop_completed(
        hop_index=0,
        agent_id=caller_emit_id,
        agent_name=caller_emit_name,
        hop_span_id=hop0_span,
        outcome=hop0_outcome,
        duration_ms=_duration_ms(hop0_started_at),
        delegator_agent_id=None,
    )

    downstream_decision = None
    downstream_reason = None
    attempted = False
    executed = False
    outcome: str | None = hop0.operation_outcome
    payload: dict[str, Any] | None = None

    if not control.blocks_deputy and control.ticket is not None:
        if mutate_request_after_allow is not None:
            mutate_request_after_allow(del_request)
        ticket = control.ticket
        bound_tool, bound_scope, bound_args, bound_deputy = bind_deputy_call(ticket)
        if bound_deputy != CODED_DEPUTY_ID or bound_tool != ticket.tool:
            blocked = True
            block_reason = CONTROL_ERROR_REASON
            error_stage = "control_evaluation"
            emitter.pipeline_stopped(
                hop_index=0,
                agent_id=caller_emit_id,
                stop_reason="error",
                delegator_agent_id=None,
            )
        else:
            deputy_policy = policy_for_authority_source(ticket.authority_source)
            server = McpServer(registry=registry, policy=deputy_policy)
            hop1 = _run_deputy_mcp_hop(
                server=server,
                client=client,
                emitter=emitter,
                registry=registry,
                user_id=user_id,
                tool=bound_tool,
                arguments=bound_args,
                requested_scope=bound_scope,
                counts_before=counts_before,
            )
            hops.append(hop1)
            downstream_decision = hop1.control_decision
            downstream_reason = hop1.control_reason
            attempted = hop1.operation_attempted
            executed = hop1.operation_executed
            outcome = hop1.operation_outcome
            payload = hop1.response
            if hop1.control_decision == "DENY":
                blocked = True
                block_reason = hop1.control_reason
            elif hop1.control_decision == "ERROR" or hop1.mcp_failed:
                blocked = True
                block_reason = (
                    hop1.control_reason if hop1.control_decision == "ERROR" else (hop1.mcp_error or "mcp_error")
                )
                error_stage = "control_evaluation" if hop1.control_decision == "ERROR" else "mcp_invocation"

    last = hops[-1]
    if blocked and last.control_decision == "DENY":
        terminal = "completed_denied"
        emitter.run_completed(outcome="completed_denied", duration_ms=_duration_ms(started))
        actual = f"DENY {last.tool_name}; handler_invokes={registry.invoke_total - counts_before}"
    elif blocked:
        terminal = "run_failed"
        stage = error_stage or "pipeline"
        emitter.run_failed(
            error_type=block_reason or "mcp_error",
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
            error_message=block_reason or "MCP-006 stopped with error",
        )
        actual = f"ERROR {last.tool_name}; handler_invokes={registry.invoke_total - counts_before}"
    else:
        terminal = "completed_allowed"
        emitter.run_completed(outcome="completed_allowed", duration_ms=_duration_ms(started))
        actual = f"ALLOW {last.tool_name}; handler_invokes={registry.invoke_total - counts_before}"

    handler_count = registry.invoke_total - counts_before
    lookup_policy_count = registry.invoke_counts.get("lookup_policy", 0) - counts_before_by_tool.get("lookup_policy", 0)
    lookup_tier_count = registry.invoke_counts.get("lookup_customer_tier", 0) - counts_before_by_tool.get(
        "lookup_customer_tier", 0
    )

    snapshot_after = grant_snapshot()
    coded_after = coded_policy()
    if snapshot_after != snapshot_before:
        raise RuntimeError("MCP-006 blocker: delegation grant snapshot mutated")
    if coded_after.allowed_tools != coded_before.allowed_tools:
        raise RuntimeError("MCP-006 blocker: coded allowed_tools mutated")
    if coded_after.allowed_scopes != coded_before.allowed_scopes:
        raise RuntimeError("MCP-006 blocker: coded allowed_scopes mutated")
    if coded_after.allowed_policy_ids != coded_before.allowed_policy_ids:
        raise RuntimeError("MCP-006 blocker: coded allowed_policy_ids mutated")
    if ALLOWED_TOOLS != frozenset({"lookup_policy"}):
        raise RuntimeError("MCP-006 blocker: global ALLOWED_TOOLS mutated")
    if ALLOWED_SCOPES != frozenset({"policy:read"}):
        raise RuntimeError("MCP-006 blocker: global ALLOWED_SCOPES mutated")
    if ALLOWED_POLICY_IDS != frozenset({"lending-basics"}):
        raise RuntimeError("MCP-006 blocker: global ALLOWED_POLICY_IDS mutated")

    expected = expected_behavior or _expected_mcp006(
        settings.security_profile, control.decision, control.tool_name
    )
    events = [event for event in memory.events if event.get("agentsec.run.id") == str(ctx.run_id)]
    export_report = flush_export(sink)
    evidence_dir = None
    if write_evidence:
        request_doc = {
            "caller": caller_emit_id,
            "deputy": deputy_emit_id,
            "tool": control.tool_name,
            "requested_scope": control.requested_scope,
            "arguments.hash": content_hash(json.dumps(arguments, sort_keys=True)),
            "arguments.preview": content_preview(json.dumps(arguments, sort_keys=True)),
        }
        bundle = write_evidence_bundle(
            run_id=str(ctx.run_id),
            incident_id=ctx.incident_id,
            settings=settings,
            events=events,
            user_input=content,
            hops=hops,
            testbed_mode=testbed_mode,
            attack_id="MCP-006",
            expected_behavior=expected,
            actual_behavior=actual,
            llm_call_count=0,
            blocked=blocked,
            terminal=terminal,
            export_report=export_report,
            extra_manifest={
                "workflow.entry": MCP_WORKFLOW_ENTRY,
                "mcp.lab.id": "LAB-MCP-006",
                "mcp.handler.invoked.count": handler_count,
                "mcp.handler.lookup_policy.count": lookup_policy_count,
                "mcp.handler.lookup_customer_tier.count": lookup_tier_count,
                "mcp.tool.name": control.tool_name,
                "delegation.caller.id": caller_emit_id,
                "delegation.deputy.id": deputy_emit_id,
                "delegation.delegator.id": CODED_DELEGATOR_ID,
                "delegation.decision": control.decision,
                "delegation.reason": control.reason,
                "delegation.authority.source": control.authority_source,
                "delegation.delegated.tools": ",".join(sorted(DELEGATED_TOOLS)),
                "delegation.delegated.scopes": ",".join(sorted(DELEGATED_SCOPES)),
                "delegation.ambient.tools": ",".join(sorted(DEPUTY_AMBIENT_TOOLS)),
                "delegation.ambient.scopes": ",".join(sorted(DEPUTY_AMBIENT_SCOPES)),
                "downstream.mcp.decision": downstream_decision,
                "downstream.mcp.reason": downstream_reason,
                "operation.attempted": attempted,
                "operation.executed": executed,
                "operation.outcome": outcome,
                "server_owned.allowed_tools": ",".join(sorted(coded_after.allowed_tools)),
            },
            request_doc=request_doc,
            extra_result={
                "mcp.started": any(hop.mcp_started for hop in hops),
                "handler.invoked": handler_count > 0,
                "handler.lookup_policy.count": lookup_policy_count,
                "handler.lookup_customer_tier.count": lookup_tier_count,
                "delegation.decision": control.decision,
                "delegation.reason": control.reason,
                "delegation.authority.source": control.authority_source,
                "downstream.mcp.decision": downstream_decision,
                "tool.result": payload,
            },
            limitations_items=[
                "CTRL-DELEGATION-001 is a lab delegated-authority check, not production IAM.",
                "Caller and deputy identities are coded. HTTP JSON cannot set them.",
                "Vulnerable ambient substitution is per-request. coded_policy() is never mutated.",
                "Hop 1 CTRL-MCP-001 always uses the defended membership check against the selected policy object.",
                "Tools are deterministic in-memory fixtures. No shell, filesystem writes, or network.",
                "Schema 1.4.0 has no gen_ai.tool.call.id. Same-tool twice in one run is correlated only by sequence.",
                "Grant lists are not indexed as allowed_tools. Runtime/manifest remain authoritative for Q3/Q4.",
                "splunk.verified=false. Splunk is not verified in this runtime slice. No DET-MCP-006. No SPL.",
                "Runtime never sets collector.observed, hec.ok, or splunk.verified.",
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
        hops=hops,
        events=events,
        evidence_dir=evidence_dir,
        handler_invoke_count=handler_count,
        expected_behavior=expected,
        actual_behavior=actual,
        attack_id="MCP-006",
        error_stage=error_stage,
        lookup_policy_handler_count=lookup_policy_count,
        lookup_customer_tier_handler_count=lookup_tier_count,
        server_owned_allowed_tools=",".join(sorted(coded_after.allowed_tools)),
        caller_agent_id=caller_emit_id,
        deputy_agent_id=deputy_emit_id,
        delegation_decision=control.decision,
        delegation_reason=control.reason,
        authority_source=control.authority_source,
        downstream_mcp_decision=downstream_decision,
        downstream_mcp_reason=downstream_reason,
        operation_attempted=attempted,
        operation_executed=executed,
        operation_outcome=outcome,
    )


def _run_deputy_mcp_hop(
    *,
    server: McpServer,
    client: McpClient,
    emitter: EventEmitter,
    registry: ToolRegistry,
    user_id: str,
    tool: str,
    arguments: dict[str, str],
    requested_scope: str,
    counts_before: int,
) -> McpHop:
    """Hop 1: real CTRL-MCP-001 then maybe handler. Profile is always defended membership."""
    del counts_before
    hop_started_at = time.monotonic()
    hop_span_id = new_span_id()
    emitter.hop_started(
        hop_index=1,
        agent_id=CODED_DEPUTY_ID,
        agent_name=CODED_DEPUTY_NAME,
        hop_span_id=hop_span_id,
        delegator_agent_id=CODED_DELEGATOR_ID,
    )
    rpc = client.tools_call(name=tool, arguments=dict(arguments), request_id=2)
    decision = server.authorize(
        rpc,
        profile="defended",
        requested_scope=requested_scope,
        coded_agent_id=CODED_DEPUTY_ID,
    )
    control = decision.control
    content = json.dumps(
        {
            "tool": tool,
            "requested_scope": requested_scope,
            "deputy": CODED_DEPUTY_ID,
            "delegator": CODED_DELEGATOR_ID,
        },
        sort_keys=True,
    )
    emitter.control_decision(
        hop_index=1,
        agent_id=CODED_DEPUTY_ID,
        agent_name=CODED_DEPUTY_NAME,
        hop_span_id=hop_span_id,
        control_id=control.control_id,
        control_type=control.control_type,
        decision=control.decision,
        reason=control.reason,
        trust_boundary="acmebank.mcp.authorize",
        invariant_ids=_invariants(control.decision),
        content_text=content,
        origin_type="agent",
        origin_id=CODED_CALLER_ID,
        influence_kind="tool_request",
        delegator_agent_id=CODED_DELEGATOR_ID,
        error_stage=control.error_stage,
        tool_name=control.tool_name,
        mcp_method="tools/call",
        requested_scope=control.requested_scope,
        allowed_scope=control.allowed_scope,
        resource_id=control.resource_id,
        allowed_resource_ids=control.allowed_resource_ids,
    )
    mcp_started = False
    mcp_completed = False
    mcp_failed = False
    attempted = False
    executed = False
    outcome: str | None = None
    payload = None
    mcp_error = None
    hop_outcome = "hop_allowed"
    if control.blocks_tool:
        outcome = "prevented"
        hop_outcome = "hop_denied" if control.decision == "DENY" else "hop_error"
        emitter.pipeline_stopped(
            hop_index=1,
            agent_id=CODED_DEPUTY_ID,
            stop_reason="denied" if control.decision == "DENY" else "error",
            delegator_agent_id=CODED_DELEGATOR_ID,
        )
    else:
        mcp_span_id = new_span_id()
        exec_started = time.monotonic()
        emitter.mcp_started(
            hop_index=1,
            agent_id=CODED_DEPUTY_ID,
            agent_name=CODED_DEPUTY_NAME,
            hop_span_id=hop_span_id,
            mcp_span_id=mcp_span_id,
            tool_name=decision.tool_name,
            delegator_agent_id=CODED_DELEGATOR_ID,
        )
        mcp_started = True
        attempted = True
        executed = True
        execution = server.execute(decision.ticket)
        if not execution.ok:
            mcp_error = execution.error_type
            mcp_failed = True
            outcome = "error"
            hop_outcome = "hop_error"
            emitter.mcp_failed(
                hop_index=1,
                agent_id=CODED_DEPUTY_ID,
                agent_name=CODED_DEPUTY_NAME,
                hop_span_id=hop_span_id,
                mcp_span_id=mcp_span_id,
                tool_name=decision.tool_name,
                error_type=execution.error_type or "mcp_error",
                error_message=execution.error_message or execution.error_type or "mcp_error",
                delegator_agent_id=CODED_DELEGATOR_ID,
            )
            emitter.pipeline_stopped(
                hop_index=1,
                agent_id=CODED_DEPUTY_ID,
                stop_reason="error",
                delegator_agent_id=CODED_DELEGATOR_ID,
            )
        else:
            mcp_completed = True
            outcome = "success"
            payload = execution.payload
            result_text = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            emitter.mcp_completed(
                hop_index=1,
                agent_id=CODED_DEPUTY_ID,
                agent_name=CODED_DEPUTY_NAME,
                hop_span_id=hop_span_id,
                mcp_span_id=mcp_span_id,
                tool_name=decision.tool_name,
                duration_ms=_duration_ms(exec_started),
                result_text=result_text,
                delegator_agent_id=CODED_DELEGATOR_ID,
            )
    emitter.hop_completed(
        hop_index=1,
        agent_id=CODED_DEPUTY_ID,
        agent_name=CODED_DEPUTY_NAME,
        hop_span_id=hop_span_id,
        outcome=hop_outcome,
        duration_ms=_duration_ms(hop_started_at),
        delegator_agent_id=CODED_DELEGATOR_ID,
    )
    return McpHop(
        index=1,
        agent_id=CODED_DEPUTY_ID,
        agent_name=CODED_DEPUTY_NAME,
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
        delegator_agent_id=CODED_DELEGATOR_ID,
        handler_invoked=mcp_started,
        tool_name=decision.tool_name or tool,
        response=payload,
        mcp_error=mcp_error,
    )
