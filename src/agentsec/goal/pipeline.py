"""Dedicated goal/task-integrity path: classify the instruction, then CTRL-MCP-001."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from agentsec.events import EventEmitter, RunContext, new_span_id
from agentsec.evidence import write_evidence_bundle
from agentsec.experiment import EXECUTION_MODE, SCHEMA_NAME, SCHEMA_VERSION, TELEMETRY_FIDELITY
from agentsec.goal.fixtures import (
    CLOSED_EXPANSION_ACTION,
    GOAL_AGENT_ID,
    GOAL_AGENT_NAME,
    GOAL_ATTACK_ID,
    GOAL_WORKFLOW_ENTRY,
    GOAL_WORKFLOW_NAME,
    INSTRUCTION_PROVENANCE,
    INSTRUCTION_TRUST,
    ORCHESTRATOR_AGENT_ID,
    ORCHESTRATOR_AGENT_NAME,
    TASK_PROVENANCE,
    goal_agent_policy,
)
from agentsec.goal.influence import ProposedTaskChange, parse_goal_request
from agentsec.goal.task import TaskContract, authoritative_task_contract
from agentsec.goal.trust import (
    GOAL_FAIL_OPEN_REASON,
    GoalDerivedOverlay,
    GoalTrustDecision,
    effective_action,
    evaluate_goal_integrity_safe,
    mint_goal_overlay,
)
from agentsec.mcp.authorize import McpControlResult
from agentsec.mcp.client import McpClient
from agentsec.mcp.pipeline import McpHop
from agentsec.mcp.policy import policy_unchanged_by_goal_instruction
from agentsec.mcp.registry import ToolRegistry, default_registry
from agentsec.mcp.server import McpServer
from agentsec.settings import Settings, get_settings
from agentsec.telemetry import EventSink, MemorySink, flush_export

AuthorizeFn = Callable[..., McpControlResult]


@dataclass
class GoalIntegrityResult:
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
    goal_control_decision: str | None
    goal_control_reason: str | None
    instruction_trust: str | None
    follow_on_decision: str | None
    follow_on_reason: str | None
    frozen_task: TaskContract
    frozen_change: ProposedTaskChange | None
    task_fingerprint: str
    instruction_hash: str | None
    proposed_fingerprint: str | None
    proposed_action: str | None
    effective_action: str | None
    overlay_applied: bool
    overlay_run_id: str | None
    lookup_policy_handler_count: int
    in_task_lookup_policy_count: int
    wrong_goal_lookup_policy_count: int
    check_use_consistent: bool
    server_owned_allowed_tools: str
    error_stage: str | None = None


def _duration_ms(started: float) -> int:
    return max(0, int((time.monotonic() - started) * 1000))


def _goal_invariants(decision: str) -> list[str]:
    if decision == "ERROR":
        return ["INV-002", "INV-006", "INV-008", "INV-007"]
    if decision == "DENY":
        return ["INV-002", "INV-006", "INV-007"]
    return ["INV-002", "INV-006", "INV-007"]


def _mcp_invariants(decision: str) -> list[str]:
    if decision == "DENY":
        return ["INV-001", "INV-008", "INV-007"]
    if decision == "ERROR":
        return ["INV-008", "INV-007"]
    return ["INV-001", "INV-004", "INV-007"]


def _expected(
    profile: str,
    goal: GoalTrustDecision,
    follow_on: str | None,
    follow_reason: str | None,
    wrong_goal: int,
) -> str:
    if goal.decision == "ERROR":
        return "ERROR before follow-on; untrusted instruction is not task authority; handler 0"
    if profile == "vulnerable" and wrong_goal == 1:
        return (
            "CTRL-GOAL-INTEGRITY-001 OBSERVE "
            f"{GOAL_FAIL_OPEN_REASON}; "
            "CTRL-MCP-001 ALLOW tool_granted; wrong-goal lookup_policy handler 1"
        )
    if goal.decision == "DENY":
        return (
            "CTRL-GOAL-INTEGRITY-001 DENY unauthorized_task_expansion; "
            "CTRL-MCP-001 ALLOW tool_granted; in-task lookup_policy handler 1; wrong-goal handler 0"
        )
    if follow_on == "ALLOW" and follow_reason == "tool_granted":
        return (
            "CTRL-GOAL-INTEGRITY-001 OBSERVE untrusted_instruction_cannot_redefine_task; "
            "CTRL-MCP-001 ALLOW tool_granted; in-task lookup_policy handler 1; wrong-goal handler 0"
        )
    return (
        "CTRL-GOAL-INTEGRITY-001 recorded; untrusted instruction is not task authority; "
        f"mcp={follow_on}/{follow_reason}"
    )


def run_goal_integrity(
    *,
    payload: object,
    sink: EventSink,
    memory: MemorySink,
    settings: Settings | None = None,
    testbed_mode: str,
    registry: ToolRegistry | None = None,
    authorize_fn: AuthorizeFn | None = None,
    write_evidence: bool = True,
    frozen_task: TaskContract | None = None,
    frozen_change: ProposedTaskChange | None = None,
) -> GoalIntegrityResult:
    settings = settings or get_settings()
    registry = registry or default_registry()
    task = frozen_task or authoritative_task_contract()
    parsed = parse_goal_request(payload, task=task) if frozen_change is None else None
    change = frozen_change
    parse_error = None
    parse_stage = None
    if frozen_change is None:
        assert parsed is not None
        if parsed.ok:
            change = parsed.change
        else:
            parse_error = parsed.error_reason
            parse_stage = parsed.error_stage

    principal = change.principal_id if change is not None else "unknown"
    ctx = RunContext.mint(
        user_id=principal,
        testbed_mode=testbed_mode,
        attack_id=GOAL_ATTACK_ID,
        workflow_entry=GOAL_WORKFLOW_ENTRY,
        workflow_name=GOAL_WORKFLOW_NAME,
    )
    emitter = EventEmitter(ctx, sink.emit, settings)
    emitter.run_started()
    run_started_at = time.monotonic()
    goal = evaluate_goal_integrity_safe(
        task=task,
        change=change,
        profile=settings.security_profile,
        parse_error=parse_error,
        parse_stage=parse_stage,
    )
    hop_started_at = time.monotonic()
    hop_span_id = new_span_id()
    emitter.hop_started(
        hop_index=0,
        agent_id=ORCHESTRATOR_AGENT_ID,
        agent_name=ORCHESTRATOR_AGENT_NAME,
        hop_span_id=hop_span_id,
        delegator_agent_id=None,
    )
    instruction_text = change.instruction if change is not None else json.dumps(payload, default=str)
    content = json.dumps(
        {
            "task_id": task.task_id,
            "task_hash": task.fingerprint,
            "proposed_action": goal.proposed_action,
            "instruction_hash": change.instruction_hash if change is not None else None,
            "instruction_trust": INSTRUCTION_TRUST,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    emitter.control_decision(
        hop_index=0,
        agent_id=ORCHESTRATOR_AGENT_ID,
        agent_name=ORCHESTRATOR_AGENT_NAME,
        hop_span_id=hop_span_id,
        control_id=goal.control_id,
        control_type=goal.control_type,
        decision=goal.decision,
        reason=goal.reason,
        trust_boundary="agent.task.contract",
        invariant_ids=_goal_invariants(goal.decision),
        content_text=content,
        origin_type="user",
        origin_id=principal,
        influence_kind="untrusted_instruction",
        delegator_agent_id=None,
        error_stage=goal.error_stage,
        tool_name=goal.proposed_action,
        task_id=task.task_id,
        task_hash=task.fingerprint,
        task_preview=task.preview(),
        task_provenance=TASK_PROVENANCE,
        instruction_trust=INSTRUCTION_TRUST,
        instruction_provenance=INSTRUCTION_PROVENANCE,
        goal_proposed=goal.proposed_action,
        goal_decision=goal.decision,
        goal_reason=goal.reason,
    )
    hops: list[McpHop] = []
    blocked = goal.decision == "ERROR"
    block_reason = goal.reason if blocked else None
    hop_outcome = "hop_error" if blocked else "hop_allowed"
    if blocked:
        emitter.pipeline_stopped(
            hop_index=0,
            agent_id=ORCHESTRATOR_AGENT_ID,
            stop_reason="error",
            delegator_agent_id=None,
        )
    hops.append(
        McpHop(
            index=0,
            agent_id=ORCHESTRATOR_AGENT_ID,
            agent_name=ORCHESTRATOR_AGENT_NAME,
            control_decision=goal.decision,
            control_reason=goal.reason,
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
            tool_name=goal.proposed_action,
            response=None,
            mcp_error=None,
        )
    )
    emitter.hop_completed(
        hop_index=0,
        agent_id=ORCHESTRATOR_AGENT_ID,
        agent_name=ORCHESTRATOR_AGENT_NAME,
        hop_span_id=hop_span_id,
        outcome=hop_outcome,
        duration_ms=_duration_ms(hop_started_at),
        delegator_agent_id=None,
    )

    policy = goal_agent_policy()
    server = McpServer(registry=registry, policy=policy, authorize_fn=authorize_fn)
    client = McpClient()
    counts_before_by_tool = dict(registry.invoke_counts)
    overlay = None
    overlay_applied = False
    follow_on_decision = None
    follow_on_reason = None
    action = None
    check_use_consistent = False
    if not blocked and change is not None:
        overlay = mint_goal_overlay(
            task=task,
            change=change,
            run_id=str(ctx.run_id),
            profile=settings.security_profile,
        )
        overlay_applied = overlay is not None
        action = effective_action(task=task, change=change, overlay=overlay, goal=goal)
        hop = _run_follow_on(
            server=server,
            client=client,
            emitter=emitter,
            registry=registry,
            settings=settings,
            task=task,
            change=change,
            action=action,
            counts_before_by_tool=counts_before_by_tool,
        )
        hops.append(hop)
        follow_on_decision = hop.control_decision
        follow_on_reason = hop.control_reason
        check_use_consistent = hop.tool_name == change.resulting_tool and (
            overlay is None or overlay.proposed_fingerprint == change.fingerprint
        )
        policy_unchanged_by_goal_instruction(policy, change)

    lookup_policy_count = registry.invoke_counts.get("lookup_policy", 0) - counts_before_by_tool.get(
        "lookup_policy", 0
    )
    wrong_goal_count = 0
    in_task_count = 0
    if lookup_policy_count > 0 and action == CLOSED_EXPANSION_ACTION:
        wrong_goal_count = lookup_policy_count
    elif lookup_policy_count > 0:
        in_task_count = lookup_policy_count

    terminal = "run_failed" if blocked or (hops and hops[-1].operation_outcome == "error") else "run_completed"
    if terminal == "run_failed":
        if blocked:
            emitter.run_failed(
                error_type=goal.reason,
                error_stage=goal.error_stage or "schema_validation",
                error_message=goal.reason,
            )
        else:
            emitter.run_failed(
                error_type=hops[-1].mcp_error or "mcp_error",
                error_stage="mcp_invocation",
                error_message=hops[-1].mcp_error or "handler failed after ALLOW",
            )
    else:
        if follow_on_decision == "ERROR":
            terminal = "run_failed"
            emitter.run_failed(
                error_type=follow_on_reason or "mcp_error",
                error_stage="control_evaluation",
                error_message=follow_on_reason or "mcp_error",
            )
        else:
            outcome = "completed_denied" if goal.decision == "DENY" else "completed_allowed"
            emitter.run_completed(outcome=outcome, duration_ms=_duration_ms(run_started_at))

    expected = _expected(
        settings.security_profile, goal, follow_on_decision, follow_on_reason, wrong_goal_count
    )
    actual = (
        f"goal={goal.decision}/{goal.reason}; "
        f"mcp={follow_on_decision}/{follow_on_reason}; "
        f"action={action}; lookup_policy={lookup_policy_count}; "
        f"wrong_goal={wrong_goal_count}; in_task={in_task_count}"
    )
    events = [event for event in memory.events if event.get("agentsec.run.id") == str(ctx.run_id)]
    export_report = flush_export(sink)
    evidence_dir = None
    if write_evidence:
        request_doc = {
            "task": task.canonical_dict(),
            "instruction": change.canonical_dict() if change is not None else {"error": goal.reason},
        }
        bundle = write_evidence_bundle(
            run_id=str(ctx.run_id),
            incident_id=ctx.incident_id,
            settings=settings,
            events=events,
            user_input=instruction_text,
            hops=hops,
            testbed_mode=testbed_mode,
            attack_id=GOAL_ATTACK_ID,
            expected_behavior=expected,
            actual_behavior=actual,
            llm_call_count=0,
            blocked=blocked or goal.decision == "DENY",
            terminal=terminal,
            export_report=export_report,
            extra_manifest={
                "workflow.entry": GOAL_WORKFLOW_ENTRY,
                "lab.id": GOAL_WORKFLOW_NAME,
                "task.id": task.task_id,
                "task.hash": task.fingerprint,
                "instruction.hash": change.instruction_hash if change is not None else None,
                "goal.proposed": goal.proposed_action,
                "goal.decision": goal.decision,
                "goal.reason": goal.reason,
                "overlay.applied": overlay_applied,
                "wrong_goal.handler.count": wrong_goal_count,
                "splunk.verified": False,
            },
            request_doc=request_doc,
            extra_result={
                "goal.control.decision": goal.decision,
                "mcp.control.decision": follow_on_decision,
                "wrong_goal.handler.count": wrong_goal_count,
                "in_task.handler.count": in_task_count,
            },
            limitations_items=[
                "CTRL-GOAL-INTEGRITY-001 classifies untrusted instructions as data. OBSERVE is not ALLOW.",
                "DENY unauthorized_task_expansion rejects task expansion. It is not CTRL-MCP-001 tool_not_granted.",
                "lookup_policy remains coded for this agent. extract_full_policy is outside the task, not a missing tool grant.",
                "Vulnerable untrusted-instruction-derived task authority is a per-request overlay. coded_policy() is never mutated.",
                "CTRL-MCP-001 remains the only tool PDP. Goal observation/deny does not mint AllowTicket.",
                "No LLM planner, LangGraph, prompt filter, Splunk SPL, DET-GOAL, or Dashboard Studio in this slice.",
                "splunk.verified=false. Splunk is not verified in this runtime slice. DET-MCP-001 is unchanged.",
                "Schema 1.9.0 has no session.id, tenant.id, gen_ai.tool.call.id, or token fields.",
            ],
        )
        evidence_dir = str(bundle)

    return GoalIntegrityResult(
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
        attack_id=GOAL_ATTACK_ID,
        goal_control_decision=goal.decision,
        goal_control_reason=goal.reason,
        instruction_trust=INSTRUCTION_TRUST,
        follow_on_decision=follow_on_decision,
        follow_on_reason=follow_on_reason,
        frozen_task=task,
        frozen_change=change,
        task_fingerprint=task.fingerprint,
        instruction_hash=change.instruction_hash if change is not None else None,
        proposed_fingerprint=change.fingerprint if change is not None else None,
        proposed_action=goal.proposed_action,
        effective_action=action,
        overlay_applied=overlay_applied,
        overlay_run_id=str(ctx.run_id) if overlay_applied else None,
        lookup_policy_handler_count=lookup_policy_count,
        in_task_lookup_policy_count=in_task_count,
        wrong_goal_lookup_policy_count=wrong_goal_count,
        check_use_consistent=check_use_consistent,
        server_owned_allowed_tools=",".join(sorted(policy.allowed_tools)),
        error_stage=goal.error_stage,
    )


def _run_follow_on(
    *,
    server: McpServer,
    client: McpClient,
    emitter: EventEmitter,
    registry: ToolRegistry,
    settings: Settings,
    task: TaskContract,
    change: ProposedTaskChange,
    action: str,
    counts_before_by_tool: dict[str, int],
) -> McpHop:
    hop_started_at = time.monotonic()
    hop_span_id = new_span_id()
    emitter.hop_started(
        hop_index=1,
        agent_id=GOAL_AGENT_ID,
        agent_name=GOAL_AGENT_NAME,
        hop_span_id=hop_span_id,
        delegator_agent_id=ORCHESTRATOR_AGENT_ID,
    )
    rpc = client.tools_call(
        name=change.resulting_tool,
        arguments=change.tool_arguments(),
        request_id=2,
    )
    decision = server.authorize(
        rpc,
        profile=settings.security_profile,
        requested_scope=change.resulting_scope,
        coded_agent_id=GOAL_AGENT_ID,
    )
    control = decision.control
    content = json.dumps(
        {
            "tool": change.resulting_tool,
            "requested_scope": change.resulting_scope,
            "resource": change.resulting_resource,
            "effective_action": action,
            "task_hash": task.fingerprint,
            "proposed_fingerprint": change.fingerprint,
            "server_owned_allowed_tools": ",".join(sorted(server.policy.allowed_tools)),
        },
        sort_keys=True,
    )
    emitter.control_decision(
        hop_index=1,
        agent_id=GOAL_AGENT_ID,
        agent_name=GOAL_AGENT_NAME,
        hop_span_id=hop_span_id,
        control_id=control.control_id,
        control_type=control.control_type,
        decision=control.decision,
        reason=control.reason,
        trust_boundary="acmebank.mcp.authorize",
        invariant_ids=_mcp_invariants(control.decision),
        content_text=content,
        origin_type="agent",
        origin_id=GOAL_AGENT_ID,
        influence_kind="tool_request",
        delegator_agent_id=ORCHESTRATOR_AGENT_ID,
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
    payload: dict[str, Any] | None = None
    mcp_error = None
    hop_outcome = "hop_allowed"
    if control.blocks_tool:
        outcome = "prevented"
        hop_outcome = "hop_denied" if control.decision == "DENY" else "hop_error"
        emitter.pipeline_stopped(
            hop_index=1,
            agent_id=GOAL_AGENT_ID,
            stop_reason="denied" if control.decision == "DENY" else "error",
            delegator_agent_id=ORCHESTRATOR_AGENT_ID,
        )
    else:
        mcp_span_id = new_span_id()
        exec_started = time.monotonic()
        emitter.mcp_started(
            hop_index=1,
            agent_id=GOAL_AGENT_ID,
            agent_name=GOAL_AGENT_NAME,
            hop_span_id=hop_span_id,
            mcp_span_id=mcp_span_id,
            tool_name=decision.tool_name,
            delegator_agent_id=ORCHESTRATOR_AGENT_ID,
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
                agent_id=GOAL_AGENT_ID,
                agent_name=GOAL_AGENT_NAME,
                hop_span_id=hop_span_id,
                mcp_span_id=mcp_span_id,
                tool_name=decision.tool_name,
                error_type=execution.error_type or "mcp_error",
                error_message=execution.error_message or execution.error_type or "mcp_error",
                delegator_agent_id=ORCHESTRATOR_AGENT_ID,
            )
            emitter.pipeline_stopped(
                hop_index=1,
                agent_id=GOAL_AGENT_ID,
                stop_reason="error",
                delegator_agent_id=ORCHESTRATOR_AGENT_ID,
            )
        else:
            mcp_completed = True
            outcome = "success"
            payload = execution.payload
            result_text = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            emitter.mcp_completed(
                hop_index=1,
                agent_id=GOAL_AGENT_ID,
                agent_name=GOAL_AGENT_NAME,
                hop_span_id=hop_span_id,
                mcp_span_id=mcp_span_id,
                tool_name=decision.tool_name,
                duration_ms=_duration_ms(exec_started),
                result_text=result_text,
                delegator_agent_id=ORCHESTRATOR_AGENT_ID,
            )
    emitter.hop_completed(
        hop_index=1,
        agent_id=GOAL_AGENT_ID,
        agent_name=GOAL_AGENT_NAME,
        hop_span_id=hop_span_id,
        outcome=hop_outcome,
        duration_ms=_duration_ms(hop_started_at),
        delegator_agent_id=ORCHESTRATOR_AGENT_ID,
    )
    invoked = registry.invoke_counts.get(change.resulting_tool, 0) > counts_before_by_tool.get(
        change.resulting_tool, 0
    )
    return McpHop(
        index=1,
        agent_id=GOAL_AGENT_ID,
        agent_name=GOAL_AGENT_NAME,
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
        delegator_agent_id=ORCHESTRATOR_AGENT_ID,
        handler_invoked=invoked,
        tool_name=decision.tool_name or change.resulting_tool,
        response=payload,
        mcp_error=mcp_error,
    )


def write_goal_specimen_pack(
    *,
    label: str,
    result: GoalIntegrityResult,
    settings: Settings,
) -> Path:
    root = settings.artifacts_dir / f"lab-agent-goal-integrity-001-{label}-{result.run_id}"
    root.mkdir(parents=True, exist_ok=True)
    events_path = root / "events.jsonl"
    with events_path.open("w", encoding="utf-8") as handle:
        for event in result.events:
            handle.write(json.dumps(event, separators=(",", ":")) + "\n")
    request_doc = {
        "task": result.frozen_task.canonical_dict(),
        "instruction": result.frozen_change.canonical_dict() if result.frozen_change is not None else {},
    }
    manifest = {
        "schema.name": SCHEMA_NAME,
        "schema.version": SCHEMA_VERSION,
        "lab.id": settings.lab_id,
        "attack.id": GOAL_ATTACK_ID,
        "label": label,
        "run.id": result.run_id,
        "profile": result.profile,
        "mode": result.testbed_mode,
        "task.id": result.frozen_task.task_id,
        "task.hash": result.task_fingerprint,
        "instruction.hash": result.instruction_hash,
        "goal.proposed": result.proposed_action,
        "goal.proposed.fingerprint": result.proposed_fingerprint,
        "goal.control.decision": result.goal_control_decision,
        "goal.control.reason": result.goal_control_reason,
        "effective.action": result.effective_action,
        "mcp.control.decision": result.follow_on_decision,
        "mcp.control.reason": result.follow_on_reason,
        "mcp.handler.lookup_policy.count": result.lookup_policy_handler_count,
        "mcp.handler.in_task.lookup_policy.count": result.in_task_lookup_policy_count,
        "mcp.handler.wrong_goal.lookup_policy.count": result.wrong_goal_lookup_policy_count,
        "goal.overlay.applied": result.overlay_applied,
        "splunk.verified": False,
        "evidence_dir": result.evidence_dir,
    }
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (root / "request.json").write_text(json.dumps(request_doc, indent=2) + "\n", encoding="utf-8")
    (root / "result.json").write_text(
        json.dumps(
            {
                "run.id": result.run_id,
                "goal.control.decision": result.goal_control_decision,
                "mcp.control.decision": result.follow_on_decision,
                "mcp.control.reason": result.follow_on_reason,
                "effective.action": result.effective_action,
                "handler.lookup_policy.count": result.lookup_policy_handler_count,
                "handler.wrong_goal.count": result.wrong_goal_lookup_policy_count,
                "handler.in_task.count": result.in_task_lookup_policy_count,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (root / "export.json").write_text(
        json.dumps({"splunk.verified": False, "otlp.enabled": False}, indent=2) + "\n",
        encoding="utf-8",
    )
    (root / "limitations.json").write_text(
        json.dumps(
            {
                "splunk.verified": False,
                "llm.planner": "NOT USED",
                "task.authority": "server-owned TaskContract",
                "tool.authority": "CTRL-MCP-001 / coded_policy()",
                "overlay": "LAB-ONLY per-request; not a grant",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return root
