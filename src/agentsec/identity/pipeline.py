"""Dedicated identity/delegation path: OBSERVE the claim, then CTRL-MCP-001."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from agentsec.events import EventEmitter, RunContext, new_span_id
from agentsec.evidence import write_evidence_bundle
from agentsec.experiment import EXECUTION_MODE, SCHEMA_NAME, SCHEMA_VERSION, TELEMETRY_FIDELITY
from agentsec.identity.fixtures import (
    CALLEE_AGENT_ID,
    CALLEE_AGENT_NAME,
    CALLER_AGENT_ID,
    CLAIM_TRUST,
    IDENTITY_ATTACK_ID,
    IDENTITY_WORKFLOW_ENTRY,
    IDENTITY_WORKFLOW_NAME,
    identity_agent_policy,
)
from agentsec.identity.request import A2ADelegationRequest, parse_a2a_delegation_request
from agentsec.identity.trust import (
    IDENTITY_FAIL_OPEN_REASON,
    IdentityDerivedOverlay,
    IdentityTrustDecision,
    evaluate_identity_claim_safe,
    mint_identity_overlay,
)
from agentsec.mcp.authorize import McpControlResult
from agentsec.mcp.client import McpClient
from agentsec.mcp.pipeline import McpHop
from agentsec.mcp.policy import coded_policy, policy_unchanged_by_identity_claim
from agentsec.mcp.registry import ToolRegistry, default_registry
from agentsec.mcp.server import McpServer
from agentsec.settings import Settings, get_settings
from agentsec.telemetry import EventSink, MemorySink, flush_export

AuthorizeFn = Callable[..., McpControlResult]


@dataclass
class IdentityDelegationResult:
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
    identity_control_decision: str | None
    identity_control_reason: str | None
    claim_trust: str | None
    follow_on_decision: str | None
    follow_on_reason: str | None
    frozen_request: A2ADelegationRequest | None
    request_fingerprint: str | None
    overlay_applied: bool
    overlay_run_id: str | None
    lookup_policy_handler_count: int
    lookup_customer_tier_handler_count: int
    server_owned_allowed_tools: str
    caller_agent_id: str
    callee_agent_id: str
    principal_id: str
    error_stage: str | None = None
    check_use_consistent: bool = False


def _duration_ms(started: float) -> int:
    return max(0, int((time.monotonic() - started) * 1000))


def _identity_invariants(decision: str) -> list[str]:
    if decision == "ERROR":
        return ["INV-001", "INV-002", "INV-005", "INV-008", "INV-007"]
    return ["INV-001", "INV-002", "INV-005", "INV-007"]


def _mcp_invariants(decision: str) -> list[str]:
    if decision == "DENY":
        return ["INV-001", "INV-005", "INV-008", "INV-007"]
    if decision == "ERROR":
        return ["INV-008", "INV-007"]
    return ["INV-001", "INV-004", "INV-005", "INV-007"]


def _expected(profile: str, identity: IdentityTrustDecision, follow_on: str | None, follow_reason: str | None) -> str:
    if identity.decision == "ERROR":
        return "ERROR before follow-on; identity/delegation input is not a grant; handler 0"
    if profile == "vulnerable" and follow_on == "ALLOW":
        return (
            "CTRL-IDENTITY-001 OBSERVE identity_claim_is_not_grant; "
            f"CTRL-MCP-001 ALLOW {IDENTITY_FAIL_OPEN_REASON}; lookup_customer_tier handler 1"
        )
    if follow_on == "DENY":
        return (
            "CTRL-IDENTITY-001 OBSERVE identity_claim_is_not_grant; "
            "CTRL-MCP-001 DENY tool_not_granted; lookup_customer_tier handler 0"
        )
    if follow_on == "ALLOW" and follow_reason == "tool_granted":
        return (
            "CTRL-IDENTITY-001 OBSERVE identity_claim_is_not_grant; "
            "CTRL-MCP-001 ALLOW tool_granted; lookup_policy handler 1; lookup_customer_tier handler 0"
        )
    return (
        "CTRL-IDENTITY-001 OBSERVE identity_claim_is_not_grant; "
        "CTRL-MCP-001 follow-on recorded; identity claim is not a grant"
    )


def run_identity_delegation(
    *,
    payload: object,
    sink: EventSink,
    memory: MemorySink,
    settings: Settings | None = None,
    testbed_mode: str,
    registry: ToolRegistry | None = None,
    authorize_fn: AuthorizeFn | None = None,
    write_evidence: bool = True,
    frozen_request: A2ADelegationRequest | None = None,
) -> IdentityDelegationResult:
    settings = settings or get_settings()
    registry = registry or default_registry()
    parsed = parse_a2a_delegation_request(payload) if frozen_request is None else None
    request = frozen_request
    parse_error = None
    parse_stage = None
    if frozen_request is None:
        assert parsed is not None
        if parsed.ok:
            request = parsed.request
        else:
            parse_error = parsed.error_reason
            parse_stage = parsed.error_stage
            if parsed.extra_fields and parsed.error_reason == "unknown_fields":
                parse_error = f"{parsed.error_reason}:{','.join(parsed.extra_fields)}"

    ctx = RunContext.mint(
        user_id=request.principal_id if request is not None else "unknown",
        testbed_mode=testbed_mode,
        attack_id=IDENTITY_ATTACK_ID,
        workflow_entry=IDENTITY_WORKFLOW_ENTRY,
        workflow_name=IDENTITY_WORKFLOW_NAME,
    )
    emitter = EventEmitter(ctx, sink.emit, settings)
    emitter.run_started()
    run_started_at = time.monotonic()
    identity = evaluate_identity_claim_safe(
        request=request,
        profile=settings.security_profile,
        parse_error=parse_error,
        parse_stage=parse_stage,
    )
    hop_started_at = time.monotonic()
    hop_span_id = new_span_id()
    hop0_agent = CALLEE_AGENT_ID
    hop0_name = CALLEE_AGENT_NAME
    emitter.hop_started(
        hop_index=0,
        agent_id=hop0_agent,
        agent_name=hop0_name,
        hop_span_id=hop_span_id,
        delegator_agent_id=None,
    )
    claim_content = json.dumps(
        request.canonical_dict() if request is not None else {"error": identity.reason},
        sort_keys=True,
        separators=(",", ":"),
    )
    emitter.control_decision(
        hop_index=0,
        agent_id=hop0_agent,
        agent_name=hop0_name,
        hop_span_id=hop_span_id,
        control_id=identity.control_id,
        control_type=identity.control_type,
        decision=identity.decision,
        reason=identity.reason,
        trust_boundary="agent.identity.claim",
        invariant_ids=_identity_invariants(identity.decision),
        content_text=claim_content,
        origin_type="agent",
        origin_id=request.caller_agent_id if request is not None else "unknown",
        influence_kind="tool_request",
        delegator_agent_id=None,
        error_stage=identity.error_stage,
        tool_name=request.requested_tool if request is not None else None,
        requested_scope=request.requested_scope if request is not None else None,
        identity_caller_agent_id=request.caller_agent_id if request is not None else "unknown",
        identity_callee_agent_id=request.callee_agent_id if request is not None else "unknown",
        identity_claim_trust=CLAIM_TRUST,
        claimed_scope=request.claimed_scope if request is not None else "unspecified",
    )
    hops: list[McpHop] = []
    blocked = identity.decision == "ERROR"
    block_reason = identity.reason if blocked else None
    error_stage = identity.error_stage
    hop_outcome = "hop_error" if blocked else "hop_allowed"
    if blocked:
        emitter.pipeline_stopped(
            hop_index=0,
            agent_id=hop0_agent,
            stop_reason="error",
            delegator_agent_id=None,
        )
    hops.append(
        McpHop(
            index=0,
            agent_id=hop0_agent,
            agent_name=hop0_name,
            control_decision=identity.decision,
            control_reason=identity.reason,
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
        agent_id=hop0_agent,
        agent_name=hop0_name,
        hop_span_id=hop_span_id,
        outcome=hop_outcome,
        duration_ms=_duration_ms(hop_started_at),
        delegator_agent_id=None,
    )

    policy = identity_agent_policy(CALLEE_AGENT_ID)
    server = McpServer(registry=registry, policy=policy, authorize_fn=authorize_fn)
    client = McpClient()
    counts_before_by_tool = dict(registry.invoke_counts)
    overlay = None
    overlay_applied = False
    follow_on_decision = None
    follow_on_reason = None
    check_use_consistent = False
    if identity.decision != "ERROR" and identity.request is not None:
        evaluated = identity.request
        overlay = mint_identity_overlay(
            request=evaluated,
            run_id=str(ctx.run_id),
            profile=settings.security_profile,
        )
        overlay_applied = overlay is not None
        if overlay is not None:
            server.identity_derived_overlay = overlay
        hop = _run_follow_on_from_frozen(
            server=server,
            client=client,
            emitter=emitter,
            registry=registry,
            settings=settings,
            request=evaluated,
            overlay=overlay,
            counts_before_by_tool=counts_before_by_tool,
        )
        hops.append(hop)
        follow_on_decision = hop.control_decision
        follow_on_reason = hop.control_reason
        check_use_consistent = hop.tool_name == evaluated.requested_tool and (
            overlay is None or overlay.request_fingerprint == evaluated.fingerprint
        )
        policy_unchanged_by_identity_claim(policy, evaluated)

    lookup_policy_count = registry.invoke_counts.get("lookup_policy", 0) - counts_before_by_tool.get(
        "lookup_policy", 0
    )
    lookup_tier_count = registry.invoke_counts.get("lookup_customer_tier", 0) - counts_before_by_tool.get(
        "lookup_customer_tier", 0
    )
    policy_after = identity_agent_policy(CALLEE_AGENT_ID)
    terminal = "run_failed" if blocked or (hops and hops[-1].operation_outcome == "error") else "run_completed"
    if terminal == "run_failed":
        if not blocked:
            emitter.run_failed(
                error_type=hops[-1].mcp_error or "mcp_error",
                error_stage="mcp_invocation",
                error_message=hops[-1].mcp_error or "handler failed after ALLOW",
            )
        else:
            emitter.run_failed(
                error_type=identity.reason,
                error_stage=identity.error_stage or "schema_validation",
                error_message=identity.reason,
            )
    else:
        outcome = "completed_denied" if follow_on_decision == "DENY" else "completed_allowed"
        if follow_on_decision == "ERROR":
            terminal = "run_failed"
            emitter.run_failed(
                error_type=follow_on_reason or "mcp_error",
                error_stage="control_evaluation",
                error_message=follow_on_reason or "mcp_error",
            )
        else:
            emitter.run_completed(outcome=outcome, duration_ms=_duration_ms(run_started_at))

    expected = _expected(settings.security_profile, identity, follow_on_decision, follow_on_reason)
    actual = (
        f"identity={identity.decision}/{identity.reason}; "
        f"mcp={follow_on_decision}/{follow_on_reason}; "
        f"lookup_policy={lookup_policy_count}; lookup_customer_tier={lookup_tier_count}"
    )
    events = [event for event in memory.events if event.get("agentsec.run.id") == str(ctx.run_id)]
    export_report = flush_export(sink)
    evidence_dir = None
    if write_evidence:
        request_doc = request.canonical_dict() if request is not None else {"error": identity.reason}
        bundle = write_evidence_bundle(
            run_id=str(ctx.run_id),
            incident_id=ctx.incident_id,
            settings=settings,
            events=events,
            user_input=json.dumps(request_doc, sort_keys=True),
            hops=hops,
            testbed_mode=testbed_mode,
            attack_id=IDENTITY_ATTACK_ID,
            expected_behavior=expected,
            actual_behavior=actual,
            llm_call_count=0,
            blocked=blocked or follow_on_decision in ("DENY", "ERROR"),
            terminal=terminal,
            export_report=export_report,
            extra_manifest={
                "workflow.entry": IDENTITY_WORKFLOW_ENTRY,
                "schema.version": SCHEMA_VERSION,
                "principal.id": request.principal_id if request is not None else None,
                "identity.caller_agent_id": request.caller_agent_id if request is not None else None,
                "identity.callee_agent_id": request.callee_agent_id if request is not None else None,
                "identity.claim.trust": CLAIM_TRUST,
                "delegation.claimed_scope": request.claimed_scope if request is not None else None,
                "requested.tool": request.requested_tool if request is not None else None,
                "requested.scope": request.requested_scope if request is not None else None,
                "requested.resource": request.resource if request is not None else None,
                "identity.control.decision": identity.decision,
                "identity.control.reason": identity.reason,
                "mcp.control.decision": follow_on_decision,
                "mcp.control.reason": follow_on_reason,
                "mcp.handler.lookup_policy.count": lookup_policy_count,
                "mcp.handler.lookup_customer_tier.count": lookup_tier_count,
                "identity.overlay.applied": overlay_applied,
                "identity.overlay.run_id": str(ctx.run_id) if overlay_applied else None,
                "server_owned.allowed_tools": ",".join(sorted(policy_after.allowed_tools)),
                "splunk.verified": False,
            },
            request_doc=request_doc,
            extra_result={
                "identity.control.decision": identity.decision,
                "identity.control.reason": identity.reason,
                "mcp.control.decision": follow_on_decision,
                "mcp.control.reason": follow_on_reason,
                "handler.lookup_policy.count": lookup_policy_count,
                "handler.lookup_customer_tier.count": lookup_tier_count,
                "identity.overlay.applied": overlay_applied,
                "check_use_consistent": check_use_consistent,
            },
            limitations_items=[
                "CTRL-IDENTITY-001 classifies identity/delegation claims as data. OBSERVE is not ALLOW and not DENY.",
                "WHO AUTHENTICATED is not modeled. Agent id strings are attribution, not cryptographic proof.",
                "Neither Agent A nor Agent B is coded customer:read or lookup_customer_tier.",
                "Vulnerable caller-identity-derived authority is a per-request overlay. coded_policy() is never mutated.",
                "CTRL-MCP-001 remains the only tool PDP. Identity observation does not mint AllowTicket.",
                "No HTTP A2A, OAuth, OIDC, JWT validation, SPIFFE/SPIRE, or Agent Card service in this slice.",
                "splunk.verified=false. Splunk is not verified in this runtime slice. DET-MCP-001 is unchanged.",
                "Schema 1.9.0 has no session.id, tenant.id, gen_ai.tool.call.id, or token fields.",
                "No Splunk SPL, Dashboard Studio, DET-A2A, DET-DELEGATION, or live A2A transport in this slice.",
            ],
        )
        evidence_dir = str(bundle)

    return IdentityDelegationResult(
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
        attack_id=IDENTITY_ATTACK_ID,
        identity_control_decision=identity.decision,
        identity_control_reason=identity.reason,
        claim_trust=identity.claim_trust,
        follow_on_decision=follow_on_decision,
        follow_on_reason=follow_on_reason,
        frozen_request=request,
        request_fingerprint=request.fingerprint if request is not None else None,
        overlay_applied=overlay_applied,
        overlay_run_id=str(ctx.run_id) if overlay_applied else None,
        lookup_policy_handler_count=lookup_policy_count,
        lookup_customer_tier_handler_count=lookup_tier_count,
        server_owned_allowed_tools=",".join(sorted(policy_after.allowed_tools)),
        caller_agent_id=request.caller_agent_id if request is not None else CALLER_AGENT_ID,
        callee_agent_id=request.callee_agent_id if request is not None else CALLEE_AGENT_ID,
        principal_id=request.principal_id if request is not None else "unknown",
        error_stage=error_stage,
        check_use_consistent=check_use_consistent,
    )


def _run_follow_on_from_frozen(
    *,
    server: McpServer,
    client: McpClient,
    emitter: EventEmitter,
    registry: ToolRegistry,
    settings: Settings,
    request: A2ADelegationRequest,
    overlay: IdentityDerivedOverlay | None,
    counts_before_by_tool: dict[str, int],
) -> McpHop:
    hop_started_at = time.monotonic()
    hop_span_id = new_span_id()
    emitter.hop_started(
        hop_index=1,
        agent_id=CALLEE_AGENT_ID,
        agent_name=CALLEE_AGENT_NAME,
        hop_span_id=hop_span_id,
        delegator_agent_id=CALLER_AGENT_ID,
    )
    rpc = client.tools_call(
        name=request.requested_tool,
        arguments=request.tool_arguments(),
        request_id=2,
    )
    authority_source = "caller-identity-derived overlay" if overlay is not None else "server-owned"
    decision = server.authorize(
        rpc,
        profile=settings.security_profile,
        requested_scope=request.requested_scope,
        coded_agent_id=CALLEE_AGENT_ID,
        identity_derived_overlay=overlay,
    )
    control = decision.control
    content = json.dumps(
        {
            "tool": request.requested_tool,
            "requested_scope": request.requested_scope,
            "resource": request.resource,
            "request_fingerprint": request.fingerprint,
            "server_owned_allowed_tools": ",".join(sorted(server.policy.allowed_tools)),
            "authority_source": authority_source,
        },
        sort_keys=True,
    )
    emitter.control_decision(
        hop_index=1,
        agent_id=CALLEE_AGENT_ID,
        agent_name=CALLEE_AGENT_NAME,
        hop_span_id=hop_span_id,
        control_id=control.control_id,
        control_type=control.control_type,
        decision=control.decision,
        reason=control.reason,
        trust_boundary="acmebank.mcp.authorize",
        invariant_ids=_mcp_invariants(control.decision),
        content_text=content,
        origin_type="agent",
        origin_id=CALLEE_AGENT_ID,
        influence_kind="tool_request",
        delegator_agent_id=CALLER_AGENT_ID,
        error_stage=control.error_stage,
        tool_name=control.tool_name,
        mcp_method="tools/call",
        requested_scope=control.requested_scope,
        allowed_scope=control.allowed_scope,
        resource_id=control.resource_id,
        allowed_resource_ids=control.allowed_resource_ids,
        identity_caller_agent_id=request.caller_agent_id,
        identity_callee_agent_id=request.callee_agent_id,
        claimed_scope=request.claimed_scope,
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
            agent_id=CALLEE_AGENT_ID,
            stop_reason="denied" if control.decision == "DENY" else "error",
            delegator_agent_id=CALLER_AGENT_ID,
        )
    else:
        mcp_span_id = new_span_id()
        exec_started = time.monotonic()
        emitter.mcp_started(
            hop_index=1,
            agent_id=CALLEE_AGENT_ID,
            agent_name=CALLEE_AGENT_NAME,
            hop_span_id=hop_span_id,
            mcp_span_id=mcp_span_id,
            tool_name=decision.tool_name,
            delegator_agent_id=CALLER_AGENT_ID,
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
                agent_id=CALLEE_AGENT_ID,
                agent_name=CALLEE_AGENT_NAME,
                hop_span_id=hop_span_id,
                mcp_span_id=mcp_span_id,
                tool_name=decision.tool_name,
                error_type=execution.error_type or "mcp_error",
                error_message=execution.error_message or execution.error_type or "mcp_error",
                delegator_agent_id=CALLER_AGENT_ID,
            )
            emitter.pipeline_stopped(
                hop_index=1,
                agent_id=CALLEE_AGENT_ID,
                stop_reason="error",
                delegator_agent_id=CALLER_AGENT_ID,
            )
        else:
            mcp_completed = True
            outcome = "success"
            payload = execution.payload
            result_text = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            emitter.mcp_completed(
                hop_index=1,
                agent_id=CALLEE_AGENT_ID,
                agent_name=CALLEE_AGENT_NAME,
                hop_span_id=hop_span_id,
                mcp_span_id=mcp_span_id,
                tool_name=decision.tool_name,
                duration_ms=_duration_ms(exec_started),
                result_text=result_text,
                delegator_agent_id=CALLER_AGENT_ID,
            )
    emitter.hop_completed(
        hop_index=1,
        agent_id=CALLEE_AGENT_ID,
        agent_name=CALLEE_AGENT_NAME,
        hop_span_id=hop_span_id,
        outcome=hop_outcome,
        duration_ms=_duration_ms(hop_started_at),
        delegator_agent_id=CALLER_AGENT_ID,
    )
    invoked = registry.invoke_counts.get(request.requested_tool, 0) > counts_before_by_tool.get(
        request.requested_tool, 0
    )
    return McpHop(
        index=1,
        agent_id=CALLEE_AGENT_ID,
        agent_name=CALLEE_AGENT_NAME,
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
        delegator_agent_id=CALLER_AGENT_ID,
        handler_invoked=invoked,
        tool_name=decision.tool_name or request.requested_tool,
        response=payload,
        mcp_error=mcp_error,
    )


def write_identity_specimen_pack(
    *,
    label: str,
    result: IdentityDelegationResult,
    settings: Settings,
) -> Path:
    root = settings.artifacts_dir / f"lab-agent-delegation-001-{label}-{result.run_id}"
    root.mkdir(parents=True, exist_ok=True)
    events_path = root / "events.jsonl"
    with events_path.open("w", encoding="utf-8") as handle:
        for event in result.events:
            handle.write(json.dumps(event, separators=(",", ":")) + "\n")
    request_doc = result.frozen_request.canonical_dict() if result.frozen_request is not None else {}
    manifest = {
        "schema.name": SCHEMA_NAME,
        "schema.version": SCHEMA_VERSION,
        "lab.id": settings.lab_id,
        "attack.id": IDENTITY_ATTACK_ID,
        "label": label,
        "run.id": result.run_id,
        "profile": result.profile,
        "mode": result.testbed_mode,
        "principal.id": result.principal_id,
        "identity.caller_agent_id": result.caller_agent_id,
        "identity.callee_agent_id": result.callee_agent_id,
        "identity.claim.trust": result.claim_trust,
        "delegation.claimed_scope": (
            result.frozen_request.claimed_scope if result.frozen_request is not None else None
        ),
        "requested.tool": result.frozen_request.requested_tool if result.frozen_request is not None else None,
        "requested.scope": result.frozen_request.requested_scope if result.frozen_request is not None else None,
        "requested.resource": result.frozen_request.resource if result.frozen_request is not None else None,
        "identity.control.decision": result.identity_control_decision,
        "identity.control.reason": result.identity_control_reason,
        "mcp.control.decision": result.follow_on_decision,
        "mcp.control.reason": result.follow_on_reason,
        "mcp.handler.lookup_policy.count": result.lookup_policy_handler_count,
        "mcp.handler.lookup_customer_tier.count": result.lookup_customer_tier_handler_count,
        "identity.overlay.applied": result.overlay_applied,
        "splunk.verified": False,
        "evidence_dir": result.evidence_dir,
    }
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (root / "request.json").write_text(json.dumps(request_doc, indent=2) + "\n", encoding="utf-8")
    (root / "result.json").write_text(
        json.dumps(
            {
                "run.id": result.run_id,
                "identity.control.decision": result.identity_control_decision,
                "mcp.control.decision": result.follow_on_decision,
                "mcp.control.reason": result.follow_on_reason,
                "handler.lookup_policy.count": result.lookup_policy_handler_count,
                "handler.lookup_customer_tier.count": result.lookup_customer_tier_handler_count,
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
                "authenticated": "NOT PROVEN / NOT MODELED",
                "a2a.transport": "NOT IMPLEMENTED",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return root
