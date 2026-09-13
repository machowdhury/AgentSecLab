"""Sequential loan pipeline: input control → maybe Ollama → schema 1.0.0 telemetry → evidence."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable

from agentsec.agents import PIPELINE_ORDER
from agentsec.controls import ControlResult, evaluate_input_control, inspect_input
from agentsec.events import EventEmitter, RunContext, new_span_id
from agentsec.experiment import EXECUTION_MODE, SCHEMA_NAME, SCHEMA_VERSION, TELEMETRY_FIDELITY
from agentsec.evidence import write_evidence_bundle
from agentsec.llm import LLMClient
from agentsec.settings import Settings, get_settings
from agentsec.telemetry import EventSink, MemorySink, flush_export

InspectFn = Callable[[str, str], ControlResult]


@dataclass
class AgentHop:
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
    span_id: str
    delegator_agent_id: str | None
    response: str | None = None
    llm_error: str | None = None


@dataclass
class PipelineResult:
    run_id: str
    incident_id: str
    testbed_mode: str
    execution_mode: str
    telemetry_fidelity: str
    profile: str
    blocked: bool
    block_reason: str | None
    terminal: str
    final_output: str | None
    hops: list[AgentHop]
    events: list[dict]
    evidence_dir: str | None
    llm_call_count: int
    expected_behavior: str
    actual_behavior: str
    attack_id: str
    error_stage: str | None = None


def _handoff_context(user_input: str, previous_name: str, previous_text: str) -> str:
    return (
        f"Previous agent ({previous_name}) output:\n{previous_text}\n\n"
        f"Original request:\n{user_input}"
    )


def _control_invariants(decision: str, hop_index: int) -> list[str]:
    if decision == "DENY":
        return ["INV-008", "INV-007"] if hop_index == 0 else ["INV-008", "INV-002", "INV-007"]
    if decision == "ERROR":
        return ["INV-008", "INV-007"]
    if hop_index == 0:
        return ["INV-004", "INV-007"]
    return ["INV-002", "INV-004", "INV-007"]


def _duration_ms(started: float) -> int:
    return max(0, int((time.monotonic() - started) * 1000))


def run_loan_pipeline(
    user_input: str,
    *,
    llm: LLMClient,
    sink: EventSink,
    memory: MemorySink,
    settings: Settings | None = None,
    user_id: str = "applicant-web",
    testbed_mode: str,
    attack_id: str,
    expected_behavior: str | None = None,
    write_evidence: bool = True,
    inspect_fn: InspectFn = inspect_input,
) -> PipelineResult:
    settings = settings or get_settings()
    started = time.monotonic()
    ctx = RunContext.mint(user_id=user_id, testbed_mode=testbed_mode, attack_id=attack_id)
    emitter = EventEmitter(ctx, sink.emit, settings)
    hops: list[AgentHop] = []
    llm_calls = 0
    blocked = False
    block_reason = None
    error_stage = None
    terminal = "completed_allowed"
    final_output = None
    context = user_input
    expected = expected_behavior or _default_expected(attack_id, settings.security_profile)

    emitter.run_started()

    for index, agent in enumerate(PIPELINE_ORDER):
        hop_started_at = time.monotonic()
        hop_span_id = new_span_id()
        delegator = ctx.last_agent_id if index > 0 else None
        origin_type = "user" if index == 0 else "agent"
        origin_id = ctx.user_id if index == 0 else (ctx.last_agent_id or ctx.user_id)
        influence = "user_message" if index == 0 else "prior_agent_output"
        trust_boundary = "acmebank.http_api" if index == 0 else "acmebank.agent_handoff"

        emitter.hop_started(
            hop_index=index,
            agent_id=agent.agent_id,
            agent_name=agent.name,
            hop_span_id=hop_span_id,
            delegator_agent_id=delegator,
        )

        control = evaluate_input_control(context, settings.security_profile, inspect_fn)
        emitter.control_decision(
            hop_index=index,
            agent_id=agent.agent_id,
            agent_name=agent.name,
            hop_span_id=hop_span_id,
            control_id=control.control_id,
            control_type=control.control_type,
            decision=control.decision,
            reason=control.reason,
            trust_boundary=trust_boundary,
            invariant_ids=_control_invariants(control.decision, index),
            content_text=context if isinstance(context, str) else "",
            origin_type=origin_type,
            origin_id=origin_id,
            influence_kind=influence,
            delegator_agent_id=delegator,
            error_stage=control.error_stage,
        )

        attempted = False
        executed = False
        outcome: str | None = None
        llm_started = False
        llm_completed = False
        llm_failed = False
        response_text = None
        llm_error = None
        hop_outcome = "hop_allowed"

        if control.blocks_llm:
            blocked = True
            block_reason = control.reason
            attempted = False
            executed = False
            outcome = "prevented"
            hop_outcome = "hop_denied" if control.decision == "DENY" else "hop_error"
            error_stage = control.error_stage or (
                "schema_validation" if control.decision == "ERROR" else None
            )
            emitter.pipeline_stopped(
                hop_index=index,
                agent_id=agent.agent_id,
                stop_reason="denied" if control.decision == "DENY" else "error",
                delegator_agent_id=delegator,
            )
        else:
            llm_span_id = new_span_id()
            emitter.llm_started(
                hop_index=index,
                agent_id=agent.agent_id,
                agent_name=agent.name,
                hop_span_id=hop_span_id,
                llm_span_id=llm_span_id,
                delegator_agent_id=delegator,
            )
            llm_started = True
            attempted = True
            executed = True
            result = llm.generate(
                agent_id=agent.agent_id,
                system_prompt=agent.system_prompt,
                user_message=context,
                temperature=agent.temperature,
                max_tokens=agent.max_tokens,
            )
            llm_calls += 1
            if not result.ok:
                blocked = True
                block_reason = result.error_type or "llm_error"
                llm_error = result.error_type
                llm_failed = True
                outcome = "error"
                hop_outcome = "hop_error"
                error_stage = "llm_invocation"
                emitter.llm_failed(
                    hop_index=index,
                    agent_id=agent.agent_id,
                    agent_name=agent.name,
                    hop_span_id=hop_span_id,
                    llm_span_id=llm_span_id,
                    error_type=result.error_type or "llm_error",
                    error_message=result.error_message or result.error_type or "llm_error",
                    delegator_agent_id=delegator,
                )
                emitter.pipeline_stopped(
                    hop_index=index,
                    agent_id=agent.agent_id,
                    stop_reason="error",
                    delegator_agent_id=delegator,
                )
            else:
                llm_completed = True
                outcome = "success"
                response_text = result.text
                duration = max(0, int(result.latency_ms))
                emitter.llm_completed(
                    hop_index=index,
                    agent_id=agent.agent_id,
                    agent_name=agent.name,
                    hop_span_id=hop_span_id,
                    llm_span_id=llm_span_id,
                    duration_ms=duration,
                    input_tokens=result.input_tokens,
                    output_tokens=result.output_tokens,
                    response_model=result.model,
                    delegator_agent_id=delegator,
                )

        hop = AgentHop(
            index=index,
            agent_id=agent.agent_id,
            agent_name=agent.name,
            control_decision=control.decision,
            control_reason=control.reason,
            operation_attempted=attempted,
            operation_executed=executed,
            operation_outcome=outcome,
            llm_started=llm_started,
            llm_completed=llm_completed,
            llm_failed=llm_failed,
            span_id=hop_span_id,
            delegator_agent_id=delegator,
            response=response_text,
            llm_error=llm_error,
        )
        hops.append(hop)
        emitter.hop_completed(
            hop_index=index,
            agent_id=agent.agent_id,
            agent_name=agent.name,
            hop_span_id=hop_span_id,
            outcome=hop_outcome,
            duration_ms=_duration_ms(hop_started_at),
            delegator_agent_id=delegator,
        )
        ctx.last_agent_id = agent.agent_id
        ctx.last_agent_name = agent.name
        ctx.last_hop_span_id = hop_span_id

        if blocked:
            final_output = None
            break

        context = _handoff_context(user_input, agent.name, response_text or "")
        final_output = response_text

    if blocked and hops and hops[-1].control_decision == "DENY":
        terminal = "completed_denied"
        emitter.run_completed(outcome="completed_denied", duration_ms=_duration_ms(started))
        actual = f"DENY at {hops[-1].agent_id}; llm_calls={llm_calls}"
    elif blocked:
        terminal = "run_failed"
        stage = error_stage or "pipeline"
        emitter.run_failed(
            error_type=block_reason or "pipeline_error",
            error_stage=stage,
            error_message=block_reason or "pipeline stopped with error",
        )
        actual = f"ERROR at {hops[-1].agent_id if hops else 'pre-hop'}; llm_calls={llm_calls}"
    else:
        terminal = "completed_allowed"
        emitter.run_completed(outcome="completed_allowed", duration_ms=_duration_ms(started))
        actual = f"ALLOW complete; llm_calls={llm_calls}"

    evidence_dir = None
    events = [event for event in memory.events if event.get("agentsec.run.id") == str(ctx.run_id)]
    export_report = flush_export(sink)
    if write_evidence:
        bundle = write_evidence_bundle(
            run_id=str(ctx.run_id),
            incident_id=ctx.incident_id,
            settings=settings,
            events=events,
            user_input=user_input if isinstance(user_input, str) else "",
            hops=hops,
            testbed_mode=testbed_mode,
            attack_id=attack_id,
            expected_behavior=expected,
            actual_behavior=actual,
            llm_call_count=llm_calls,
            blocked=blocked,
            terminal=terminal,
            export_report=export_report,
        )
        evidence_dir = str(bundle)

    return PipelineResult(
        run_id=str(ctx.run_id),
        incident_id=ctx.incident_id,
        testbed_mode=testbed_mode,
        execution_mode=EXECUTION_MODE,
        telemetry_fidelity=TELEMETRY_FIDELITY,
        profile=settings.security_profile,
        blocked=blocked,
        block_reason=block_reason,
        terminal=terminal,
        final_output=final_output,
        hops=hops,
        events=events,
        evidence_dir=evidence_dir,
        llm_call_count=llm_calls,
        expected_behavior=expected,
        actual_behavior=actual,
        attack_id=attack_id,
        error_stage=error_stage,
    )


def run_schema_failure(
    *,
    llm: LLMClient,
    sink: EventSink,
    memory: MemorySink,
    settings: Settings,
    user_id: str,
    testbed_mode: str,
    attack_id: str,
    error_reason: str,
    extra_fields: tuple[str, ...] = (),
    input_text: str | None = None,
    write_evidence: bool = True,
) -> PipelineResult:
    """Malformed / unknown-field requests: mint ids, emit run.started + run.failed, never call Ollama."""
    del llm
    ctx = RunContext.mint(user_id=user_id, testbed_mode=testbed_mode, attack_id=attack_id)
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
    actual = f"schema_validation ERROR ({error_reason}); llm_calls=0"
    events = [event for event in memory.events if event.get("agentsec.run.id") == str(ctx.run_id)]
    evidence_dir = None
    stored_input = input_text or ""
    export_report = flush_export(sink)
    if write_evidence:
        bundle = write_evidence_bundle(
            run_id=str(ctx.run_id),
            incident_id=ctx.incident_id,
            settings=settings,
            events=events,
            user_input=stored_input,
            hops=[],
            testbed_mode=testbed_mode,
            attack_id=attack_id,
            expected_behavior="ERROR before hops; Ollama never invoked",
            actual_behavior=actual,
            llm_call_count=0,
            blocked=True,
            terminal="run_failed",
            export_report=export_report,
        )
        evidence_dir = str(bundle)
    return PipelineResult(
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
        llm_call_count=0,
        expected_behavior="ERROR before hops; Ollama never invoked",
        actual_behavior=actual,
        attack_id=attack_id,
        error_stage="schema_validation",
    )


def _default_expected(attack_id: str, profile: str) -> str:
    if attack_id == "ATK-002" and profile == "defended":
        return "DENY before LLM; attempted=false, executed=false, outcome=prevented"
    if attack_id == "ATK-002" and profile == "vulnerable":
        return "labeled ALLOW fail-open; LLM may run"
    return "ALLOW four-agent loan pipeline"


def result_to_dict(result: PipelineResult) -> dict[str, Any]:
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
        "llm_call_count": result.llm_call_count,
        "expected_behavior": result.expected_behavior,
        "actual_behavior": result.actual_behavior,
        "attack_id": result.attack_id,
        "evidence_dir": result.evidence_dir,
        "schema_name": SCHEMA_NAME,
        "schema_version": SCHEMA_VERSION,
        "error_stage": result.error_stage,
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
                "llm.started": hop.llm_started,
                "llm.completed": hop.llm_completed,
                "llm.failed": hop.llm_failed,
                "delegator.agent.id": hop.delegator_agent_id,
                "span_id": hop.span_id,
                "llm_error": hop.llm_error,
            }
            for hop in result.hops
        ],
    }
