"""Sequential loan pipeline: input control → maybe Ollama → telemetry → evidence."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agentsec.agents import PIPELINE_ORDER
from agentsec.controls import CONTROL_ID, ControlResult, inspect_input
from agentsec.events import EventBuilder, RunContext, new_span_id
from agentsec.evidence import write_evidence_bundle
from agentsec.llm import LLMClient
from agentsec.settings import Settings, get_settings
from agentsec.telemetry import EventSink, MemorySink

@dataclass
class AgentHop:
    agent_id: str
    agent_name: str
    decision: str
    reason: str
    operation_executed: bool
    response: str | None
    span_id: str
    llm_error: str | None = None


@dataclass
class PipelineResult:
    run_id: str
    testbed_mode: str
    profile: str
    blocked: bool
    block_reason: str | None
    final_output: str | None
    hops: list[AgentHop]
    events: list[dict]
    evidence_dir: str | None
    llm_call_count: int
    expected_behavior: str
    actual_behavior: str
    attack_id: str | None = None


def _handoff_context(user_input: str, previous_name: str, previous_text: str) -> str:
    return (
        f"Previous agent ({previous_name}) output:\n{previous_text}\n\n"
        f"Original request:\n{user_input}"
    )


def _activity_event_name(
    *,
    hop_index: int,
    decision: str,
    matched_rule: str | None,
    testbed_mode: str,
) -> str:
    if matched_rule:
        return "agentsec.prompt_attack"
    if hop_index == 0:
        return "agentsec.normal_request"
    return "agentsec.agent_handoff"


def run_loan_pipeline(
    user_input: str,
    *,
    llm: LLMClient,
    sink: EventSink,
    memory: MemorySink,
    settings: Settings | None = None,
    user_id: str = "applicant-web",
    testbed_mode: str = "LIVE",
    technique_id: str | None = None,
    attack_id: str | None = None,
    expected_behavior: str | None = None,
    write_evidence: bool = True,
) -> PipelineResult:
    settings = settings or get_settings()
    if testbed_mode not in ("LIVE", "BASELINE"):
        testbed_mode = "LIVE"

    ctx = RunContext.mint(
        user_id=user_id,
        testbed_mode=testbed_mode,
        technique_id=technique_id,
    )
    builder = EventBuilder(ctx, settings)
    hops: list[AgentHop] = []
    llm_calls = 0
    blocked = False
    block_reason = None
    final_output = None
    context = user_input
    expected = expected_behavior or (
        "DENY before LLM"
        if attack_id == "ATK-002" and settings.security_profile == "defended"
        else "ALLOW four-agent loan pipeline"
    )

    for index, agent in enumerate(PIPELINE_ORDER):
        control = inspect_input(context, settings.security_profile)
        span_id = new_span_id()
        parent = ctx.last_span_id
        executed = False
        response_text = None
        llm_error = None
        tokens_in = 0
        tokens_out = 0
        response_model = None
        error_type = None

        if control.blocks_llm:
            blocked = True
            block_reason = control.reason
        else:
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
                error_type = result.error_type
                control = ControlResult(
                    control_id=CONTROL_ID,
                    decision="ERROR",
                    reason=result.error_type or "llm_error",
                    matched_rule=control.matched_rule,
                    profile=settings.security_profile,
                )
            else:
                executed = True
                response_text = result.text
                tokens_in = result.input_tokens
                tokens_out = result.output_tokens
                response_model = result.model

        decision = control.decision
        if decision == "DENY":
            executed = False

        invariants = ["INV-008", "INV-007"] if decision == "DENY" else ["INV-004", "INV-007"]
        if index > 0:
            invariants = ["INV-002", "INV-006", "INV-007"]
            if decision == "DENY":
                invariants = ["INV-008", "INV-002", "INV-007"]

        activity_name = _activity_event_name(
            hop_index=index,
            decision=decision,
            matched_rule=control.matched_rule,
            testbed_mode=testbed_mode,
        )
        if activity_name == "agentsec.prompt_attack" and not ctx.technique_id:
            ctx.technique_id = "AML.T0054"

        origin_type = "user" if index == 0 else "agent"
        origin_id = ctx.user_id if index == 0 else ctx.last_agent_id
        influence = "user_message" if index == 0 else "prior_agent_output"
        delegator = ctx.last_agent_id if index > 0 else None

        control_event = builder.build(
            event_name="agentsec.control_decision",
            agent_id=agent.agent_id,
            agent_name=agent.name,
            agent_description=agent.description,
            operation_name="chat",
            trust_boundary=agent.trust_boundary,
            invariant_ids=["INV-008"] if decision in ("DENY", "ERROR") else ["INV-007"],
            control_id=control.control_id,
            decision=decision,
            reason=control.reason,
            operation_executed=executed,
            span_id=new_span_id(),
            parent_span_id=span_id,
            scope_requested=agent.scope,
            scope_allowed=agent.scope if decision != "DENY" else agent.scope,
            influence_kind=influence,
            origin_type=origin_type,
            origin_id=origin_id or ctx.user_id,
            content_text=context,
            delegator_agent_id=delegator,
            input_tokens=tokens_in,
            output_tokens=tokens_out,
            response_model=response_model,
            error_type=error_type,
        )
        sink.emit(control_event)

        activity = builder.build(
            event_name=activity_name,
            agent_id=agent.agent_id,
            agent_name=agent.name,
            agent_description=agent.description,
            operation_name="chat" if index == 0 else "invoke_agent",
            trust_boundary=agent.trust_boundary,
            invariant_ids=invariants,
            control_id=control.control_id,
            decision=decision,
            reason=control.reason,
            operation_executed=executed,
            span_id=span_id,
            parent_span_id=parent if activity_name == "agentsec.agent_handoff" or parent else parent,
            scope_requested=agent.scope,
            scope_allowed=agent.scope,
            influence_kind=influence,
            origin_type=origin_type,
            origin_id=origin_id or ctx.user_id,
            content_text=context,
            delegator_agent_id=delegator,
            input_tokens=tokens_in,
            output_tokens=tokens_out,
            response_model=response_model if executed else None,
            error_type=error_type,
        )
        # agent_handoff requires parent_span_id
        if activity_name == "agentsec.agent_handoff" and not parent:
            raise RuntimeError("handoff missing parent span")
        sink.emit(activity)

        hop = AgentHop(
            agent_id=agent.agent_id,
            agent_name=agent.name,
            decision=decision,
            reason=control.reason,
            operation_executed=executed,
            response=response_text,
            span_id=span_id,
            llm_error=llm_error or error_type,
        )
        hops.append(hop)
        ctx.last_span_id = span_id
        ctx.last_agent_id = agent.agent_id
        ctx.last_agent_name = agent.name

        if blocked:
            final_output = None
            break

        context = _handoff_context(user_input, agent.name, response_text or "")
        final_output = response_text

    if blocked:
        actual = f"{hops[-1].decision} at {hops[-1].agent_id}; llm_calls={llm_calls}"
    else:
        actual = f"ALLOW complete; llm_calls={llm_calls}"

    evidence_dir = None
    if write_evidence:
        bundle = write_evidence_bundle(
            run_id=str(ctx.run_id),
            settings=settings,
            events=list(memory.events),
            user_input=user_input,
            hops=hops,
            testbed_mode=testbed_mode,
            attack_id=attack_id,
            expected_behavior=expected,
            actual_behavior=actual,
            llm_call_count=llm_calls,
            blocked=blocked,
        )
        evidence_dir = str(bundle)

    return PipelineResult(
        run_id=str(ctx.run_id),
        testbed_mode=testbed_mode,
        profile=settings.security_profile,
        blocked=blocked,
        block_reason=block_reason,
        final_output=final_output,
        hops=hops,
        events=list(memory.events),
        evidence_dir=evidence_dir,
        llm_call_count=llm_calls,
        expected_behavior=expected,
        actual_behavior=actual,
        attack_id=attack_id,
    )


def result_to_dict(result: PipelineResult) -> dict[str, Any]:
    return {
        "run_id": result.run_id,
        "testbed_mode": result.testbed_mode,
        "profile": result.profile,
        "blocked": result.blocked,
        "block_reason": result.block_reason,
        "final_output": result.final_output,
        "llm_call_count": result.llm_call_count,
        "expected_behavior": result.expected_behavior,
        "actual_behavior": result.actual_behavior,
        "attack_id": result.attack_id,
        "evidence_dir": result.evidence_dir,
        "hops": [
            {
                "agent_id": hop.agent_id,
                "agent_name": hop.agent_name,
                "decision": hop.decision,
                "reason": hop.reason,
                "operation_executed": hop.operation_executed,
                "response": hop.response,
                "span_id": hop.span_id,
                "llm_error": hop.llm_error,
            }
            for hop in result.hops
        ],
    }
