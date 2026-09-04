"""Live pipeline events must match the closed security-event schema."""

from agentsec.attacks import ATK_002_PAYLOAD, BENIGN_LOAN
from agentsec.llm import StubLLM
from agentsec.pipeline import run_loan_pipeline
from agentsec.schema import validate_event
from agentsec.telemetry import MemorySink


def test_benign_and_attack_events_validate(settings, stub_llm, memory):
    benign = run_loan_pipeline(
        BENIGN_LOAN,
        llm=stub_llm,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="BASELINE",
        attack_id="ATK-001",
    )
    for event in benign.events:
        validate_event(event)

    attack_memory = MemorySink()
    attack = run_loan_pipeline(
        ATK_002_PAYLOAD,
        llm=StubLLM(),
        sink=attack_memory,
        memory=attack_memory,
        settings=settings,
        user_id="attacker-lab",
        testbed_mode="LIVE",
        technique_id="AML.T0054",
        attack_id="ATK-002",
    )
    for event in attack.events:
        validate_event(event)
    names = {event["event.name"] for event in attack.events}
    assert "agentsec.prompt_attack" in names
    assert "agentsec.control_decision" in names


def test_four_agent_run_shares_ids_and_handoff_parent(settings, stub_llm, memory):
    result = run_loan_pipeline(
        BENIGN_LOAN,
        llm=stub_llm,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="LIVE",
        attack_id="ATK-001",
    )
    activities = [
        event
        for event in result.events
        if event["event.name"] in ("agentsec.normal_request", "agentsec.agent_handoff")
    ]
    assert len(activities) == 4
    assert len({event["agentsec.run.id"] for event in result.events}) == 1
    assert len({event["trace_id"] for event in result.events}) == 1
    assert activities[0]["event.name"] == "agentsec.normal_request"
    assert activities[1]["parent_span_id"] == activities[0]["span_id"]
    assert activities[2]["parent_span_id"] == activities[1]["span_id"]
    assert activities[3]["parent_span_id"] == activities[2]["span_id"]
    assert activities[1]["agentsec.delegator.agent.id"] == activities[0]["gen_ai.agent.id"]
