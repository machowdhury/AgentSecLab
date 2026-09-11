"""Live pipeline events must match schema 1.0.0 and first-lab sequences."""

from agentsec.attacks import ATK_002_PAYLOAD, BENIGN_LOAN
from agentsec.events import (
    EVENT_CONTROL_DECISION,
    EVENT_HOP_COMPLETED,
    EVENT_HOP_STARTED,
    EVENT_LLM_COMPLETED,
    EVENT_LLM_STARTED,
    EVENT_PIPELINE_STOPPED,
    EVENT_RUN_COMPLETED,
    EVENT_RUN_STARTED,
)
from agentsec.llm import StubLLM
from agentsec.pipeline import run_loan_pipeline
from agentsec.telemetry import MemorySink
from tests.helpers import (
    PREDECESSOR_EVENT_NAMES,
    assert_all_schema_valid,
    assert_correlation,
    assert_no_llm_for_hop,
    assert_sequence_ordering,
    event_names,
    events_named,
    hop_events,
)


def test_benign_and_attack_events_validate(settings, counting_llm, memory):
    benign = run_loan_pipeline(
        BENIGN_LOAN,
        llm=counting_llm,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="BASELINE",
        attack_id="ATK-001",
    )
    assert_all_schema_valid(benign.events)
    names = set(event_names(benign.events))
    assert EVENT_RUN_STARTED in names
    assert EVENT_RUN_COMPLETED in names
    assert EVENT_CONTROL_DECISION in names
    assert EVENT_LLM_STARTED in names
    assert names.isdisjoint(PREDECESSOR_EVENT_NAMES)

    attack_memory = MemorySink()
    attack_llm = StubLLM()
    attack = run_loan_pipeline(
        ATK_002_PAYLOAD,
        llm=attack_llm,
        sink=attack_memory,
        memory=attack_memory,
        settings=settings,
        user_id="attacker-lab",
        testbed_mode="ATTACK",
        attack_id="ATK-002",
    )
    assert_all_schema_valid(attack.events)
    attack_names = set(event_names(attack.events))
    assert EVENT_CONTROL_DECISION in attack_names
    assert "agentsec.prompt_attack" not in attack_names
    assert EVENT_PIPELINE_STOPPED in attack_names
    assert_no_llm_for_hop(attack.events, 0)


def test_four_agent_run_shares_ids_sequence_and_delegator(settings, counting_llm, memory):
    result = run_loan_pipeline(
        BENIGN_LOAN,
        llm=counting_llm,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="BASELINE",
        attack_id="ATK-001",
    )
    assert_correlation(result.events, result.run_id)
    assert_sequence_ordering(result.events)
    assert len({event["trace_id"] for event in result.events}) == 1

    started = events_named(result.events, EVENT_HOP_STARTED)
    assert len(started) == 4
    assert "agentsec.delegator.agent.id" not in started[0]
    assert started[1]["agentsec.delegator.agent.id"] == started[0]["gen_ai.agent.id"]
    assert started[2]["agentsec.delegator.agent.id"] == started[1]["gen_ai.agent.id"]
    assert started[3]["agentsec.delegator.agent.id"] == started[2]["gen_ai.agent.id"]

    for event in hop_events(result.events, 0):
        assert "agentsec.delegator.agent.id" not in event
    for hop_index in (1, 2, 3):
        for event in hop_events(result.events, hop_index):
            assert event["agentsec.delegator.agent.id"]

    allow = [
        event
        for event in events_named(result.events, EVENT_CONTROL_DECISION)
        if event["agentsec.control.decision"] == "ALLOW"
    ]
    for event in allow:
        assert event["agentsec.operation.attempted"] is False
        assert event["agentsec.operation.executed"] is False
        assert "agentsec.operation.outcome" not in event

    for event in events_named(result.events, EVENT_LLM_STARTED):
        assert event["agentsec.operation.attempted"] is True
        assert event["agentsec.operation.executed"] is True
        assert "agentsec.operation.outcome" not in event
    for event in events_named(result.events, EVENT_LLM_COMPLETED):
        assert event["agentsec.operation.outcome"] == "success"

    completed = events_named(result.events, EVENT_HOP_COMPLETED)
    assert [event["parent_span_id"] for event in started] == [result.events[0]["span_id"]] * 4
    assert all(event["agentsec.outcome"] == "hop_allowed" for event in completed)
