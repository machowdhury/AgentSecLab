from agentsec.attacks import ATK_002_PAYLOAD, BENIGN_LOAN
from agentsec.events import EVENT_CONTROL_DECISION, EVENT_LLM_COMPLETED, EVENT_LLM_FAILED, EVENT_LLM_STARTED
from agentsec.pipeline import run_loan_pipeline
from tests.helpers import assert_no_llm_for_hop, control_events, event_names, events_named


def test_deny_happens_before_any_llm_call(settings, counting_llm, memory):
    result = run_loan_pipeline(
        ATK_002_PAYLOAD,
        llm=counting_llm,
        sink=memory,
        memory=memory,
        settings=settings,
        user_id="attacker-lab",
        testbed_mode="RETEST",
        attack_id="ATK-002",
    )
    assert counting_llm.calls == []
    assert counting_llm.call_count == 0
    assert result.llm_call_count == 0
    deny_events = [
        event
        for event in result.events
        if event.get("agentsec.control.decision") == "DENY"
    ]
    assert deny_events
    for event in deny_events:
        assert event["event.name"] == EVENT_CONTROL_DECISION
        assert event["agentsec.control.id"] == "CTRL-INPUT-001"
        assert event["agentsec.operation.attempted"] is False
        assert event["agentsec.operation.executed"] is False
        assert event["agentsec.operation.outcome"] == "prevented"
    names = event_names(result.events)
    assert EVENT_LLM_STARTED not in names
    assert EVENT_LLM_COMPLETED not in names
    assert EVENT_LLM_FAILED not in names
    assert_no_llm_for_hop(result.events, 0)


def test_defended_atk002_negative_contract(settings, counting_llm, memory):
    """Critical negative test: DENY means the LLM client was never called."""
    result = run_loan_pipeline(
        ATK_002_PAYLOAD,
        llm=counting_llm,
        sink=memory,
        memory=memory,
        settings=settings,
        user_id="attacker-lab",
        testbed_mode="RETEST",
        attack_id="ATK-002",
    )
    control = control_events(result.events)[0]
    assert control["agentsec.control.id"] == "CTRL-INPUT-001"
    assert control["agentsec.control.decision"] == "DENY"
    assert control["agentsec.operation.attempted"] is False
    assert control["agentsec.operation.executed"] is False
    assert control["agentsec.operation.outcome"] == "prevented"
    assert events_named(result.events, EVENT_LLM_STARTED) == []
    assert events_named(result.events, EVENT_LLM_COMPLETED) == []
    assert events_named(result.events, EVENT_LLM_FAILED) == []
    assert counting_llm.call_count == 0
    assert counting_llm.calls == []


def test_benign_path_does_call_llm(settings, counting_llm, memory):
    result = run_loan_pipeline(
        BENIGN_LOAN,
        llm=counting_llm,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="BASELINE",
        attack_id="ATK-001",
    )
    assert counting_llm.call_count == 4
    assert result.blocked is False
    assert events_named(result.events, EVENT_LLM_STARTED)
    assert events_named(result.events, EVENT_LLM_COMPLETED)
