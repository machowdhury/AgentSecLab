from agentsec.attacks import ATK_002_PAYLOAD, BENIGN_LOAN
from agentsec.pipeline import run_loan_pipeline
from tests.helpers import assert_correlation, assert_sequence_ordering, hop_events


def test_incident_id_equals_run_id_on_every_event(settings, counting_llm, memory):
    result = run_loan_pipeline(
        BENIGN_LOAN,
        llm=counting_llm,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="BASELINE",
        attack_id="ATK-001",
    )
    assert result.incident_id == result.run_id
    assert_correlation(result.events, result.run_id)


def test_sequence_is_unique_and_increasing(settings, counting_llm, memory):
    result = run_loan_pipeline(
        ATK_002_PAYLOAD,
        llm=counting_llm,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="ATTACK",
        attack_id="ATK-002",
    )
    assert_sequence_ordering(result.events)


def test_delegator_absent_on_hop_zero_required_later(settings, counting_llm, memory):
    result = run_loan_pipeline(
        BENIGN_LOAN,
        llm=counting_llm,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="BASELINE",
        attack_id="ATK-001",
    )
    for event in hop_events(result.events, 0):
        assert "agentsec.delegator.agent.id" not in event
    for hop_index in (1, 2, 3):
        rows = hop_events(result.events, hop_index)
        assert rows
        for event in rows:
            assert event["agentsec.delegator.agent.id"]
