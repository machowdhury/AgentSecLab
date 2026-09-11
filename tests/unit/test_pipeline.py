from agentsec.agents import COMPLIANCE_ID, CREDIT_ID, INTAKE_ID, RISK_ID
from agentsec.attacks import ATK_002_PAYLOAD, BENIGN_LOAN
from agentsec.events import EVENT_LLM_STARTED
from agentsec.pipeline import run_loan_pipeline
from tests.helpers import (
    assert_all_schema_valid,
    assert_correlation,
    assert_no_llm_for_hop,
    assert_sequence_ordering,
    control_events,
    event_names,
)


def test_benign_pipeline_runs_four_agents(settings, counting_llm, memory):
    result = run_loan_pipeline(
        BENIGN_LOAN,
        llm=counting_llm,
        sink=memory,
        memory=memory,
        settings=settings,
        user_id="applicant-001",
        testbed_mode="BASELINE",
        attack_id="ATK-001",
    )
    assert result.blocked is False
    assert result.terminal == "completed_allowed"
    assert result.llm_call_count == 4
    assert counting_llm.call_count == 4
    assert [hop.agent_id for hop in result.hops] == [
        INTAKE_ID,
        CREDIT_ID,
        RISK_ID,
        COMPLIANCE_ID,
    ]
    assert all(hop.control_decision == "ALLOW" for hop in result.hops)
    assert all(hop.operation_attempted is True for hop in result.hops)
    assert all(hop.operation_executed is True for hop in result.hops)
    assert all(hop.operation_outcome == "success" for hop in result.hops)
    assert result.testbed_mode == "BASELINE"
    assert result.execution_mode == "LIVE"
    assert result.telemetry_fidelity == "OBSERVED"
    assert_all_schema_valid(result.events)
    assert_correlation(result.events, result.run_id)
    assert_sequence_ordering(result.events)
    assert EVENT_LLM_STARTED in event_names(result.events)
    assert "agentsec.pipeline.stopped" not in event_names(result.events)


def test_injection_stops_before_later_agents(settings, counting_llm, memory):
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
    assert result.blocked is True
    assert result.terminal == "completed_denied"
    assert result.llm_call_count == 0
    assert counting_llm.call_count == 0
    assert counting_llm.calls == []
    assert len(result.hops) == 1
    assert result.hops[0].agent_id == INTAKE_ID
    assert result.hops[0].control_decision == "DENY"
    assert result.hops[0].operation_attempted is False
    assert result.hops[0].operation_executed is False
    assert result.hops[0].operation_outcome == "prevented"
    assert_no_llm_for_hop(result.events, 0)
    decisions = control_events(result.events)
    assert decisions[0]["agentsec.control.decision"] == "DENY"
    assert "agentsec.pipeline.stopped" in event_names(result.events)


def test_empty_input_errors_without_llm(settings, counting_llm, memory):
    result = run_loan_pipeline(
        "   ",
        llm=counting_llm,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="BASELINE",
        attack_id="ATK-001",
    )
    assert result.terminal == "run_failed"
    assert result.hops[0].control_decision == "ERROR"
    assert result.hops[0].operation_attempted is False
    assert result.hops[0].operation_executed is False
    assert result.hops[0].operation_outcome == "prevented"
    assert counting_llm.call_count == 0
    assert_no_llm_for_hop(result.events, 0)
