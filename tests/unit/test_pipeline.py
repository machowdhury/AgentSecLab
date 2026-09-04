from agentsec.agents import COMPLIANCE_ID, CREDIT_ID, INTAKE_ID, RISK_ID
from agentsec.attacks import ATK_002_PAYLOAD, BENIGN_LOAN
from agentsec.pipeline import run_loan_pipeline


def test_benign_pipeline_runs_four_agents(settings, stub_llm, memory):
    result = run_loan_pipeline(
        BENIGN_LOAN,
        llm=stub_llm,
        sink=memory,
        memory=memory,
        settings=settings,
        user_id="applicant-001",
        testbed_mode="BASELINE",
        attack_id="ATK-001",
    )
    assert result.blocked is False
    assert result.llm_call_count == 4
    assert [hop.agent_id for hop in result.hops] == [
        INTAKE_ID,
        CREDIT_ID,
        RISK_ID,
        COMPLIANCE_ID,
    ]
    assert all(hop.decision == "ALLOW" for hop in result.hops)
    assert all(hop.operation_executed for hop in result.hops)
    run_ids = {event["agentsec.run.id"] for event in result.events}
    assert run_ids == {result.run_id}


def test_injection_stops_before_later_agents(settings, stub_llm, memory):
    result = run_loan_pipeline(
        ATK_002_PAYLOAD,
        llm=stub_llm,
        sink=memory,
        memory=memory,
        settings=settings,
        user_id="attacker-lab",
        testbed_mode="LIVE",
        technique_id="AML.T0054",
        attack_id="ATK-002",
    )
    assert result.blocked is True
    assert result.llm_call_count == 0
    assert len(result.hops) == 1
    assert result.hops[0].agent_id == INTAKE_ID
    assert result.hops[0].decision == "DENY"
    assert result.hops[0].operation_executed is False
    assert stub_llm.calls == []
