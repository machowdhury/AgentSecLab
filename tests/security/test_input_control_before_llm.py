from agentsec.attacks import ATK_002_PAYLOAD, BENIGN_LOAN
from agentsec.pipeline import run_loan_pipeline


def test_deny_happens_before_any_llm_call(settings, stub_llm, memory):
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
    assert stub_llm.calls == []
    assert result.llm_call_count == 0
    deny_events = [
        event
        for event in result.events
        if event["agentsec.control.decision"] == "DENY"
    ]
    assert deny_events
    for event in deny_events:
        assert event["agentsec.operation.executed"] is False
        assert event["gen_ai.usage.input_tokens"] == 0
        assert event["gen_ai.usage.output_tokens"] == 0


def test_benign_path_does_call_llm(settings, stub_llm, memory):
    result = run_loan_pipeline(
        BENIGN_LOAN,
        llm=stub_llm,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="LIVE",
        attack_id="ATK-001",
    )
    assert len(stub_llm.calls) == 4
    assert result.blocked is False
