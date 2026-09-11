from agentsec.attacks import BENIGN_LOAN
from agentsec.events import EVENT_CONTROL_DECISION, EVENT_LLM_STARTED
from agentsec.pipeline import run_loan_pipeline
from tests.helpers import assert_no_llm_for_hop, control_events, event_names


def exploding_inspect(text: str, profile: str):
    raise RuntimeError("injected control evaluation failure")


def test_control_evaluation_failure_fail_closed(settings, counting_llm, memory):
    result = run_loan_pipeline(
        BENIGN_LOAN,
        llm=counting_llm,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="BASELINE",
        attack_id="ATK-001",
        inspect_fn=exploding_inspect,
    )
    assert result.terminal == "run_failed"
    assert result.error_stage == "control_evaluation"
    assert counting_llm.call_count == 0
    assert counting_llm.calls == []
    control = control_events(result.events)[0]
    assert control["event.name"] == EVENT_CONTROL_DECISION
    assert control["agentsec.control.decision"] == "ERROR"
    assert control["agentsec.operation.attempted"] is False
    assert control["agentsec.operation.executed"] is False
    assert control["agentsec.operation.outcome"] == "prevented"
    assert control["agentsec.error.stage"] == "control_evaluation"
    assert "control_evaluation_failure" in control["agentsec.control.reason"]
    assert EVENT_LLM_STARTED not in event_names(result.events)
    assert_no_llm_for_hop(result.events, 0)
    assert result.hops[0].control_decision != "DENY"
