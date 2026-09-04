from agentsec.detections import local_q_deny_live, local_q_run


def test_q_run_counts_matching_run():
    events = [
        {"agentsec.run.id": "aaa"},
        {"agentsec.run.id": "bbb"},
        {"agentsec.run.id": "aaa"},
    ]
    result = local_q_run(events, "aaa")
    assert result["matched"] is True
    assert result["event_count"] == 2


def test_q_deny_live_ignores_baseline_and_executed_true():
    events = [
        {
            "event.name": "agentsec.prompt_attack",
            "agentsec.run.id": "r1",
            "gen_ai.agent.id": "acme-agent-intake-001",
            "agentsec.control.reason": "input_pattern_matched",
            "agentsec.control.decision": "DENY",
            "agentsec.operation.executed": False,
            "agentsec.testbed.mode": "LIVE",
        },
        {
            "event.name": "agentsec.control_decision",
            "agentsec.run.id": "r2",
            "gen_ai.agent.id": "acme-agent-intake-001",
            "agentsec.control.reason": "benign_loan_request",
            "agentsec.control.decision": "ALLOW",
            "agentsec.operation.executed": True,
            "agentsec.testbed.mode": "BASELINE",
        },
    ]
    result = local_q_deny_live(events)
    assert result["event_count"] == 1
    assert result["events"][0]["agentsec.run.id"] == "r1"
