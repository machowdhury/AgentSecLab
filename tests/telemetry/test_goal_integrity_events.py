"""LAB-AGENT-GOAL-INTEGRITY-001 event sequence and schema 1.9.0 honesty."""

from agentsec.events import EVENT_CONTROL_DECISION
from agentsec.goal.fixtures import CLOSED_EXPANSION_ACTION, TASK_ID, adversarial_goal_payload, baseline_goal_payload
from agentsec.goal.pipeline import run_goal_integrity
from agentsec.goal.trust import GOAL_CONTROL_ID
from agentsec.mcp.registry import default_registry
from tests.helpers import assert_all_schema_valid, control_events


def test_goal_events_are_schema_valid(settings, memory):
    result = run_goal_integrity(
        payload=baseline_goal_payload(),
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="BASELINE",
        registry=default_registry(),
    )
    assert_all_schema_valid(result.events)
    goal = next(
        event
        for event in control_events(result.events)
        if event.get("agentsec.control.id") == GOAL_CONTROL_ID
    )
    assert goal["event.name"] == EVENT_CONTROL_DECISION
    assert goal["agentsec.schema.version"] == "1.9.0"
    assert goal["agentsec.task.id"] == TASK_ID
    assert goal["agentsec.task.provenance"] == "agentsec.orchestrator.task_contract"
    assert goal["agentsec.instruction.trust"] == "untrusted_instruction"
    assert goal["agentsec.trust_boundary"] == "agent.task.contract"
    assert goal["agentsec.content.influence.kind"] == "untrusted_instruction"
    assert "agentsec.instruction.body" not in goal
    assert "trusted_instruction" not in goal


def test_attack_and_retest_share_hashes_on_events(tmp_path, monkeypatch, settings, memory):
    monkeypatch.setenv("AGENTSEC_OTEL_ENABLED", "false")
    monkeypatch.setenv("AGENTSEC_SECURITY_PROFILE", "vulnerable")
    monkeypatch.setenv("AGENTSEC_ARTIFACTS_DIR", str(tmp_path / "artifacts-goal-events"))
    from agentsec.settings import get_settings, reset_settings_cache

    reset_settings_cache()
    vuln = get_settings()
    from agentsec.telemetry import MemorySink

    vuln_memory = MemorySink()
    attack = run_goal_integrity(
        payload=adversarial_goal_payload(),
        sink=vuln_memory,
        memory=vuln_memory,
        settings=vuln,
        testbed_mode="ATTACK",
        registry=default_registry(),
    )
    retest = run_goal_integrity(
        payload=adversarial_goal_payload(),
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="RETEST",
        registry=default_registry(),
    )
    attack_goal = next(
        event for event in control_events(attack.events) if event.get("agentsec.control.id") == GOAL_CONTROL_ID
    )
    retest_goal = next(
        event for event in control_events(retest.events) if event.get("agentsec.control.id") == GOAL_CONTROL_ID
    )
    assert attack_goal["agentsec.task.hash"] == retest_goal["agentsec.task.hash"]
    assert attack_goal["agentsec.goal.proposed"] == retest_goal["agentsec.goal.proposed"] == CLOSED_EXPANSION_ACTION
    assert attack_goal["agentsec.content.hash"] == retest_goal["agentsec.content.hash"]
    assert attack_goal["agentsec.goal.decision"] == "OBSERVE"
    assert retest_goal["agentsec.goal.decision"] == "DENY"
    assert_all_schema_valid(attack.events)
    assert_all_schema_valid(retest.events)
