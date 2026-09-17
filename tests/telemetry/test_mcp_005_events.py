from agentsec.events import (
    EVENT_CONTROL_DECISION,
    EVENT_MCP_COMPLETED,
    EVENT_MCP_STARTED,
    EVENT_PIPELINE_STOPPED,
)
from agentsec.mcp.fixtures import MCP_LOOKUP_POLICY_ARGS, MCP_POLICY_SCOPE
from agentsec.mcp.pipeline import run_mcp_invoke
from agentsec.mcp.registry import default_registry
from agentsec.mcp.result_trust import RESULT_IS_DATA_REASON
from agentsec.settings import reset_settings_cache
from agentsec.telemetry import MemorySink
from tests.helpers import (
    assert_all_schema_valid,
    assert_correlation,
    assert_sequence_ordering,
    control_events,
    event_names,
    events_named,
)


def _run(settings, memory, *, mode, profile_settings=None, registry=None):
    return run_mcp_invoke(
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_ARGS,
        requested_scope=MCP_POLICY_SCOPE,
        sink=memory,
        memory=memory,
        settings=profile_settings or settings,
        testbed_mode=mode,
        attack_id="MCP-005",
        registry=registry or default_registry(),
    )


def test_mcp005_baseline_attack_retest_sequences(settings, memory, tmp_path, monkeypatch):
    baseline = _run(settings, memory, mode="BASELINE")
    assert_all_schema_valid(baseline.events)
    assert_correlation(baseline.events, baseline.run_id, workflow_entry="/mcp/invoke")
    assert_sequence_ordering(baseline.events)
    names = event_names(baseline.events)
    first_ctrl = events_named(baseline.events, EVENT_CONTROL_DECISION)[0]
    assert first_ctrl["agentsec.control.id"] == "CTRL-MCP-001"
    assert names.index(EVENT_CONTROL_DECISION) < names.index(EVENT_MCP_STARTED)
    assert EVENT_MCP_COMPLETED in names
    result_ctrl = next(e for e in control_events(baseline.events) if e["agentsec.control.id"] == "CTRL-MCP-RESULT-001")
    assert result_ctrl["agentsec.schema.version"] == "1.6.0"
    assert result_ctrl["agentsec.control.decision"] == "OBSERVE"
    assert result_ctrl["agentsec.control.reason"] == RESULT_IS_DATA_REASON
    assert result_ctrl["agentsec.operation.attempted"] is False
    assert result_ctrl["agentsec.operation.executed"] is False
    assert "agentsec.operation.outcome" not in result_ctrl
    assert "agentsec.mcp.result.trust" not in result_ctrl
    completed = events_named(baseline.events, EVENT_MCP_COMPLETED)[0]
    assert completed["agentsec.mcp.result.trust"] == "untrusted_data"
    assert completed["agentsec.mcp.result.provenance"] == "mcp.tool.handler"
    assert len(completed["agentsec.content.preview"]) <= 200
    assert "SECURITY_OVERRIDE" not in completed["agentsec.content.preview"]
    assert names.count(EVENT_MCP_STARTED) == 1

    monkeypatch.setenv("AGENTSEC_OTEL_ENABLED", "false")
    monkeypatch.setenv("AGENTSEC_SECURITY_PROFILE", "vulnerable")
    monkeypatch.setenv("AGENTSEC_ARTIFACTS_DIR", str(tmp_path / "artifacts-attack"))
    reset_settings_cache()
    from agentsec.settings import get_settings

    attack = _run(get_settings(), MemorySink(), mode="ATTACK")
    assert_all_schema_valid(attack.events)
    assert_sequence_ordering(attack.events)
    tools_started = [e["gen_ai.tool.name"] for e in events_named(attack.events, EVENT_MCP_STARTED)]
    assert tools_started == ["lookup_policy", "lookup_customer_tier"]
    follow = next(
        e
        for e in control_events(attack.events)
        if e["agentsec.control.id"] == "CTRL-MCP-001" and e["gen_ai.tool.name"] == "lookup_customer_tier"
    )
    assert follow["agentsec.control.reason"] == "vulnerable_profile_fail_open:result_derived_grant"
    attack_completed = events_named(attack.events, EVENT_MCP_COMPLETED)
    preview = attack_completed[0]["agentsec.content.preview"]
    assert "SECURITY_OVERRIDE" in preview
    assert "lookup_customer_tier" in preview
    assert len(preview) <= 200
    reset_settings_cache()

    retest = _run(settings, MemorySink(), mode="RETEST")
    assert_all_schema_valid(retest.events)
    assert_sequence_ordering(retest.events)
    deny = next(
        e
        for e in control_events(retest.events)
        if e["agentsec.control.id"] == "CTRL-MCP-001" and e["gen_ai.tool.name"] == "lookup_customer_tier"
    )
    assert deny["agentsec.control.decision"] == "DENY"
    assert deny["agentsec.control.reason"] == "tool_not_granted"
    assert deny["agentsec.operation.attempted"] is False
    assert deny["agentsec.operation.executed"] is False
    assert deny["agentsec.operation.outcome"] == "prevented"
    assert EVENT_PIPELINE_STOPPED in event_names(retest.events)
    assert [e["gen_ai.tool.name"] for e in events_named(retest.events, EVENT_MCP_STARTED)] == ["lookup_policy"]


def test_same_tool_twice_would_be_sequence_only(settings, memory):
    """Honest limitation: schema 1.4.0 still has no gen_ai.tool.call.id.

    This lab uses two different tool names. Same-tool twice is ordered by
    agentsec.sequence only — not a stable call identity.
    """
    result = _run(settings, memory, mode="RETEST")
    tools = [e.get("gen_ai.tool.name") for e in result.events if e.get("gen_ai.tool.name")]
    assert "lookup_policy" in tools
    assert "lookup_customer_tier" in tools
    for event in result.events:
        assert "gen_ai.tool.call.id" not in event
    sequences = [e["agentsec.sequence"] for e in result.events]
    assert sequences == sorted(sequences)
    assert len(set(sequences)) == len(sequences)
