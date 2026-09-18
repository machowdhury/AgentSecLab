from agentsec.events import EVENT_CONTROL_DECISION, EVENT_MCP_COMPLETED, EVENT_MCP_STARTED, EVENT_PIPELINE_STOPPED
from agentsec.mcp.authorize import MCP004_FAIL_OPEN_REASON
from agentsec.mcp.fixtures import (
    MCP_LOOKUP_POLICY_ARGS,
    MCP_LOOKUP_POLICY_RESTRICTED_ARGS,
    MCP_POLICY_SCOPE,
    MCP_POLICY_UNKNOWN_ID,
)
from agentsec.mcp.pipeline import run_mcp_invoke
from agentsec.mcp.registry import default_registry
from agentsec.settings import reset_settings_cache
from agentsec.telemetry import MemorySink
from tests.helpers import assert_all_schema_valid, assert_correlation, assert_sequence_ordering, event_names, events_named


def test_mcp004_baseline_attack_retest_sequences(settings, memory, tmp_path, monkeypatch):
    baseline = run_mcp_invoke(
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_ARGS,
        requested_scope=MCP_POLICY_SCOPE,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="BASELINE",
        attack_id="MCP-004",
        registry=default_registry(),
    )
    assert_all_schema_valid(baseline.events)
    assert_correlation(baseline.events, baseline.run_id, workflow_entry="/mcp/invoke")
    assert_sequence_ordering(baseline.events)
    names = event_names(baseline.events)
    assert names.index(EVENT_CONTROL_DECISION) < names.index(EVENT_MCP_STARTED)
    assert EVENT_MCP_COMPLETED in names
    allow = events_named(baseline.events, EVENT_CONTROL_DECISION)[0]
    assert allow["agentsec.schema.version"] == "1.7.0"
    assert allow["agentsec.mcp.resource.id"] == "lending-basics"
    assert allow["agentsec.mcp.allowed_resource.ids"] == "lending-basics"
    assert allow["agentsec.operation.attempted"] is False
    assert allow["agentsec.operation.executed"] is False
    assert "agentsec.operation.outcome" not in allow
    started = events_named(baseline.events, EVENT_MCP_STARTED)[0]
    assert started["agentsec.operation.attempted"] is True
    assert started["agentsec.operation.executed"] is True
    assert "gen_ai.tool.call.arguments" not in allow

    monkeypatch.setenv("AGENTSEC_OTEL_ENABLED", "false")
    monkeypatch.setenv("AGENTSEC_SECURITY_PROFILE", "vulnerable")
    monkeypatch.setenv("AGENTSEC_ARTIFACTS_DIR", str(tmp_path / "artifacts-attack"))
    reset_settings_cache()
    from agentsec.settings import get_settings

    attack_settings = get_settings()
    attack_memory = MemorySink()
    attack = run_mcp_invoke(
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_RESTRICTED_ARGS,
        requested_scope=MCP_POLICY_SCOPE,
        sink=attack_memory,
        memory=attack_memory,
        settings=attack_settings,
        testbed_mode="ATTACK",
        attack_id="MCP-004",
        registry=default_registry(),
    )
    assert_all_schema_valid(attack.events)
    fail_open = events_named(attack.events, EVENT_CONTROL_DECISION)[0]
    assert fail_open["agentsec.control.reason"] == MCP004_FAIL_OPEN_REASON
    assert fail_open["agentsec.mcp.resource.id"] == "executive-restricted"
    assert fail_open["agentsec.mcp.allowed_resource.ids"] == "lending-basics"
    reset_settings_cache()

    retest_memory = MemorySink()
    retest = run_mcp_invoke(
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_RESTRICTED_ARGS,
        requested_scope=MCP_POLICY_SCOPE,
        sink=retest_memory,
        memory=retest_memory,
        settings=settings,
        testbed_mode="RETEST",
        attack_id="MCP-004",
        registry=default_registry(),
    )
    assert_all_schema_valid(retest.events)
    retest_names = event_names(retest.events)
    assert EVENT_MCP_STARTED not in retest_names
    assert EVENT_PIPELINE_STOPPED in retest_names
    deny = events_named(retest.events, EVENT_CONTROL_DECISION)[0]
    assert deny["agentsec.control.decision"] == "DENY"
    assert deny["agentsec.control.reason"] == "resource_not_granted"
    assert deny["agentsec.mcp.resource.id"] == "executive-restricted"
    assert deny["agentsec.mcp.allowed_resource.ids"] == "lending-basics"
    assert deny["agentsec.operation.outcome"] == "prevented"
    assert deny["agentsec.schema.version"] == "1.7.0"


def test_unknown_resource_telemetry(settings, memory):
    result = run_mcp_invoke(
        tool="lookup_policy",
        arguments={"policy_id": MCP_POLICY_UNKNOWN_ID},
        requested_scope=MCP_POLICY_SCOPE,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="ATTACK",
        attack_id="MCP-004",
        registry=default_registry(),
    )
    assert_all_schema_valid(result.events)
    error = events_named(result.events, EVENT_CONTROL_DECISION)[0]
    assert error["agentsec.control.decision"] == "ERROR"
    assert error["agentsec.control.reason"] == "unknown_resource"
    assert error["agentsec.mcp.resource.id"] == MCP_POLICY_UNKNOWN_ID
    assert error["agentsec.mcp.allowed_resource.ids"] == "lending-basics"
    assert error["agentsec.operation.outcome"] == "prevented"
    assert EVENT_MCP_STARTED not in event_names(result.events)
