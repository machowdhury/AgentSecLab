from agentsec.events import (
    EVENT_CONTROL_DECISION,
    EVENT_MCP_COMPLETED,
    EVENT_MCP_STARTED,
    EVENT_PIPELINE_STOPPED,
)
from agentsec.mcp.authorize import MCP003_FAIL_OPEN_REASON
from agentsec.mcp.fixtures import MCP_LOOKUP_POLICY_ARGS, MCP_POLICY_RESTRICTED_SCOPE, MCP_POLICY_SCOPE
from agentsec.mcp.pipeline import run_mcp_invoke
from agentsec.mcp.registry import default_registry
from agentsec.settings import reset_settings_cache
from agentsec.telemetry import MemorySink
from tests.helpers import assert_all_schema_valid, assert_correlation, assert_sequence_ordering, event_names, events_named


def test_mcp003_baseline_attack_retest_sequences(settings, memory, tmp_path, monkeypatch):
    baseline = run_mcp_invoke(
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_ARGS,
        requested_scope=MCP_POLICY_SCOPE,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="BASELINE",
        attack_id="MCP-003",
        registry=default_registry(),
    )
    assert_all_schema_valid(baseline.events)
    assert_correlation(baseline.events, baseline.run_id, workflow_entry="/mcp/invoke")
    assert_sequence_ordering(baseline.events)
    names = event_names(baseline.events)
    assert names.index(EVENT_CONTROL_DECISION) < names.index(EVENT_MCP_STARTED)
    assert EVENT_MCP_COMPLETED in names
    allow = events_named(baseline.events, EVENT_CONTROL_DECISION)[0]
    assert allow["agentsec.schema.version"] == "1.9.0"
    assert allow["agentsec.control.decision"] == "ALLOW"
    assert allow["agentsec.operation.attempted"] is False
    assert allow["agentsec.operation.executed"] is False
    assert "agentsec.operation.outcome" not in allow
    started = events_named(baseline.events, EVENT_MCP_STARTED)[0]
    assert started["agentsec.operation.attempted"] is True
    assert started["agentsec.operation.executed"] is True

    monkeypatch.setenv("AGENTSEC_OTEL_ENABLED", "false")
    monkeypatch.setenv("AGENTSEC_SECURITY_PROFILE", "vulnerable")
    monkeypatch.setenv("AGENTSEC_ARTIFACTS_DIR", str(tmp_path / "artifacts-attack"))
    reset_settings_cache()
    from agentsec.settings import get_settings

    attack_settings = get_settings()
    attack_memory = MemorySink()
    attack = run_mcp_invoke(
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_ARGS,
        requested_scope=MCP_POLICY_RESTRICTED_SCOPE,
        sink=attack_memory,
        memory=attack_memory,
        settings=attack_settings,
        testbed_mode="ATTACK",
        attack_id="MCP-003",
        registry=default_registry(),
    )
    assert_all_schema_valid(attack.events)
    attack_names = event_names(attack.events)
    assert attack_names.index(EVENT_CONTROL_DECISION) < attack_names.index(EVENT_MCP_STARTED)
    fail_open = events_named(attack.events, EVENT_CONTROL_DECISION)[0]
    assert fail_open["agentsec.control.reason"] == MCP003_FAIL_OPEN_REASON
    assert fail_open["agentsec.mcp.requested_scope"] == MCP_POLICY_RESTRICTED_SCOPE
    assert fail_open["agentsec.mcp.allowed_scope"] == MCP_POLICY_SCOPE
    reset_settings_cache()

    retest_memory = MemorySink()
    retest = run_mcp_invoke(
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_ARGS,
        requested_scope=MCP_POLICY_RESTRICTED_SCOPE,
        sink=retest_memory,
        memory=retest_memory,
        settings=settings,
        testbed_mode="RETEST",
        attack_id="MCP-003",
        registry=default_registry(),
    )
    assert_all_schema_valid(retest.events)
    retest_names = event_names(retest.events)
    assert EVENT_MCP_STARTED not in retest_names
    assert EVENT_PIPELINE_STOPPED in retest_names
    deny = events_named(retest.events, EVENT_CONTROL_DECISION)[0]
    assert deny["agentsec.control.decision"] == "DENY"
    assert deny["agentsec.control.reason"] == "scope_not_granted"
    assert deny["agentsec.mcp.requested_scope"] == MCP_POLICY_RESTRICTED_SCOPE
    assert deny["agentsec.mcp.allowed_scope"] == MCP_POLICY_SCOPE
    assert deny["agentsec.operation.attempted"] is False
    assert deny["agentsec.operation.executed"] is False
    assert deny["agentsec.operation.outcome"] == "prevented"
    assert deny["agentsec.schema.version"] == "1.9.0"
    assert deny["gen_ai.tool.name"] == "lookup_policy"
    assert deny["mcp.method.name"] == "tools/call"
    assert deny["agentsec.control.id"] == "CTRL-MCP-001"
