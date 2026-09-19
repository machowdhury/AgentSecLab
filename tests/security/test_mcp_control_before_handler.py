from agentsec.events import EVENT_CONTROL_DECISION, EVENT_MCP_COMPLETED, EVENT_MCP_FAILED, EVENT_MCP_STARTED
from agentsec.mcp.fixtures import (
    MCP_CUSTOMER_SCOPE,
    MCP_LOOKUP_POLICY_ARGS,
    MCP_LOOKUP_TIER_ARGS,
    MCP_POLICY_SCOPE,
)
from agentsec.mcp.pipeline import run_mcp_invoke
from agentsec.mcp.policy import coded_policy, policy_unchanged_by_result
from agentsec.mcp.registry import default_registry
from tests.helpers import control_events, event_names, events_named


def exploding_authorize(**kwargs):
    raise RuntimeError("injected mcp control failure")


def test_authorized_tool_executes_after_allow(settings, memory):
    registry = default_registry()
    result = run_mcp_invoke(
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_ARGS,
        requested_scope=MCP_POLICY_SCOPE,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="BASELINE",
        attack_id="MCP-001",
        registry=registry,
    )
    assert result.terminal == "completed_allowed"
    assert result.hops[0].control_decision == "ALLOW"
    assert result.hops[0].operation_attempted is True
    assert result.hops[0].operation_executed is True
    assert result.hops[0].operation_outcome == "success"
    assert result.handler_invoke_count == 1
    assert registry.invoke_counts["lookup_policy"] == 1
    assert registry.invoke_counts["lookup_customer_tier"] == 0
    names = event_names(result.events)
    allow_idx = names.index(EVENT_CONTROL_DECISION)
    started_idx = names.index(EVENT_MCP_STARTED)
    assert allow_idx < started_idx
    assert EVENT_MCP_COMPLETED in names
    control = control_events(result.events)[0]
    assert control["agentsec.control.id"] == "CTRL-MCP-001"
    assert control["agentsec.operation.attempted"] is False
    assert control["agentsec.operation.executed"] is False
    assert "agentsec.operation.outcome" not in control


def test_known_ungranted_defended_does_not_execute(settings, memory):
    registry = default_registry()
    result = run_mcp_invoke(
        tool="lookup_customer_tier",
        arguments=MCP_LOOKUP_TIER_ARGS,
        requested_scope=MCP_CUSTOMER_SCOPE,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="RETEST",
        attack_id="MCP-002",
        registry=registry,
    )
    assert result.terminal == "completed_denied"
    assert result.hops[0].control_decision == "DENY"
    assert result.hops[0].operation_attempted is False
    assert result.hops[0].operation_executed is False
    assert result.hops[0].operation_outcome == "prevented"
    assert result.handler_invoke_count == 0
    assert registry.invoke_total == 0
    names = event_names(result.events)
    assert EVENT_MCP_STARTED not in names
    assert EVENT_MCP_COMPLETED not in names
    assert EVENT_MCP_FAILED not in names
    deny = control_events(result.events)[0]
    assert deny["agentsec.operation.outcome"] == "prevented"


def test_unknown_tool_error_does_not_execute(settings, memory):
    registry = default_registry()
    result = run_mcp_invoke(
        tool="unknown_tool_xyz",
        arguments={"policy_id": "x"},
        requested_scope=MCP_POLICY_SCOPE,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="ATTACK",
        attack_id="MCP-002",
        registry=registry,
    )
    assert result.hops[0].control_decision == "ERROR"
    assert result.hops[0].control_reason == "unknown_tool"
    assert result.handler_invoke_count == 0
    assert registry.invoke_total == 0
    assert EVENT_MCP_STARTED not in event_names(result.events)


def test_malformed_args_error_does_not_execute(settings, memory):
    registry = default_registry()
    result = run_mcp_invoke(
        tool="lookup_policy",
        arguments={"policy_id": "lending-basics", "agent_id": "spoof"},
        requested_scope=MCP_POLICY_SCOPE,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="BASELINE",
        attack_id="MCP-001",
        registry=registry,
    )
    assert result.hops[0].control_decision == "ERROR"
    assert result.hops[0].control_reason == "malformed_arguments"
    assert result.handler_invoke_count == 0
    assert registry.invoke_total == 0
    assert EVENT_MCP_STARTED not in event_names(result.events)


def test_control_evaluation_failure_does_not_execute(settings, memory):
    registry = default_registry()
    result = run_mcp_invoke(
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_ARGS,
        requested_scope=MCP_POLICY_SCOPE,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="BASELINE",
        attack_id="MCP-001",
        registry=registry,
        authorize_fn=exploding_authorize,
    )
    assert result.hops[0].control_decision == "ERROR"
    assert "control_evaluation_failure" in result.hops[0].control_reason
    assert result.handler_invoke_count == 0
    assert registry.invoke_total == 0
    assert EVENT_MCP_STARTED not in event_names(result.events)


def test_handler_failure_after_allow_is_execution_not_prevention(settings, memory):
    registry = default_registry()

    def boom(_arguments):
        raise RuntimeError("injected handler failure")

    registry.replace_handler("lookup_policy", boom)
    result = run_mcp_invoke(
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_ARGS,
        requested_scope=MCP_POLICY_SCOPE,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="BASELINE",
        attack_id="MCP-001",
        registry=registry,
    )
    assert registry.invoke_counts["lookup_policy"] == 1
    assert result.handler_invoke_count == 1
    assert result.hops[0].operation_executed is True
    assert result.hops[0].operation_outcome == "error"
    assert result.hops[0].control_decision == "ALLOW"
    names = event_names(result.events)
    assert EVENT_MCP_STARTED in names
    assert EVENT_MCP_FAILED in names
    assert EVENT_MCP_COMPLETED not in names
    failed = events_named(result.events, EVENT_MCP_FAILED)[0]
    assert failed["agentsec.operation.executed"] is True
    assert failed["agentsec.operation.outcome"] == "error"


def test_result_data_cannot_change_policy(settings, memory):
    registry = default_registry()
    first = run_mcp_invoke(
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_ARGS,
        requested_scope=MCP_POLICY_SCOPE,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="BASELINE",
        attack_id="MCP-001",
        registry=registry,
    )
    policy = coded_policy()
    after = policy_unchanged_by_result(policy, first.final_output)
    assert after.allowed_tools == policy.allowed_tools
    assert "lookup_customer_tier" not in after.allowed_tools
    second = run_mcp_invoke(
        tool="lookup_customer_tier",
        arguments=MCP_LOOKUP_TIER_ARGS,
        requested_scope=MCP_CUSTOMER_SCOPE,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="RETEST",
        attack_id="MCP-002",
        registry=registry,
    )
    assert second.hops[0].control_decision == "DENY"
    assert registry.invoke_counts["lookup_customer_tier"] == 0
