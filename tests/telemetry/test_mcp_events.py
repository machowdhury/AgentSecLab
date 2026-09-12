from agentsec.events import (
    EVENT_CONTROL_DECISION,
    EVENT_MCP_COMPLETED,
    EVENT_MCP_STARTED,
    EVENT_PIPELINE_STOPPED,
    EVENT_RUN_COMPLETED,
    EVENT_RUN_STARTED,
)
from agentsec.mcp.fixtures import (
    MCP_CUSTOMER_SCOPE,
    MCP_LOOKUP_POLICY_ARGS,
    MCP_LOOKUP_TIER_ARGS,
    MCP_POLICY_SCOPE,
)
from agentsec.mcp.pipeline import run_mcp_invoke
from agentsec.mcp.policy import MCP_AGENT_ID
from agentsec.mcp.registry import default_registry
from tests.helpers import (
    assert_all_schema_valid,
    assert_correlation,
    assert_sequence_ordering,
    event_names,
    events_named,
)


def test_baseline_attack_retest_event_contracts(settings, memory):
    baseline = run_mcp_invoke(
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_ARGS,
        requested_scope=MCP_POLICY_SCOPE,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="BASELINE",
        attack_id="MCP-001",
        registry=default_registry(),
    )
    assert_all_schema_valid(baseline.events)
    assert_correlation(baseline.events, baseline.run_id, workflow_entry="/mcp/invoke")
    assert_sequence_ordering(baseline.events)
    names = event_names(baseline.events)
    assert names[0] == EVENT_RUN_STARTED
    assert EVENT_CONTROL_DECISION in names
    assert EVENT_MCP_STARTED in names
    assert EVENT_MCP_COMPLETED in names
    assert names[-1] == EVENT_RUN_COMPLETED
    for event in baseline.events:
        assert event["gen_ai.workflow.name"] == "mcp_tool_lab"
        assert event["agentsec.workflow.entry"] == "/mcp/invoke"
        assert "session.id" not in event
        if event.get("gen_ai.agent.id"):
            assert event["gen_ai.agent.id"] == MCP_AGENT_ID

    from agentsec.telemetry import MemorySink

    attack_memory = MemorySink()
    attack = run_mcp_invoke(
        tool="lookup_customer_tier",
        arguments=MCP_LOOKUP_TIER_ARGS,
        requested_scope=MCP_CUSTOMER_SCOPE,
        sink=attack_memory,
        memory=attack_memory,
        settings=settings,
        testbed_mode="ATTACK",
        attack_id="MCP-002",
        registry=default_registry(),
    )
    assert_all_schema_valid(attack.events)
    assert EVENT_MCP_STARTED not in event_names(attack.events)
    assert EVENT_PIPELINE_STOPPED in event_names(attack.events)
    deny = events_named(attack.events, EVENT_CONTROL_DECISION)[0]
    assert deny["agentsec.control.decision"] == "DENY"
    assert deny["gen_ai.tool.name"] == "lookup_customer_tier"
    assert deny["mcp.method.name"] == "tools/call"
    assert deny["agentsec.mcp.requested_scope"] == MCP_CUSTOMER_SCOPE
    assert deny["agentsec.mcp.allowed_scope"] == "policy:read"

    retest_memory = MemorySink()
    retest = run_mcp_invoke(
        tool="lookup_customer_tier",
        arguments=MCP_LOOKUP_TIER_ARGS,
        requested_scope=MCP_CUSTOMER_SCOPE,
        sink=retest_memory,
        memory=retest_memory,
        settings=settings,
        testbed_mode="RETEST",
        attack_id="MCP-002",
        registry=default_registry(),
    )
    assert_all_schema_valid(retest.events)
    assert {event["agentsec.testbed.mode"] for event in retest.events} == {"RETEST"}
    assert EVENT_MCP_STARTED not in event_names(retest.events)
