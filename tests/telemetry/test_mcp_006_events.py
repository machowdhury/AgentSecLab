"""MCP-006 telemetry: hops, authority source, no execution after DENY/ERROR."""

from __future__ import annotations

from agentsec.events import EVENT_MCP_STARTED
from agentsec.mcp.delegation import AUTHORITY_DELEGATED, DELEGATION_DENIED_REASON
from agentsec.mcp.delegation_pipeline import run_mcp_006_invoke
from agentsec.mcp.fixtures import (
    MCP_CUSTOMER_SCOPE,
    MCP_LOOKUP_POLICY_ARGS,
    MCP_LOOKUP_TIER_ARGS,
    MCP_POLICY_SCOPE,
)
from agentsec.mcp.registry import default_registry
from tests.helpers import assert_all_schema_valid, assert_correlation, assert_sequence_ordering, control_events, event_names


def test_baseline_event_order_and_schema(settings, memory):
    result = run_mcp_006_invoke(
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_ARGS,
        requested_scope=MCP_POLICY_SCOPE,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="BASELINE",
        registry=default_registry(),
    )
    assert_all_schema_valid(result.events)
    assert_correlation(result.events, result.run_id, workflow_entry="/mcp/invoke")
    assert_sequence_ordering(result.events)
    names = event_names(result.events)
    assert names[0] == "agentsec.run.started"
    assert names[1] == "agentsec.hop.started"
    assert names[2] == "agentsec.control.decision"
    assert result.events[2]["agentsec.control.id"] == "CTRL-DELEGATION-001"
    assert "agentsec.mcp.started" in names
    started_at = names.index("agentsec.mcp.started")
    allow_mcp = names.index("agentsec.control.decision", 3)
    assert result.events[allow_mcp]["agentsec.control.id"] == "CTRL-MCP-001"
    assert allow_mcp < started_at
    assert names[started_at + 1] == "agentsec.mcp.completed"
    assert result.events[-1]["event.name"] == "agentsec.run.completed"
    for event in result.events:
        assert event["agentsec.schema.version"] == "1.7.0"
        assert event["agentsec.attack.id"] == "MCP-006"
        assert "gen_ai.tool.call.id" not in event
    hop0 = result.events[2]
    hop1_ctrl = next(e for e in control_events(result.events) if e["agentsec.control.id"] == "CTRL-MCP-001")
    assert hop0["parent_span_id"] == result.hops[0].span_id
    assert hop1_ctrl["gen_ai.agent.id"] == "acme-agent-compliance-004"
    assert hop1_ctrl["agentsec.delegator.agent.id"] == "acme-agent-credit-002"


def test_retest_has_no_mcp_started(settings, memory):
    result = run_mcp_006_invoke(
        tool="lookup_customer_tier",
        arguments=MCP_LOOKUP_TIER_ARGS,
        requested_scope=MCP_CUSTOMER_SCOPE,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="RETEST",
        registry=default_registry(),
    )
    assert_all_schema_valid(result.events)
    names = event_names(result.events)
    assert EVENT_MCP_STARTED not in names
    assert "agentsec.mcp.completed" not in names
    deny = next(e for e in control_events(result.events) if e["agentsec.control.id"] == "CTRL-DELEGATION-001")
    assert deny["agentsec.control.decision"] == "DENY"
    assert deny["agentsec.control.reason"] == DELEGATION_DENIED_REASON
    assert deny["agentsec.delegation.authority.source"] == AUTHORITY_DELEGATED
    assert deny["agentsec.operation.executed"] is False
    assert result.events[-1]["event.name"] == "agentsec.run.completed"
    assert result.events[-1]["agentsec.outcome"] == "completed_denied"


def test_error_path_has_no_mcp_started_or_success(settings, memory):
    from agentsec.mcp.delegation import DelegationRequest

    request = DelegationRequest(
        principal_id="applicant-web",
        caller_agent_id="acme-agent-unknown-999",
        deputy_agent_id="acme-agent-compliance-004",
        tool="lookup_policy",
        requested_scope=MCP_POLICY_SCOPE,
        arguments=MCP_LOOKUP_POLICY_ARGS,
    )
    result = run_mcp_006_invoke(
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_ARGS,
        requested_scope=MCP_POLICY_SCOPE,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="ATTACK",
        request=request,
    )
    assert_all_schema_valid(result.events)
    names = event_names(result.events)
    assert EVENT_MCP_STARTED not in names
    assert result.events[-1]["event.name"] == "agentsec.run.failed"
    err = next(e for e in control_events(result.events) if e["agentsec.control.id"] == "CTRL-DELEGATION-001")
    assert err["agentsec.control.decision"] == "ERROR"
    assert "agentsec.delegation.authority.source" not in err
