"""CTRL-DELEGATION-001 unit tests (INV-001). No Ollama."""

from __future__ import annotations

import pytest

from agentsec.agents import COMPLIANCE_ID, CREDIT_ID
from agentsec.mcp.delegation import (
    AUTHORITY_AMBIENT_DEPUTY,
    AUTHORITY_DELEGATED,
    DELEGATION_DENIED_REASON,
    DELEGATION_GRANTED_REASON,
    MALFORMED_REASON,
    MCP006_FAIL_OPEN_REASON,
    MISSING_CONTEXT_REASON,
    UNKNOWN_CALLER_REASON,
    UNKNOWN_DEPUTY_REASON,
    DelegationRequest,
    bind_deputy_call,
    coded_delegation_request,
    evaluate_delegation,
    evaluate_delegation_safe,
    grant_snapshot,
)
from agentsec.mcp.fixtures import MCP_LOOKUP_POLICY_ARGS, MCP_LOOKUP_TIER_ARGS, MCP_POLICY_SCOPE
from agentsec.mcp.policy import ALLOWED_TOOLS, coded_policy


def test_baseline_tool_is_delegated_allow():
    request = coded_delegation_request(
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_ARGS,
        requested_scope=MCP_POLICY_SCOPE,
        principal_id="applicant-web",
    )
    result = evaluate_delegation(request=request, profile="defended")
    assert result.decision == "ALLOW"
    assert result.reason == DELEGATION_GRANTED_REASON
    assert result.authority_source == AUTHORITY_DELEGATED
    assert result.ticket is not None
    assert result.ticket.caller_agent_id == CREDIT_ID
    assert result.ticket.deputy_agent_id == COMPLIANCE_ID


def test_defended_excessive_tool_is_deny_not_ambient():
    request = coded_delegation_request(
        tool="lookup_customer_tier",
        arguments=MCP_LOOKUP_TIER_ARGS,
        requested_scope="customer:read",
        principal_id="applicant-web",
    )
    result = evaluate_delegation(request=request, profile="defended")
    assert result.decision == "DENY"
    assert result.reason == DELEGATION_DENIED_REASON
    assert result.authority_source == AUTHORITY_DELEGATED
    assert result.ticket is None
    assert result.blocks_deputy is True


def test_vulnerable_substitutes_ambient_not_disable_authz():
    request = coded_delegation_request(
        tool="lookup_customer_tier",
        arguments=MCP_LOOKUP_TIER_ARGS,
        requested_scope="customer:read",
        principal_id="applicant-web",
    )
    result = evaluate_delegation(request=request, profile="vulnerable")
    assert result.decision == "ALLOW"
    assert result.reason == MCP006_FAIL_OPEN_REASON
    assert result.authority_source == AUTHORITY_AMBIENT_DEPUTY
    assert result.ticket is not None
    snapshot = grant_snapshot()
    assert "lookup_customer_tier" not in snapshot["delegated.tools"]
    assert "lookup_customer_tier" in snapshot["ambient.tools"]
    assert coded_policy().allowed_tools == ALLOWED_TOOLS


def test_unknown_caller_is_error():
    request = DelegationRequest(
        principal_id="applicant-web",
        caller_agent_id="acme-agent-unknown-999",
        deputy_agent_id=COMPLIANCE_ID,
        tool="lookup_policy",
        requested_scope=MCP_POLICY_SCOPE,
        arguments=MCP_LOOKUP_POLICY_ARGS,
    )
    result = evaluate_delegation(request=request, profile="vulnerable")
    assert result.decision == "ERROR"
    assert result.reason == UNKNOWN_CALLER_REASON
    assert result.ticket is None
    assert result.authority_source is None


def test_spoofed_privileged_caller_is_unknown():
    request = DelegationRequest(
        principal_id="applicant-web",
        caller_agent_id=COMPLIANCE_ID,
        deputy_agent_id=COMPLIANCE_ID,
        tool="lookup_customer_tier",
        requested_scope="customer:read",
        arguments=MCP_LOOKUP_TIER_ARGS,
    )
    result = evaluate_delegation(request=request, profile="vulnerable")
    assert result.decision == "ERROR"
    assert result.reason == UNKNOWN_CALLER_REASON


def test_unknown_deputy_is_error():
    request = DelegationRequest(
        principal_id="applicant-web",
        caller_agent_id=CREDIT_ID,
        deputy_agent_id="acme-agent-mcp-001",
        tool="lookup_policy",
        requested_scope=MCP_POLICY_SCOPE,
        arguments=MCP_LOOKUP_POLICY_ARGS,
    )
    result = evaluate_delegation(request=request, profile="defended")
    assert result.decision == "ERROR"
    assert result.reason == UNKNOWN_DEPUTY_REASON


def test_missing_caller_is_error():
    request = DelegationRequest(
        principal_id="applicant-web",
        caller_agent_id="",
        deputy_agent_id=COMPLIANCE_ID,
        tool="lookup_policy",
        requested_scope=MCP_POLICY_SCOPE,
        arguments=MCP_LOOKUP_POLICY_ARGS,
    )
    result = evaluate_delegation(request=request, profile="vulnerable")
    assert result.decision == "ERROR"
    assert result.reason == MISSING_CONTEXT_REASON


def test_malformed_tool_type_is_error():
    request = DelegationRequest(
        principal_id="applicant-web",
        caller_agent_id=CREDIT_ID,
        deputy_agent_id=COMPLIANCE_ID,
        tool={"name": "lookup_policy"},
        requested_scope=MCP_POLICY_SCOPE,
        arguments=MCP_LOOKUP_POLICY_ARGS,
    )
    result = evaluate_delegation(request=request, profile="vulnerable")
    assert result.decision == "ERROR"
    assert result.reason == MALFORMED_REASON


def test_injected_authority_field_is_malformed():
    request = DelegationRequest(
        principal_id="applicant-web",
        caller_agent_id=CREDIT_ID,
        deputy_agent_id=COMPLIANCE_ID,
        tool="lookup_customer_tier",
        requested_scope="customer:read",
        arguments=MCP_LOOKUP_TIER_ARGS,
        extra={"delegated_authority": "lookup_customer_tier"},
    )
    result = evaluate_delegation(request=request, profile="vulnerable")
    assert result.decision == "ERROR"
    assert result.reason == MALFORMED_REASON
    assert result.ticket is None


def test_control_exception_is_error_not_ambient():
    def boom(*, request, profile):
        raise RuntimeError("injected control failure")

    request = coded_delegation_request(
        tool="lookup_customer_tier",
        arguments=MCP_LOOKUP_TIER_ARGS,
        requested_scope="customer:read",
        principal_id="applicant-web",
    )
    result = evaluate_delegation_safe(request=request, profile="vulnerable", evaluate_fn=boom)
    assert result.decision == "ERROR"
    assert result.reason == "delegation_control_error"
    assert result.ticket is None


def test_ticket_is_frozen_and_bind_ignores_later_request_mutation():
    request = coded_delegation_request(
        tool="lookup_policy",
        arguments=dict(MCP_LOOKUP_POLICY_ARGS),
        requested_scope=MCP_POLICY_SCOPE,
        principal_id="applicant-web",
    )
    result = evaluate_delegation(request=request, profile="defended")
    ticket = result.ticket
    assert ticket is not None
    request.tool = "lookup_customer_tier"
    request.requested_scope = "customer:read"
    tool, scope, args, deputy = bind_deputy_call(ticket)
    assert tool == "lookup_policy"
    assert scope == MCP_POLICY_SCOPE
    assert args == MCP_LOOKUP_POLICY_ARGS
    assert deputy == COMPLIANCE_ID
    with pytest.raises(Exception):
        ticket.tool = "lookup_customer_tier"  # type: ignore[misc]
