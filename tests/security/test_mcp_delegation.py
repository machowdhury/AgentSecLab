"""MCP-006 confused deputy: ambient deputy authority must not satisfy an unauthorized caller."""

from __future__ import annotations

from agentsec.events import EVENT_MCP_STARTED
from agentsec.mcp.delegation import (
    AUTHORITY_AMBIENT_DEPUTY,
    AUTHORITY_DELEGATED,
    DELEGATION_DENIED_REASON,
    DELEGATION_GRANTED_REASON,
    MCP006_FAIL_OPEN_REASON,
    DelegationRequest,
    grant_snapshot,
)
from agentsec.mcp.delegation_pipeline import run_mcp_006_invoke
from agentsec.mcp.fixtures import (
    MCP_CUSTOMER_SCOPE,
    MCP_LOOKUP_POLICY_ARGS,
    MCP_LOOKUP_TIER_ARGS,
    MCP_POLICY_RESTRICTED_SCOPE,
    MCP_POLICY_SCOPE,
)
from agentsec.mcp.policy import ALLOWED_TOOLS, coded_policy
from agentsec.mcp.registry import default_registry
from agentsec.settings import reset_settings_cache
from agentsec.telemetry import MemorySink
from tests.helpers import control_events, event_names, events_named


def _run(settings, memory, *, mode, tool, arguments, requested_scope, registry=None, **kwargs):
    return run_mcp_006_invoke(
        tool=tool,
        arguments=arguments,
        requested_scope=requested_scope,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode=mode,
        registry=registry or default_registry(),
        **kwargs,
    )


def _vulnerable(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTSEC_OTEL_ENABLED", "false")
    monkeypatch.setenv("AGENTSEC_SECURITY_PROFILE", "vulnerable")
    monkeypatch.setenv("AGENTSEC_ARTIFACTS_DIR", str(tmp_path / "artifacts-vuln"))
    reset_settings_cache()
    from agentsec.settings import get_settings

    return get_settings()


def test_baseline_legitimate_delegation_executes_once(settings, memory):
    registry = default_registry()
    result = _run(
        settings,
        memory,
        mode="BASELINE",
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_ARGS,
        requested_scope=MCP_POLICY_SCOPE,
        registry=registry,
    )
    assert result.terminal == "completed_allowed"
    assert result.delegation_decision == "ALLOW"
    assert result.delegation_reason == DELEGATION_GRANTED_REASON
    assert result.authority_source == AUTHORITY_DELEGATED
    assert result.downstream_mcp_decision == "ALLOW"
    assert result.downstream_mcp_reason == "tool_granted"
    assert result.operation_attempted is True
    assert result.operation_executed is True
    assert result.operation_outcome == "success"
    assert result.lookup_policy_handler_count == 1
    assert result.lookup_customer_tier_handler_count == 0
    assert registry.invoke_counts["lookup_policy"] == 1
    assert result.hops[0].agent_id == "acme-agent-credit-002"
    assert result.hops[1].agent_id == "acme-agent-compliance-004"
    assert result.hops[1].delegator_agent_id == "acme-agent-credit-002"
    names = event_names(result.events)
    assert names.count(EVENT_MCP_STARTED) == 1
    delegation = next(e for e in control_events(result.events) if e["agentsec.control.id"] == "CTRL-DELEGATION-001")
    assert delegation["agentsec.hop.index"] == 0
    assert delegation["gen_ai.agent.id"] == "acme-agent-credit-002"
    assert delegation["agentsec.delegation.authority.source"] == AUTHORITY_DELEGATED
    mcp_ctrl = next(e for e in control_events(result.events) if e["agentsec.control.id"] == "CTRL-MCP-001")
    assert mcp_ctrl["agentsec.hop.index"] == 1
    assert "vulnerable_profile_fail_open" not in mcp_ctrl["agentsec.control.reason"]


def test_attack_ambient_substitution_executes_tier(tmp_path, monkeypatch):
    settings = _vulnerable(tmp_path, monkeypatch)
    before = grant_snapshot()
    coded_before = coded_policy()
    registry = default_registry()
    result = _run(
        settings,
        MemorySink(),
        mode="ATTACK",
        tool="lookup_customer_tier",
        arguments=MCP_LOOKUP_TIER_ARGS,
        requested_scope=MCP_CUSTOMER_SCOPE,
        registry=registry,
    )
    assert result.delegation_decision == "ALLOW"
    assert result.delegation_reason == MCP006_FAIL_OPEN_REASON
    assert result.authority_source == AUTHORITY_AMBIENT_DEPUTY
    assert result.downstream_mcp_decision == "ALLOW"
    assert result.downstream_mcp_reason == "tool_granted"
    assert result.lookup_customer_tier_handler_count == 1
    assert result.lookup_policy_handler_count == 0
    assert grant_snapshot() == before
    assert coded_policy().allowed_tools == coded_before.allowed_tools == ALLOWED_TOOLS
    reset_settings_cache()


def test_retest_same_request_denied_no_mcp_start(settings, memory):
    registry = default_registry()
    result = _run(
        settings,
        memory,
        mode="RETEST",
        tool="lookup_customer_tier",
        arguments=MCP_LOOKUP_TIER_ARGS,
        requested_scope=MCP_CUSTOMER_SCOPE,
        registry=registry,
    )
    assert result.profile == "defended"
    assert result.delegation_decision == "DENY"
    assert result.delegation_reason == DELEGATION_DENIED_REASON
    assert result.authority_source == AUTHORITY_DELEGATED
    assert result.downstream_mcp_decision is None
    assert result.operation_attempted is False
    assert result.operation_executed is False
    assert result.operation_outcome == "prevented"
    assert result.lookup_customer_tier_handler_count == 0
    assert result.handler_invoke_count == 0
    assert len(result.hops) == 1
    assert events_named(result.events, EVENT_MCP_STARTED) == []
    assert not any(e.get("event.name") == EVENT_MCP_STARTED for e in result.events)


def test_attack_retest_request_equivalence(tmp_path, monkeypatch, settings, memory):
    vuln = _vulnerable(tmp_path, monkeypatch)
    attack = _run(
        vuln,
        MemorySink(),
        mode="ATTACK",
        tool="lookup_customer_tier",
        arguments=dict(MCP_LOOKUP_TIER_ARGS),
        requested_scope=MCP_CUSTOMER_SCOPE,
    )
    reset_settings_cache()
    retest = _run(
        settings,
        memory,
        mode="RETEST",
        tool="lookup_customer_tier",
        arguments=dict(MCP_LOOKUP_TIER_ARGS),
        requested_scope=MCP_CUSTOMER_SCOPE,
    )
    assert attack.caller_agent_id == retest.caller_agent_id
    assert attack.deputy_agent_id == retest.deputy_agent_id
    assert attack.hops[0].tool_name == retest.hops[0].tool_name == "lookup_customer_tier"
    attack_req = next(e for e in attack.events if e["event.name"] == "agentsec.control.decision")
    retest_req = next(e for e in retest.events if e["event.name"] == "agentsec.control.decision")
    assert attack_req["gen_ai.tool.name"] == retest_req["gen_ai.tool.name"]
    assert attack_req["agentsec.mcp.requested_scope"] == retest_req["agentsec.mcp.requested_scope"]
    assert attack.delegation_decision != retest.delegation_decision
    reset_settings_cache()


def test_valid_delegation_then_mcp_deny_handler_zero(settings, memory):
    result = _run(
        settings,
        memory,
        mode="BASELINE",
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_ARGS,
        requested_scope=MCP_POLICY_RESTRICTED_SCOPE,
    )
    assert result.delegation_decision == "ALLOW"
    assert result.delegation_reason == DELEGATION_GRANTED_REASON
    assert result.downstream_mcp_decision == "DENY"
    assert result.downstream_mcp_reason == "scope_not_granted"
    assert result.handler_invoke_count == 0
    assert events_named(result.events, EVENT_MCP_STARTED) == []


def test_handler_failure_after_allow_is_error_not_prevented(settings, memory):
    registry = default_registry()

    def boom(_arguments):
        raise RuntimeError("injected deputy handler failure")

    registry.replace_handler("lookup_policy", boom)
    result = _run(
        settings,
        memory,
        mode="BASELINE",
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_ARGS,
        requested_scope=MCP_POLICY_SCOPE,
        registry=registry,
    )
    assert result.delegation_decision == "ALLOW"
    assert result.downstream_mcp_decision == "ALLOW"
    assert result.operation_attempted is True
    assert result.operation_executed is True
    assert result.operation_outcome == "error"
    assert result.hops[1].mcp_failed is True
    assert result.terminal == "run_failed"
    assert result.lookup_policy_handler_count == 1


def test_unknown_caller_handler_zero(settings, memory):
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
    assert result.hops[0].agent_id == "acme-agent-unknown-999"
    assert result.caller_agent_id == "acme-agent-unknown-999"
    assert result.delegation_decision == "ERROR"
    assert result.delegation_reason == "unknown_caller"
    assert result.handler_invoke_count == 0
    assert events_named(result.events, EVENT_MCP_STARTED) == []


def test_unknown_deputy_handler_zero(settings, memory):
    request = DelegationRequest(
        principal_id="applicant-web",
        caller_agent_id="acme-agent-credit-002",
        deputy_agent_id="acme-agent-risk-003",
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
    assert result.delegation_decision == "ERROR"
    assert result.delegation_reason == "unknown_deputy"
    assert result.handler_invoke_count == 0


def test_missing_delegation_context_handler_zero(settings, memory):
    request = DelegationRequest(
        principal_id="applicant-web",
        caller_agent_id="",
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
    assert result.delegation_decision == "ERROR"
    assert result.delegation_reason == "missing_delegation_context"
    assert result.handler_invoke_count == 0


def test_malformed_nested_arguments_handler_zero(settings, memory):
    request = DelegationRequest(
        principal_id="applicant-web",
        caller_agent_id="acme-agent-credit-002",
        deputy_agent_id="acme-agent-compliance-004",
        tool="lookup_policy",
        requested_scope=MCP_POLICY_SCOPE,
        arguments={"policy_id": {"nested": "lending-basics"}},
    )
    result = run_mcp_006_invoke(
        tool="lookup_policy",
        arguments={"policy_id": {"nested": "lending-basics"}},
        requested_scope=MCP_POLICY_SCOPE,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="ATTACK",
        request=request,
    )
    assert result.delegation_decision == "ERROR"
    assert result.delegation_reason == "malformed_delegation"
    assert result.handler_invoke_count == 0


def test_control_exception_no_ambient_fallback(tmp_path, monkeypatch):
    settings = _vulnerable(tmp_path, monkeypatch)
    memory = MemorySink()

    def boom(*, request, profile):
        raise RuntimeError("injected")

    result = run_mcp_006_invoke(
        tool="lookup_customer_tier",
        arguments=MCP_LOOKUP_TIER_ARGS,
        requested_scope=MCP_CUSTOMER_SCOPE,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="ATTACK",
        evaluate_fn=boom,
    )
    assert result.delegation_decision == "ERROR"
    assert result.delegation_reason == "delegation_control_error"
    assert result.handler_invoke_count == 0
    assert events_named(result.events, EVENT_MCP_STARTED) == []
    reset_settings_cache()


def test_cross_run_isolation_attack_then_retest(tmp_path, monkeypatch, settings):
    vuln = _vulnerable(tmp_path, monkeypatch)
    before = grant_snapshot()
    attack = _run(
        vuln,
        MemorySink(),
        mode="ATTACK",
        tool="lookup_customer_tier",
        arguments=MCP_LOOKUP_TIER_ARGS,
        requested_scope=MCP_CUSTOMER_SCOPE,
    )
    assert attack.lookup_customer_tier_handler_count == 1
    reset_settings_cache()
    retest = _run(
        settings,
        MemorySink(),
        mode="RETEST",
        tool="lookup_customer_tier",
        arguments=MCP_LOOKUP_TIER_ARGS,
        requested_scope=MCP_CUSTOMER_SCOPE,
    )
    assert retest.lookup_customer_tier_handler_count == 0
    assert grant_snapshot() == before
    assert coded_policy().allowed_tools == ALLOWED_TOOLS


def test_check_use_ignores_mutated_request_after_allow(settings, memory):
    def mutate(request):
        request.tool = "lookup_customer_tier"
        request.requested_scope = MCP_CUSTOMER_SCOPE
        request.arguments = dict(MCP_LOOKUP_TIER_ARGS)

    result = _run(
        settings,
        memory,
        mode="BASELINE",
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_ARGS,
        requested_scope=MCP_POLICY_SCOPE,
        mutate_request_after_allow=mutate,
    )
    assert result.delegation_decision == "ALLOW"
    assert result.hops[1].tool_name == "lookup_policy"
    assert result.lookup_policy_handler_count == 1
    assert result.lookup_customer_tier_handler_count == 0


def test_llm_not_invoked(settings, memory):
    result = _run(
        settings,
        memory,
        mode="BASELINE",
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_ARGS,
        requested_scope=MCP_POLICY_SCOPE,
    )
    assert all(not hop.llm_started for hop in result.hops)
    assert not any(e["event.name"].startswith("agentsec.llm.") for e in result.events)
