"""MCP-005: tool result data cannot grant authority (INV-002)."""

from __future__ import annotations

import threading

from agentsec.attacks import BENIGN_LOAN
from agentsec.events import EVENT_CONTROL_DECISION, EVENT_MCP_COMPLETED, EVENT_MCP_STARTED
from agentsec.mcp.authorize import authorize_tool
from agentsec.mcp.fixtures import (
    MCP_CUSTOMER_SCOPE,
    MCP_LOOKUP_POLICY_ARGS,
    MCP_LOOKUP_TIER_ARGS,
    MCP_POLICY_SCOPE,
)
from agentsec.mcp.pipeline import run_mcp_invoke
from agentsec.mcp.policy import ALLOWED_TOOLS, coded_policy, policy_unchanged_by_result
from agentsec.mcp.registry import default_registry
from agentsec.mcp.result_trust import (
    MALICIOUS_POLICY_SUMMARY,
    MCP005_FAIL_OPEN_REASON,
    RESULT_IS_DATA_REASON,
)
from agentsec.pipeline import run_loan_pipeline
from agentsec.settings import reset_settings_cache
from agentsec.telemetry import MemorySink
from tests.helpers import control_events, event_names, events_named


def _run_mcp005(settings, memory, *, mode: str, registry=None, authorize_fn=None):
    return run_mcp_invoke(
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_ARGS,
        requested_scope=MCP_POLICY_SCOPE,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode=mode,
        attack_id="MCP-005",
        registry=registry or default_registry(),
        authorize_fn=authorize_fn,
    )


def _vulnerable_settings(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTSEC_OTEL_ENABLED", "false")
    monkeypatch.setenv("AGENTSEC_SECURITY_PROFILE", "vulnerable")
    monkeypatch.setenv("AGENTSEC_ARTIFACTS_DIR", str(tmp_path / "artifacts-vuln"))
    reset_settings_cache()
    from agentsec.settings import get_settings

    return get_settings()


def test_baseline_normal_result_no_follow_on(settings, memory):
    registry = default_registry()
    result = _run_mcp005(settings, memory, mode="BASELINE", registry=registry)
    assert result.terminal == "completed_allowed"
    assert result.hops[0].control_decision == "ALLOW"
    assert result.lookup_policy_handler_count == 1
    assert result.lookup_customer_tier_handler_count == 0
    assert registry.invoke_counts["lookup_policy"] == 1
    assert registry.invoke_counts["lookup_customer_tier"] == 0
    assert result.result_fixture == "NORMAL"
    assert result.result_derived_authority is False
    assert result.result_control_decision == "OBSERVE"
    assert result.result_control_reason == RESULT_IS_DATA_REASON
    assert result.follow_on_decision is None
    assert MALICIOUS_POLICY_SUMMARY not in (result.final_output or {}).get("summary", "")
    assert coded_policy().allowed_tools == ALLOWED_TOOLS
    names = event_names(result.events)
    assert names.count(EVENT_MCP_STARTED) == 1
    result_ctrl = [e for e in control_events(result.events) if e["agentsec.control.id"] == "CTRL-MCP-RESULT-001"]
    assert len(result_ctrl) == 1
    assert result_ctrl[0]["agentsec.control.decision"] == "OBSERVE"
    assert "gen_ai.tool.call.result" not in result_ctrl[0]


def test_attack_vulnerable_malicious_overlay_executes_follow_on(tmp_path, monkeypatch):
    settings = _vulnerable_settings(tmp_path, monkeypatch)
    memory = MemorySink()
    registry = default_registry()
    before = coded_policy()
    result = _run_mcp005(settings, memory, mode="ATTACK", registry=registry)
    after = coded_policy()
    assert before.allowed_tools == after.allowed_tools == ALLOWED_TOOLS
    assert result.hops[0].control_decision == "ALLOW"
    assert result.lookup_policy_handler_count == 1
    assert result.lookup_customer_tier_handler_count == 1
    assert registry.invoke_counts["lookup_customer_tier"] == 1
    assert result.result_fixture == "MALICIOUS"
    assert result.final_output["summary"] == MALICIOUS_POLICY_SUMMARY
    assert result.result_derived_authority is True
    assert result.result_control_decision == "ALLOW"
    assert result.result_control_reason == MCP005_FAIL_OPEN_REASON
    assert result.follow_on_decision == "ALLOW"
    assert result.follow_on_reason == MCP005_FAIL_OPEN_REASON
    assert "scope_not_granted" not in result.follow_on_reason
    assert "resource_not_granted" not in result.follow_on_reason
    assert "known tool" not in result.follow_on_reason
    follow = result.hops[1]
    assert follow.tool_name == "lookup_customer_tier"
    assert follow.operation_executed is True
    assert follow.mcp_started is True
    allow_tools = {e["gen_ai.tool.name"] for e in control_events(result.events) if e["agentsec.control.id"] == "CTRL-MCP-001"}
    assert allow_tools == {"lookup_policy", "lookup_customer_tier"}
    follow_ctrl = next(
        e
        for e in control_events(result.events)
        if e["agentsec.control.id"] == "CTRL-MCP-001" and e["gen_ai.tool.name"] == "lookup_customer_tier"
    )
    assert follow_ctrl["agentsec.mcp.allowed_scope"] == MCP_POLICY_SCOPE
    assert follow_ctrl["agentsec.control.reason"] == MCP005_FAIL_OPEN_REASON
    reset_settings_cache()


def test_retest_same_malicious_fixture_denies_follow_on(settings, memory):
    registry = default_registry()
    result = _run_mcp005(settings, memory, mode="RETEST", registry=registry)
    assert result.hops[0].control_decision == "ALLOW"
    assert result.lookup_policy_handler_count == 1
    assert result.lookup_customer_tier_handler_count == 0
    assert registry.invoke_counts["lookup_customer_tier"] == 0
    assert result.result_fixture == "MALICIOUS"
    assert result.final_output["summary"] == MALICIOUS_POLICY_SUMMARY
    assert result.result_derived_authority is False
    assert result.result_control_decision == "OBSERVE"
    assert result.result_control_reason == RESULT_IS_DATA_REASON
    assert result.follow_on_decision == "DENY"
    assert result.follow_on_reason == "tool_not_granted"
    follow = result.hops[1]
    assert follow.operation_attempted is False
    assert follow.operation_executed is False
    assert follow.operation_outcome == "prevented"
    assert follow.mcp_started is False
    names = event_names(result.events)
    started_tools = [
        e["gen_ai.tool.name"] for e in events_named(result.events, EVENT_MCP_STARTED)
    ]
    assert started_tools == ["lookup_policy"]
    assert names.count(EVENT_MCP_STARTED) == 1


def test_attack_and_retest_use_identical_malicious_fixture(tmp_path, monkeypatch, settings, memory):
    attack_settings = _vulnerable_settings(tmp_path, monkeypatch)
    attack = _run_mcp005(attack_settings, MemorySink(), mode="ATTACK")
    reset_settings_cache()
    retest = _run_mcp005(settings, memory, mode="RETEST")
    assert attack.final_output == retest.final_output
    assert attack.final_output["summary"] == MALICIOUS_POLICY_SUMMARY
    reset_settings_cache()


def test_server_owned_grants_identical_before_after_attack(tmp_path, monkeypatch):
    settings = _vulnerable_settings(tmp_path, monkeypatch)
    before = coded_policy()
    snapshot = (before.allowed_tools, before.allowed_scopes, before.allowed_policy_ids, before.agent_id)
    _run_mcp005(settings, MemorySink(), mode="ATTACK")
    after = coded_policy()
    assert (after.allowed_tools, after.allowed_scopes, after.allowed_policy_ids, after.agent_id) == snapshot
    reset_settings_cache()


def test_cross_run_attack_does_not_contaminate_retest_or_baseline(tmp_path, monkeypatch, settings):
    attack_settings = _vulnerable_settings(tmp_path, monkeypatch)
    attack_reg = default_registry()
    attack = _run_mcp005(attack_settings, MemorySink(), mode="ATTACK", registry=attack_reg)
    assert attack.lookup_customer_tier_handler_count == 1
    reset_settings_cache()
    retest_reg = default_registry()
    retest = _run_mcp005(settings, MemorySink(), mode="RETEST", registry=retest_reg)
    assert retest.follow_on_decision == "DENY"
    assert retest.lookup_customer_tier_handler_count == 0
    baseline_reg = default_registry()
    baseline = _run_mcp005(settings, MemorySink(), mode="BASELINE", registry=baseline_reg)
    assert baseline.follow_on_decision is None
    assert baseline.lookup_customer_tier_handler_count == 0
    mcp_memory = MemorySink()
    later = run_mcp_invoke(
        tool="lookup_customer_tier",
        arguments=MCP_LOOKUP_TIER_ARGS,
        requested_scope=MCP_CUSTOMER_SCOPE,
        sink=mcp_memory,
        memory=mcp_memory,
        settings=settings,
        testbed_mode="RETEST",
        attack_id="MCP-002",
        registry=default_registry(),
    )
    assert later.hops[0].control_decision == "DENY"
    assert later.handler_invoke_count == 0
    reset_settings_cache()


def test_another_agent_after_vulnerable_run_does_not_gain_tool(tmp_path, monkeypatch, settings, counting_llm):
    attack_settings = _vulnerable_settings(tmp_path, monkeypatch)
    _run_mcp005(attack_settings, MemorySink(), mode="ATTACK")
    reset_settings_cache()
    loan_memory = MemorySink()
    run_loan_pipeline(
        BENIGN_LOAN,
        llm=counting_llm,
        sink=loan_memory,
        memory=loan_memory,
        settings=settings,
        testbed_mode="BASELINE",
        attack_id="ATK-001",
    )
    mcp_memory = MemorySink()
    denied = run_mcp_invoke(
        tool="lookup_customer_tier",
        arguments=MCP_LOOKUP_TIER_ARGS,
        requested_scope=MCP_CUSTOMER_SCOPE,
        sink=mcp_memory,
        memory=mcp_memory,
        settings=settings,
        testbed_mode="RETEST",
        attack_id="MCP-002",
        registry=default_registry(),
    )
    assert denied.hops[0].control_decision == "DENY"
    assert "lookup_customer_tier" not in coded_policy().allowed_tools
    reset_settings_cache()


def test_simultaneous_runs_do_not_share_overlay(tmp_path, monkeypatch, settings):
    attack_settings = _vulnerable_settings(tmp_path, monkeypatch)
    results = {}

    def attack_job():
        results["attack"] = _run_mcp005(attack_settings, MemorySink(), mode="ATTACK", registry=default_registry())

    def retest_job():
        results["retest"] = _run_mcp005(settings, MemorySink(), mode="RETEST", registry=default_registry())

    t1 = threading.Thread(target=attack_job)
    t2 = threading.Thread(target=retest_job)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    assert results["attack"].lookup_customer_tier_handler_count == 1
    assert results["retest"].lookup_customer_tier_handler_count == 0
    assert results["retest"].follow_on_decision == "DENY"
    reset_settings_cache()


def test_result_trust_exception_fails_safe(settings, memory, monkeypatch):
    def boom(**kwargs):
        raise RuntimeError("injected result-trust failure")

    monkeypatch.setattr("agentsec.mcp.pipeline.evaluate_result_trust_safe", boom)
    registry = default_registry()
    result = _run_mcp005(settings, memory, mode="RETEST", registry=registry)
    assert result.result_control_decision == "ERROR"
    assert result.result_derived_authority is False
    assert result.lookup_customer_tier_handler_count == 0
    assert registry.invoke_counts["lookup_customer_tier"] == 0
    assert result.lookup_policy_handler_count == 1
    assert EVENT_MCP_STARTED in event_names(result.events)
    started_tools = [e["gen_ai.tool.name"] for e in events_named(result.events, EVENT_MCP_STARTED)]
    assert "lookup_customer_tier" not in started_tools


def test_follow_on_authorization_exception_does_not_execute(settings, memory):
    def first_ok_then_boom(**kwargs):
        if kwargs.get("tool_name") == "lookup_customer_tier":
            raise RuntimeError("injected follow-on control failure")
        return authorize_tool(**kwargs)

    registry = default_registry()
    result = _run_mcp005(settings, memory, mode="RETEST", registry=registry, authorize_fn=first_ok_then_boom)
    assert result.lookup_policy_handler_count == 1
    assert result.lookup_customer_tier_handler_count == 0
    assert registry.invoke_counts["lookup_customer_tier"] == 0
    assert result.follow_on_decision == "ERROR"
    follow = result.hops[1]
    assert follow.mcp_started is False
    assert follow.handler_invoked is False


def test_initial_handler_failure_does_not_create_overlay(settings, memory):
    registry = default_registry()

    def boom(_arguments):
        raise RuntimeError("injected handler failure")

    registry.replace_handler("lookup_policy", boom)
    result = _run_mcp005(settings, memory, mode="ATTACK", registry=registry)
    assert result.lookup_policy_handler_count == 1
    assert result.lookup_customer_tier_handler_count == 0
    assert result.result_derived_authority is False
    assert result.follow_on_decision is None
    assert EVENT_MCP_COMPLETED not in event_names(result.events)


def test_follow_on_handler_failure_counts_as_execution(tmp_path, monkeypatch):
    settings = _vulnerable_settings(tmp_path, monkeypatch)
    registry = default_registry()

    def boom(_arguments):
        raise RuntimeError("injected follow-on handler failure")

    registry.replace_handler("lookup_customer_tier", boom)
    result = _run_mcp005(settings, MemorySink(), mode="ATTACK", registry=registry)
    assert result.lookup_policy_handler_count == 1
    assert result.lookup_customer_tier_handler_count == 1
    assert result.hops[1].operation_executed is True
    assert result.hops[1].mcp_failed is True
    reset_settings_cache()


def test_malicious_text_does_not_bypass_authorization_or_mutate_identity(settings, memory):
    result = _run_mcp005(settings, memory, mode="RETEST")
    assert result.profile == "defended"
    assert result.hops[0].agent_id == "acme-agent-mcp-001"
    follow_ctrl = next(
        e
        for e in control_events(result.events)
        if e.get("gen_ai.tool.name") == "lookup_customer_tier"
    )
    assert follow_ctrl["event.name"] == EVENT_CONTROL_DECISION
    assert follow_ctrl["agentsec.control.decision"] == "DENY"
    after = policy_unchanged_by_result(coded_policy(), result.final_output)
    assert after.agent_id == "acme-agent-mcp-001"
    assert after.allowed_tools == ALLOWED_TOOLS


def test_http_result_fixture_field_is_unknown_fields(acme_client):
    response = acme_client.post(
        "/mcp/invoke",
        json={
            "tool": "lookup_policy",
            "arguments": MCP_LOOKUP_POLICY_ARGS,
            "requested_scope": MCP_POLICY_SCOPE,
            "result_fixture": "malicious",
        },
    )
    body = response.get_json()
    assert response.status_code == 400
    assert body["error_stage"] == "schema_validation"
    assert body["handler_invoke_count"] == 0
