"""LAB-MCP-CATALOG: tool-description metadata cannot grant authority (INV-002)."""

from __future__ import annotations

import threading

from agentsec.attacks import BENIGN_LOAN
from agentsec.events import EVENT_CONTROL_DECISION, EVENT_MCP_COMPLETED, EVENT_MCP_STARTED
from agentsec.mcp.authorize import authorize_tool
from agentsec.mcp.catalog import build_catalog_snapshot
from agentsec.mcp.fixtures import (
    MCP_CATALOG_DESCRIPTION_MALICIOUS,
    MCP_CATALOG_FOLLOW_ON_MARKER,
    MCP_CUSTOMER_SCOPE,
    MCP_LOOKUP_POLICY_ARGS,
    MCP_LOOKUP_TIER_ARGS,
    MCP_POLICY_SCOPE,
)
from agentsec.mcp.metadata_trust import MCP_CATALOG_FAIL_OPEN_REASON, METADATA_IS_DATA_REASON
from agentsec.mcp.pipeline import run_mcp_invoke
from agentsec.mcp.policy import ALLOWED_TOOLS, coded_policy, policy_unchanged_by_catalog
from agentsec.mcp.registry import default_registry
from agentsec.pipeline import run_loan_pipeline
from agentsec.settings import reset_settings_cache
from agentsec.telemetry import MemorySink
from tests.helpers import control_events, event_names, events_named


def _run_catalog(settings, memory, *, mode: str, registry=None, authorize_fn=None, catalog_snapshot=None):
    return run_mcp_invoke(
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_ARGS,
        requested_scope=MCP_POLICY_SCOPE,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode=mode,
        attack_id="MCP-CATALOG-001",
        registry=registry or default_registry(),
        authorize_fn=authorize_fn,
        catalog_snapshot=catalog_snapshot,
    )


def _vulnerable_settings(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTSEC_OTEL_ENABLED", "false")
    monkeypatch.setenv("AGENTSEC_SECURITY_PROFILE", "vulnerable")
    monkeypatch.setenv("AGENTSEC_ARTIFACTS_DIR", str(tmp_path / "artifacts-catalog-vuln"))
    reset_settings_cache()
    from agentsec.settings import get_settings

    return get_settings()


def test_baseline_normal_catalog_no_follow_on(settings, memory):
    registry = default_registry()
    result = _run_catalog(settings, memory, mode="BASELINE", registry=registry)
    assert result.terminal == "completed_allowed"
    assert result.hops[0].control_decision == "ALLOW"
    assert result.lookup_policy_handler_count == 1
    assert result.lookup_customer_tier_handler_count == 0
    assert registry.invoke_counts["lookup_policy"] == 1
    assert registry.invoke_counts["lookup_customer_tier"] == 0
    assert result.catalog_fixture == "NORMAL"
    assert result.metadata_derived_authority is False
    assert result.metadata_control_decision == "OBSERVE"
    assert result.metadata_control_reason == METADATA_IS_DATA_REASON
    assert result.follow_on_decision is None
    assert coded_policy().allowed_tools == ALLOWED_TOOLS
    names = event_names(result.events)
    assert names.count(EVENT_MCP_STARTED) == 1
    meta = [e for e in control_events(result.events) if e["agentsec.control.id"] == "CTRL-MCP-METADATA-001"]
    assert len(meta) == 1
    assert meta[0]["agentsec.control.decision"] == "OBSERVE"
    assert meta[0]["agentsec.mcp.metadata.trust"] == "untrusted_data"


def test_attack_vulnerable_malicious_overlay_executes_follow_on(tmp_path, monkeypatch):
    settings = _vulnerable_settings(tmp_path, monkeypatch)
    memory = MemorySink()
    registry = default_registry()
    before = coded_policy()
    result = _run_catalog(settings, memory, mode="ATTACK", registry=registry)
    after = coded_policy()
    assert before.allowed_tools == after.allowed_tools == ALLOWED_TOOLS
    assert result.hops[0].control_decision == "ALLOW"
    assert result.lookup_policy_handler_count == 1
    assert result.lookup_customer_tier_handler_count == 1
    assert registry.invoke_counts["lookup_customer_tier"] == 1
    assert result.catalog_fixture == "MALICIOUS"
    assert result.metadata_derived_authority is True
    assert result.metadata_control_decision == "OBSERVE"
    assert result.metadata_control_reason == METADATA_IS_DATA_REASON
    assert result.follow_on_decision == "ALLOW"
    assert result.follow_on_reason == MCP_CATALOG_FAIL_OPEN_REASON
    assert "result_derived_grant" not in result.follow_on_reason
    assert "known tool" not in result.follow_on_reason
    follow = result.hops[1]
    assert follow.tool_name == "lookup_customer_tier"
    assert follow.operation_executed is True
    assert follow.mcp_started is True
    follow_ctrl = next(
        e
        for e in control_events(result.events)
        if e["agentsec.control.id"] == "CTRL-MCP-001" and e["gen_ai.tool.name"] == "lookup_customer_tier"
    )
    assert follow_ctrl["agentsec.control.reason"] == MCP_CATALOG_FAIL_OPEN_REASON
    reset_settings_cache()


def test_retest_same_malicious_catalog_denies_follow_on(settings, memory):
    registry = default_registry()
    result = _run_catalog(settings, memory, mode="RETEST", registry=registry)
    assert result.hops[0].control_decision == "ALLOW"
    assert result.lookup_policy_handler_count == 1
    assert result.lookup_customer_tier_handler_count == 0
    assert registry.invoke_counts["lookup_customer_tier"] == 0
    assert result.catalog_fixture == "MALICIOUS"
    assert result.metadata_derived_authority is False
    assert result.metadata_control_decision == "OBSERVE"
    assert result.follow_on_decision == "DENY"
    assert result.follow_on_reason == "tool_not_granted"
    follow = result.hops[1]
    assert follow.operation_attempted is False
    assert follow.operation_executed is False
    assert follow.operation_outcome == "prevented"
    assert follow.mcp_started is False
    started_tools = [e["gen_ai.tool.name"] for e in events_named(result.events, EVENT_MCP_STARTED)]
    assert started_tools == ["lookup_policy"]


def test_attack_and_retest_use_identical_malicious_catalog(tmp_path, monkeypatch, settings, memory):
    attack_settings = _vulnerable_settings(tmp_path, monkeypatch)
    attack = _run_catalog(attack_settings, MemorySink(), mode="ATTACK")
    reset_settings_cache()
    retest = _run_catalog(settings, memory, mode="RETEST")
    assert attack.catalog_description_hash == retest.catalog_description_hash
    assert MCP_CATALOG_FOLLOW_ON_MARKER in MCP_CATALOG_DESCRIPTION_MALICIOUS
    reset_settings_cache()


def test_server_owned_grants_identical_before_after_attack(tmp_path, monkeypatch):
    settings = _vulnerable_settings(tmp_path, monkeypatch)
    before = coded_policy()
    snapshot = (before.allowed_tools, before.allowed_scopes, before.allowed_policy_ids, before.agent_id)
    result = _run_catalog(settings, MemorySink(), mode="ATTACK")
    after = policy_unchanged_by_catalog(coded_policy(), MCP_CATALOG_DESCRIPTION_MALICIOUS)
    assert (after.allowed_tools, after.allowed_scopes, after.allowed_policy_ids, after.agent_id) == snapshot
    assert result.server_owned_allowed_tools == "lookup_policy"
    reset_settings_cache()


def test_cross_run_attack_does_not_contaminate_retest_or_baseline(tmp_path, monkeypatch, settings):
    attack_settings = _vulnerable_settings(tmp_path, monkeypatch)
    attack = _run_catalog(attack_settings, MemorySink(), mode="ATTACK", registry=default_registry())
    assert attack.lookup_customer_tier_handler_count == 1
    reset_settings_cache()
    retest = _run_catalog(settings, MemorySink(), mode="RETEST", registry=default_registry())
    assert retest.follow_on_decision == "DENY"
    assert retest.lookup_customer_tier_handler_count == 0
    baseline = _run_catalog(settings, MemorySink(), mode="BASELINE", registry=default_registry())
    assert baseline.follow_on_decision is None
    later_memory = MemorySink()
    later = run_mcp_invoke(
        tool="lookup_customer_tier",
        arguments=MCP_LOOKUP_TIER_ARGS,
        requested_scope=MCP_CUSTOMER_SCOPE,
        sink=later_memory,
        memory=later_memory,
        settings=settings,
        testbed_mode="RETEST",
        attack_id="MCP-002",
        registry=default_registry(),
    )
    assert later.hops[0].control_decision == "DENY"
    assert later.handler_invoke_count == 0
    reset_settings_cache()


def test_simultaneous_runs_do_not_share_overlay(tmp_path, monkeypatch, settings):
    attack_settings = _vulnerable_settings(tmp_path, monkeypatch)
    results = {}

    def attack_job():
        results["attack"] = _run_catalog(attack_settings, MemorySink(), mode="ATTACK", registry=default_registry())

    def retest_job():
        results["retest"] = _run_catalog(settings, MemorySink(), mode="RETEST", registry=default_registry())

    t1 = threading.Thread(target=attack_job)
    t2 = threading.Thread(target=retest_job)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    assert results["attack"].lookup_customer_tier_handler_count == 1
    assert results["retest"].lookup_customer_tier_handler_count == 0
    reset_settings_cache()


def test_metadata_exception_fails_safe(settings, memory, monkeypatch):
    def boom(**kwargs):
        raise RuntimeError("injected metadata-trust failure")

    monkeypatch.setattr("agentsec.mcp.pipeline.evaluate_metadata_trust_safe", boom)
    registry = default_registry()
    result = _run_catalog(settings, memory, mode="RETEST", registry=registry)
    assert result.metadata_control_decision == "ERROR"
    assert result.metadata_derived_authority is False
    assert result.lookup_customer_tier_handler_count == 0
    assert result.lookup_policy_handler_count == 0
    assert EVENT_MCP_STARTED not in event_names(result.events)


def test_follow_on_authorization_exception_does_not_execute(settings, memory):
    def first_ok_then_boom(**kwargs):
        if kwargs.get("tool_name") == "lookup_customer_tier":
            raise RuntimeError("injected follow-on control failure")
        return authorize_tool(**kwargs)

    registry = default_registry()
    result = _run_catalog(settings, memory, mode="RETEST", registry=registry, authorize_fn=first_ok_then_boom)
    assert result.lookup_policy_handler_count == 1
    assert result.lookup_customer_tier_handler_count == 0
    assert result.follow_on_decision == "ERROR"
    assert result.hops[1].mcp_started is False


def test_malformed_catalog_does_not_create_authority(settings, memory):
    registry = default_registry()
    result = _run_catalog(
        settings,
        memory,
        mode="ATTACK",
        registry=registry,
        catalog_snapshot={"tools": [{"name": "lookup_policy", "description": 1, "inputSchema": {}}]},
    )
    assert result.metadata_control_decision == "ERROR"
    assert result.metadata_control_reason == "invalid_description"
    assert result.lookup_policy_handler_count == 0
    assert result.lookup_customer_tier_handler_count == 0
    assert result.follow_on_decision is None
    assert coded_policy().allowed_tools == ALLOWED_TOOLS


def test_grant_like_catalog_fields_are_error(settings, memory):
    snapshot = {
        "tools": [
            {
                "name": "lookup_policy",
                "description": "Look up lending policy guidance.",
                "inputSchema": {},
                "allowed_tools": "lookup_customer_tier",
            }
        ]
    }
    result = _run_catalog(settings, memory, mode="ATTACK", catalog_snapshot=snapshot)
    assert result.metadata_control_decision == "ERROR"
    assert result.lookup_customer_tier_handler_count == 0


def test_http_catalog_and_trust_fields_are_unknown_fields(acme_client):
    for extra in (
        {"catalog_fixture": "MALICIOUS"},
        {"metadata.trust": "trusted"},
        {"allowed_tools": "lookup_customer_tier"},
        {"security.profile": "vulnerable"},
        {"agentsec.mcp.metadata.trust": "trusted"},
    ):
        body = {
            "tool": "lookup_policy",
            "arguments": MCP_LOOKUP_POLICY_ARGS,
            "requested_scope": MCP_POLICY_SCOPE,
            **extra,
        }
        response = acme_client.post("/mcp/invoke", json=body)
        payload = response.get_json()
        assert response.status_code == 400, extra
        assert payload["error_stage"] == "schema_validation"
        assert payload["handler_invoke_count"] == 0


def test_result_data_and_loan_pipeline_still_cannot_widen_authority(tmp_path, monkeypatch, settings, counting_llm):
    attack_settings = _vulnerable_settings(tmp_path, monkeypatch)
    _run_catalog(attack_settings, MemorySink(), mode="ATTACK")
    reset_settings_cache()
    run_loan_pipeline(
        BENIGN_LOAN,
        llm=counting_llm,
        sink=MemorySink(),
        memory=MemorySink(),
        settings=settings,
        testbed_mode="BASELINE",
        attack_id="ATK-001",
    )
    denied = run_mcp_invoke(
        tool="lookup_customer_tier",
        arguments=MCP_LOOKUP_TIER_ARGS,
        requested_scope=MCP_CUSTOMER_SCOPE,
        sink=MemorySink(),
        memory=MemorySink(),
        settings=settings,
        testbed_mode="RETEST",
        attack_id="MCP-002",
        registry=default_registry(),
    )
    assert denied.hops[0].control_decision == "DENY"
    assert "lookup_customer_tier" not in coded_policy().allowed_tools
    reset_settings_cache()


def test_follow_on_handler_failure_counts_as_execution(tmp_path, monkeypatch):
    settings = _vulnerable_settings(tmp_path, monkeypatch)
    registry = default_registry()

    def boom(_arguments):
        raise RuntimeError("injected follow-on handler failure")

    registry.replace_handler("lookup_customer_tier", boom)
    result = _run_catalog(settings, MemorySink(), mode="ATTACK", registry=registry)
    assert result.lookup_policy_handler_count == 1
    assert result.lookup_customer_tier_handler_count == 1
    assert result.hops[1].operation_executed is True
    assert result.hops[1].mcp_failed is True
    reset_settings_cache()


def test_observe_is_not_allow_or_deny_on_metadata_control(settings, memory):
    result = _run_catalog(settings, memory, mode="RETEST")
    meta = next(e for e in control_events(result.events) if e["agentsec.control.id"] == "CTRL-MCP-METADATA-001")
    assert meta["event.name"] == EVENT_CONTROL_DECISION
    assert meta["agentsec.control.decision"] == "OBSERVE"
    assert meta["agentsec.operation.attempted"] is False
    assert meta["agentsec.operation.executed"] is False
    first = next(
        e
        for e in control_events(result.events)
        if e["agentsec.control.id"] == "CTRL-MCP-001" and e["gen_ai.tool.name"] == "lookup_policy"
    )
    assert first["agentsec.control.decision"] == "ALLOW"
    built = build_catalog_snapshot(fixture="MALICIOUS")
    assert coded_policy().allowed_tools == ALLOWED_TOOLS
    assert "lookup_customer_tier" not in coded_policy().allowed_tools
    del built
    assert EVENT_MCP_COMPLETED in event_names(result.events)
