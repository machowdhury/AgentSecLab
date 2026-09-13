"""LAB-MCP-003: requested_scope vs coded grant. Handler spy is authoritative."""

from __future__ import annotations

from agentsec.events import EVENT_CONTROL_DECISION, EVENT_MCP_FAILED, EVENT_MCP_STARTED
from agentsec.mcp.authorize import MCP003_FAIL_OPEN_REASON
from agentsec.mcp.fixtures import (
    MCP_LOOKUP_POLICY_ARGS,
    MCP_LOOKUP_TIER_ARGS,
    MCP_POLICY_RESTRICTED_SCOPE,
    MCP_POLICY_SCOPE,
    MCP_CUSTOMER_SCOPE,
)
from agentsec.mcp.pipeline import run_mcp_invoke
from agentsec.mcp.registry import default_registry
from agentsec.settings import reset_settings_cache
from agentsec.telemetry import MemorySink
from tests.helpers import control_events, event_names, events_named


def _vulnerable_settings(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTSEC_OTEL_ENABLED", "false")
    monkeypatch.setenv("AGENTSEC_SECURITY_PROFILE", "vulnerable")
    monkeypatch.setenv("AGENTSEC_ARTIFACTS_DIR", str(tmp_path / "artifacts"))
    reset_settings_cache()
    from agentsec.settings import get_settings

    return get_settings()


def _deny_followed_by_mcp_started(events: list[dict]) -> bool:
    """Local DET-MCP-001 shape: DENY then later mcp.started same run/tool."""
    by_tool: dict[str, list[tuple[int, str, str]]] = {}
    for event in events:
        name = event.get("event.name")
        tool = event.get("gen_ai.tool.name")
        if not tool:
            continue
        seq = int(event["agentsec.sequence"])
        if name == EVENT_CONTROL_DECISION and event.get("agentsec.control.decision") == "DENY":
            by_tool.setdefault(tool, []).append((seq, "DENY", event["agentsec.run.id"]))
        if name == EVENT_MCP_STARTED:
            by_tool.setdefault(tool, []).append((seq, "STARTED", event["agentsec.run.id"]))
    for rows in by_tool.values():
        denials = [seq for seq, kind, _ in rows if kind == "DENY"]
        starts = [seq for seq, kind, _ in rows if kind == "STARTED"]
        if denials and any(start > min(denials) for start in starts):
            return True
    return False


def test_authorized_known_scope_executes(settings, memory):
    registry = default_registry()
    result = run_mcp_invoke(
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_ARGS,
        requested_scope=MCP_POLICY_SCOPE,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="BASELINE",
        attack_id="MCP-003",
        registry=registry,
    )
    assert result.hops[0].control_decision == "ALLOW"
    assert result.hops[0].control_reason == "tool_granted"
    assert result.expected_behavior.startswith("ALLOW lookup_policy")
    assert result.handler_invoke_count == 1
    assert registry.invoke_counts["lookup_policy"] == 1
    control = control_events(result.events)[0]
    assert control["agentsec.mcp.requested_scope"] == MCP_POLICY_SCOPE
    assert control["agentsec.mcp.allowed_scope"] == MCP_POLICY_SCOPE
    names = event_names(result.events)
    assert names.index(EVENT_CONTROL_DECISION) < names.index(EVENT_MCP_STARTED)


def test_known_excessive_scope_defended_deny(settings, memory):
    registry = default_registry()
    result = run_mcp_invoke(
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_ARGS,
        requested_scope=MCP_POLICY_RESTRICTED_SCOPE,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="RETEST",
        attack_id="MCP-003",
        registry=registry,
    )
    assert result.hops[0].control_decision == "DENY"
    assert result.hops[0].control_reason == "scope_not_granted"
    assert result.hops[0].operation_attempted is False
    assert result.hops[0].operation_executed is False
    assert result.hops[0].operation_outcome == "prevented"
    assert result.handler_invoke_count == 0
    assert registry.invoke_total == 0
    assert EVENT_MCP_STARTED not in event_names(result.events)
    control = control_events(result.events)[0]
    assert control["agentsec.mcp.requested_scope"] == MCP_POLICY_RESTRICTED_SCOPE
    assert control["agentsec.mcp.allowed_scope"] == MCP_POLICY_SCOPE
    assert _deny_followed_by_mcp_started(result.events) is False


def test_known_excessive_scope_vulnerable_labeled_allow_executes(tmp_path, monkeypatch):
    settings = _vulnerable_settings(tmp_path, monkeypatch)
    memory = MemorySink()
    registry = default_registry()
    result = run_mcp_invoke(
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_ARGS,
        requested_scope=MCP_POLICY_RESTRICTED_SCOPE,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="ATTACK",
        attack_id="MCP-003",
        registry=registry,
    )
    assert result.profile == "vulnerable"
    assert result.hops[0].control_decision == "ALLOW"
    assert result.hops[0].control_reason == MCP003_FAIL_OPEN_REASON
    assert result.handler_invoke_count == 1
    assert registry.invoke_counts["lookup_policy"] == 1
    names = event_names(result.events)
    assert names.index(EVENT_CONTROL_DECISION) < names.index(EVENT_MCP_STARTED)
    control = control_events(result.events)[0]
    assert control["agentsec.mcp.requested_scope"] == MCP_POLICY_RESTRICTED_SCOPE
    assert control["agentsec.mcp.allowed_scope"] == MCP_POLICY_SCOPE
    reset_settings_cache()


def test_unknown_scope_error_handler_zero(settings, memory):
    registry = default_registry()
    result = run_mcp_invoke(
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_ARGS,
        requested_scope="policy:write",
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="ATTACK",
        attack_id="MCP-003",
        registry=registry,
    )
    assert result.hops[0].control_decision == "ERROR"
    assert result.hops[0].control_reason == "unknown_scope"
    assert result.handler_invoke_count == 0
    assert registry.invoke_total == 0
    assert EVENT_MCP_STARTED not in event_names(result.events)


def test_malformed_scope_tokens_do_not_widen_authority(settings, memory):
    tokens = (
        "Policy:read",
        "policy:read ",
        " policy:read",
        "policy:*",
        "*",
        "policy",
        "policy:read,policy:restricted:read",
    )
    for token in tokens:
        registry = default_registry()
        mem = MemorySink()
        result = run_mcp_invoke(
            tool="lookup_policy",
            arguments=MCP_LOOKUP_POLICY_ARGS,
            requested_scope=token,
            sink=mem,
            memory=mem,
            settings=settings,
            testbed_mode="ATTACK",
            attack_id="MCP-003",
            registry=registry,
            write_evidence=False,
        )
        assert result.hops[0].control_decision == "ERROR", token
        assert result.hops[0].control_reason == "unknown_scope", token
        assert result.handler_invoke_count == 0, token
        assert registry.invoke_total == 0, token
        assert result.hops[0].operation_outcome == "prevented", token
        assert EVENT_MCP_STARTED not in event_names(result.events), token


def test_missing_scope_error_handler_zero(settings, memory):
    registry = default_registry()
    result = run_mcp_invoke(
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_ARGS,
        requested_scope="   ",
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="ATTACK",
        attack_id="MCP-003",
        registry=registry,
    )
    assert result.hops[0].control_decision == "ERROR"
    assert result.hops[0].control_reason == "missing_requested_scope"
    assert result.handler_invoke_count == 0
    assert registry.invoke_total == 0


def test_argument_supplied_scope_does_not_grant_authority(settings, memory):
    registry = default_registry()
    result = run_mcp_invoke(
        tool="lookup_policy",
        arguments={
            "policy_id": "lending-basics",
            "scope": MCP_POLICY_RESTRICTED_SCOPE,
            "allowed_scope": MCP_POLICY_RESTRICTED_SCOPE,
            "role": "admin",
            "authorization": MCP_POLICY_RESTRICTED_SCOPE,
        },
        requested_scope=MCP_POLICY_SCOPE,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="ATTACK",
        attack_id="MCP-003",
        registry=registry,
    )
    assert result.hops[0].control_decision == "ERROR"
    assert result.hops[0].control_reason == "malformed_arguments"
    assert result.handler_invoke_count == 0
    assert registry.invoke_total == 0
    assert EVENT_MCP_STARTED not in event_names(result.events)


def test_mcp002_and_mcp003_fail_open_paths_differ(tmp_path, monkeypatch):
    settings = _vulnerable_settings(tmp_path, monkeypatch)
    mcp002_reg = default_registry()
    mcp002_mem = MemorySink()
    mcp002 = run_mcp_invoke(
        tool="lookup_customer_tier",
        arguments=MCP_LOOKUP_TIER_ARGS,
        requested_scope=MCP_CUSTOMER_SCOPE,
        sink=mcp002_mem,
        memory=mcp002_mem,
        settings=settings,
        testbed_mode="ATTACK",
        attack_id="MCP-002",
        registry=mcp002_reg,
        write_evidence=False,
    )
    mcp003_reg = default_registry()
    mcp003_mem = MemorySink()
    mcp003 = run_mcp_invoke(
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_ARGS,
        requested_scope=MCP_POLICY_RESTRICTED_SCOPE,
        sink=mcp003_mem,
        memory=mcp003_mem,
        settings=settings,
        testbed_mode="ATTACK",
        attack_id="MCP-003",
        registry=mcp003_reg,
        write_evidence=False,
    )
    assert mcp002.hops[0].control_reason != mcp003.hops[0].control_reason
    assert "allowed_tools" in mcp002.hops[0].control_reason
    assert mcp003.hops[0].control_reason == MCP003_FAIL_OPEN_REASON
    reset_settings_cache()


def test_handler_failure_after_valid_allow_is_execution(settings, memory):
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
        attack_id="MCP-003",
        registry=registry,
    )
    assert result.handler_invoke_count == 1
    assert result.hops[0].control_decision == "ALLOW"
    assert result.hops[0].operation_executed is True
    assert result.hops[0].operation_outcome == "error"
    names = event_names(result.events)
    assert EVENT_MCP_STARTED in names
    assert EVENT_MCP_FAILED in names
    failed = events_named(result.events, EVENT_MCP_FAILED)[0]
    assert failed["agentsec.operation.executed"] is True
    assert failed["agentsec.operation.outcome"] == "error"


def test_control_failure_is_pre_execution_error(settings, memory):
    def boom(**kwargs):
        raise RuntimeError("injected mcp control failure")

    registry = default_registry()
    result = run_mcp_invoke(
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_ARGS,
        requested_scope=MCP_POLICY_RESTRICTED_SCOPE,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="ATTACK",
        attack_id="MCP-003",
        registry=registry,
        authorize_fn=boom,
    )
    assert result.hops[0].control_decision == "ERROR"
    assert "control_evaluation_failure" in result.hops[0].control_reason
    assert result.handler_invoke_count == 0
    assert registry.invoke_total == 0
    assert EVENT_MCP_STARTED not in event_names(result.events)


def test_deny_cannot_be_followed_by_mcp_started(settings, memory):
    registry = default_registry()
    result = run_mcp_invoke(
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_ARGS,
        requested_scope=MCP_POLICY_RESTRICTED_SCOPE,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="RETEST",
        attack_id="MCP-003",
        registry=registry,
    )
    assert result.hops[0].control_decision == "DENY"
    assert _deny_followed_by_mcp_started(result.events) is False
    assert registry.invoke_counts["lookup_policy"] == 0
