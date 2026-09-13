"""LAB-MCP-004: resource grant vs catalog. Handler spy is authoritative."""

from __future__ import annotations

from agentsec.events import EVENT_CONTROL_DECISION, EVENT_MCP_FAILED, EVENT_MCP_STARTED
from agentsec.mcp.authorize import MCP002_FAIL_OPEN_REASON, MCP003_FAIL_OPEN_REASON, MCP004_FAIL_OPEN_REASON
from agentsec.mcp.client import McpClient
from agentsec.mcp.fixtures import (
    MCP_CUSTOMER_SCOPE,
    MCP_LOOKUP_POLICY_ARGS,
    MCP_LOOKUP_POLICY_RESTRICTED_ARGS,
    MCP_LOOKUP_TIER_ARGS,
    MCP_POLICY_RESTRICTED_ID,
    MCP_POLICY_RESTRICTED_SCOPE,
    MCP_POLICY_SCOPE,
    MCP_POLICY_UNKNOWN_ID,
)
from agentsec.mcp.pipeline import run_mcp_invoke
from agentsec.mcp.policy import coded_policy
from agentsec.mcp.registry import default_registry
from agentsec.mcp.server import McpServer
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
    by_tool: dict[str, list[tuple[int, str]]] = {}
    for event in events:
        name = event.get("event.name")
        tool = event.get("gen_ai.tool.name")
        if not tool:
            continue
        seq = int(event["agentsec.sequence"])
        if name == EVENT_CONTROL_DECISION and event.get("agentsec.control.decision") == "DENY":
            by_tool.setdefault(tool, []).append((seq, "DENY"))
        if name == EVENT_MCP_STARTED:
            by_tool.setdefault(tool, []).append((seq, "STARTED"))
    for rows in by_tool.values():
        denials = [seq for seq, kind in rows if kind == "DENY"]
        starts = [seq for seq, kind in rows if kind == "STARTED"]
        if denials and any(start > min(denials) for start in starts):
            return True
    return False


def test_known_granted_resource_executes(settings, memory):
    registry = default_registry()
    result = run_mcp_invoke(
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_ARGS,
        requested_scope=MCP_POLICY_SCOPE,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="BASELINE",
        attack_id="MCP-004",
        registry=registry,
    )
    assert result.hops[0].control_decision == "ALLOW"
    assert result.hops[0].control_reason == "tool_granted"
    assert result.handler_invoke_count == 1
    assert registry.invoke_counts["lookup_policy"] == 1
    control = control_events(result.events)[0]
    assert control["agentsec.mcp.resource.id"] == "lending-basics"
    assert control["agentsec.mcp.allowed_resource.ids"] == "lending-basics"
    names = event_names(result.events)
    assert names.index(EVENT_CONTROL_DECISION) < names.index(EVENT_MCP_STARTED)
    assert result.final_output["policy_id"] == "lending-basics"


def test_known_ungranted_defended_deny(settings, memory):
    registry = default_registry()
    result = run_mcp_invoke(
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_RESTRICTED_ARGS,
        requested_scope=MCP_POLICY_SCOPE,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="RETEST",
        attack_id="MCP-004",
        registry=registry,
    )
    assert result.hops[0].control_decision == "DENY"
    assert result.hops[0].control_reason == "resource_not_granted"
    assert result.hops[0].operation_attempted is False
    assert result.hops[0].operation_executed is False
    assert result.hops[0].operation_outcome == "prevented"
    assert result.handler_invoke_count == 0
    assert registry.invoke_counts["lookup_policy"] == 0
    assert EVENT_MCP_STARTED not in event_names(result.events)
    control = control_events(result.events)[0]
    assert control["agentsec.mcp.resource.id"] == MCP_POLICY_RESTRICTED_ID
    assert control["agentsec.mcp.allowed_resource.ids"] == "lending-basics"


def test_known_ungranted_vulnerable_labeled_allow_executes(tmp_path, monkeypatch):
    settings = _vulnerable_settings(tmp_path, monkeypatch)
    registry = default_registry()
    memory = MemorySink()
    result = run_mcp_invoke(
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_RESTRICTED_ARGS,
        requested_scope=MCP_POLICY_SCOPE,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="ATTACK",
        attack_id="MCP-004",
        registry=registry,
    )
    assert result.hops[0].control_decision == "ALLOW"
    assert result.hops[0].control_reason == MCP004_FAIL_OPEN_REASON
    assert result.handler_invoke_count == 1
    assert registry.invoke_counts["lookup_policy"] == 1
    assert result.final_output["policy_id"] == MCP_POLICY_RESTRICTED_ID
    control = control_events(result.events)[0]
    assert control["agentsec.mcp.resource.id"] == MCP_POLICY_RESTRICTED_ID
    assert control["agentsec.mcp.allowed_resource.ids"] == "lending-basics"
    assert control["agentsec.mcp.allowed_resource.ids"] != control["agentsec.mcp.resource.id"]
    reset_settings_cache()


def test_unknown_resource_error(settings, memory):
    registry = default_registry()
    result = run_mcp_invoke(
        tool="lookup_policy",
        arguments={"policy_id": MCP_POLICY_UNKNOWN_ID},
        requested_scope=MCP_POLICY_SCOPE,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="ATTACK",
        attack_id="MCP-004",
        registry=registry,
    )
    assert result.hops[0].control_decision == "ERROR"
    assert result.hops[0].control_reason == "unknown_resource"
    assert result.handler_invoke_count == 0
    assert registry.invoke_total == 0
    assert EVENT_MCP_STARTED not in event_names(result.events)
    control = control_events(result.events)[0]
    assert control["agentsec.mcp.resource.id"] == MCP_POLICY_UNKNOWN_ID
    assert control["agentsec.mcp.allowed_resource.ids"] == "lending-basics"


def test_malformed_arguments_error(settings, memory):
    registry = default_registry()
    cases = (
        {},
        {"policy_id": 123},
        {"policy_id": "lending-basics", "extra": "no"},
        {"policy_id": ["lending-basics"]},
        {"policy_id": {"id": "lending-basics"}},
    )
    for arguments in cases:
        result = run_mcp_invoke(
            tool="lookup_policy",
            arguments=arguments,
            requested_scope=MCP_POLICY_SCOPE,
            sink=memory,
            memory=memory,
            settings=settings,
            testbed_mode="ATTACK",
            attack_id="MCP-004",
            registry=registry,
            write_evidence=False,
        )
        assert result.hops[0].control_decision == "ERROR", arguments
        assert result.hops[0].control_reason == "malformed_arguments"
        assert result.handler_invoke_count == 0
        assert EVENT_MCP_STARTED not in event_names(result.events)
    assert registry.invoke_total == 0


def test_case_whitespace_and_wildcard_cannot_widen(settings, memory):
    registry = default_registry()
    tokens = (
        "LENDING-BASICS",
        "lending-basics ",
        " lending-basics",
        "lending-basics%00",
        "lending*",
        "lending",
        "*",
    )
    for token in tokens:
        result = run_mcp_invoke(
            tool="lookup_policy",
            arguments={"policy_id": token},
            requested_scope=MCP_POLICY_SCOPE,
            sink=memory,
            memory=memory,
            settings=settings,
            testbed_mode="ATTACK",
            attack_id="MCP-004",
            registry=registry,
            write_evidence=False,
        )
        assert result.hops[0].control_decision == "ERROR", token
        assert result.hops[0].control_reason == "unknown_resource", token
        assert result.handler_invoke_count == 0
        control = control_events(result.events)[-1]
        assert control["agentsec.mcp.resource.id"] == token
        assert control["agentsec.mcp.allowed_resource.ids"] == "lending-basics"
    assert registry.invoke_total == 0


def test_client_and_argument_grants_cannot_widen(settings, memory, acme_client, runtime):
    response = acme_client.post(
        "/mcp/invoke",
        json={
            "tool": "lookup_policy",
            "arguments": MCP_LOOKUP_POLICY_RESTRICTED_ARGS,
            "requested_scope": MCP_POLICY_SCOPE,
            "allowed_policy_ids": ["executive-restricted"],
        },
    )
    body = response.get_json()
    assert response.status_code == 400
    assert body["block_reason"] == "unknown_fields"
    assert body["handler_invoke_count"] == 0

    registry = default_registry()
    result = run_mcp_invoke(
        tool="lookup_policy",
        arguments={
            "policy_id": MCP_POLICY_RESTRICTED_ID,
            "allowed_policy_ids": ["executive-restricted"],
            "authorized": True,
            "role": "admin",
        },
        requested_scope=MCP_POLICY_SCOPE,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="ATTACK",
        attack_id="MCP-004",
        registry=registry,
        write_evidence=False,
    )
    assert result.hops[0].control_decision == "ERROR"
    assert result.hops[0].control_reason == "malformed_arguments"
    assert result.handler_invoke_count == 0


def test_ticket_resource_equals_handler_resource(settings):
    seen: list[dict] = []

    def record(arguments):
        seen.append(dict(arguments))
        return {"policy_id": arguments["policy_id"], "found": True}

    registry = default_registry()
    registry.replace_handler("lookup_policy", record)
    server = McpServer(registry=registry, policy=coded_policy())
    client = McpClient()
    request_args = {"policy_id": "lending-basics"}
    rpc = client.tools_call(name="lookup_policy", arguments=request_args)
    decision = server.authorize(
        rpc,
        profile="defended",
        requested_scope=MCP_POLICY_SCOPE,
        coded_agent_id="acme-agent-mcp-001",
    )
    assert decision.control.decision == "ALLOW"
    assert decision.ticket is not None
    assert decision.ticket.resource_id == "lending-basics"
    request_args["policy_id"] = "executive-restricted"
    decision.ticket.arguments["policy_id"] = "executive-restricted"
    execution = server.execute(decision.ticket)
    assert execution.ok is True
    assert seen == [{"policy_id": "lending-basics"}]
    assert execution.payload["policy_id"] == "lending-basics"
    assert registry.invoke_counts["lookup_policy"] == 1


def test_resource_fail_open_preserves_allowed_ids(tmp_path, monkeypatch):
    settings = _vulnerable_settings(tmp_path, monkeypatch)
    memory = MemorySink()
    result = run_mcp_invoke(
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_RESTRICTED_ARGS,
        requested_scope=MCP_POLICY_SCOPE,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="ATTACK",
        attack_id="MCP-004",
        registry=default_registry(),
        write_evidence=False,
    )
    control = control_events(result.events)[0]
    assert control["agentsec.control.reason"] == MCP004_FAIL_OPEN_REASON
    assert control["agentsec.mcp.allowed_resource.ids"] == "lending-basics"
    reset_settings_cache()


def test_mcp002_003_004_reasons_differ_end_to_end(tmp_path, monkeypatch):
    settings = _vulnerable_settings(tmp_path, monkeypatch)
    mcp002 = run_mcp_invoke(
        tool="lookup_customer_tier",
        arguments=MCP_LOOKUP_TIER_ARGS,
        requested_scope=MCP_CUSTOMER_SCOPE,
        sink=MemorySink(),
        memory=MemorySink(),
        settings=settings,
        testbed_mode="ATTACK",
        attack_id="MCP-002",
        registry=default_registry(),
        write_evidence=False,
    )
    mcp003 = run_mcp_invoke(
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_ARGS,
        requested_scope=MCP_POLICY_RESTRICTED_SCOPE,
        sink=MemorySink(),
        memory=MemorySink(),
        settings=settings,
        testbed_mode="ATTACK",
        attack_id="MCP-003",
        registry=default_registry(),
        write_evidence=False,
    )
    mcp004 = run_mcp_invoke(
        tool="lookup_policy",
        arguments=MCP_LOOKUP_POLICY_RESTRICTED_ARGS,
        requested_scope=MCP_POLICY_SCOPE,
        sink=MemorySink(),
        memory=MemorySink(),
        settings=settings,
        testbed_mode="ATTACK",
        attack_id="MCP-004",
        registry=default_registry(),
        write_evidence=False,
    )
    assert mcp002.hops[0].control_reason.startswith(MCP002_FAIL_OPEN_REASON)
    assert mcp003.hops[0].control_reason == MCP003_FAIL_OPEN_REASON
    assert mcp004.hops[0].control_reason == MCP004_FAIL_OPEN_REASON
    assert len({mcp002.hops[0].control_reason, mcp003.hops[0].control_reason, mcp004.hops[0].control_reason}) == 3
    reset_settings_cache()


def test_handler_failure_after_allow_is_execution(settings, memory):
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
        attack_id="MCP-004",
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
        arguments=MCP_LOOKUP_POLICY_RESTRICTED_ARGS,
        requested_scope=MCP_POLICY_SCOPE,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="ATTACK",
        attack_id="MCP-004",
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
        arguments=MCP_LOOKUP_POLICY_RESTRICTED_ARGS,
        requested_scope=MCP_POLICY_SCOPE,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="RETEST",
        attack_id="MCP-004",
        registry=registry,
    )
    assert result.hops[0].control_decision == "DENY"
    assert _deny_followed_by_mcp_started(result.events) is False
    assert registry.invoke_counts["lookup_policy"] == 0
