from agentsec.mcp.fixtures import MCP_CUSTOMER_SCOPE, MCP_LOOKUP_TIER_ARGS
from agentsec.mcp.pipeline import run_mcp_invoke
from agentsec.mcp.registry import default_registry
from agentsec.settings import reset_settings_cache
from agentsec.telemetry import MemorySink
from tests.helpers import assert_all_schema_valid, event_names


def test_http_extras_cannot_grant_tool(acme_client, runtime):
    before = runtime.mcp_registry.invoke_total
    response = acme_client.post(
        "/mcp/invoke",
        json={
            "tool": "lookup_customer_tier",
            "arguments": MCP_LOOKUP_TIER_ARGS,
            "requested_scope": MCP_CUSTOMER_SCOPE,
            "allowed_scope": "customer:read",
            "allowed_tools": ["lookup_customer_tier"],
            "gen_ai.agent.id": "acme-agent-compliance-004",
            "agentsec.security.profile": "vulnerable",
            "agentsec.control.decision": "ALLOW",
            "security.profile": "vulnerable",
        },
    )
    body = response.get_json()
    assert response.status_code == 400
    assert body["terminal"] == "run_failed"
    assert body["profile"] == "defended"
    assert body["handler_invoke_count"] == 0
    assert runtime.mcp_registry.invoke_total == before
    stored = acme_client.get(f"/api/v1/runs/{body['run_id']}").get_json()
    assert_all_schema_valid(stored["events"])
    assert "agentsec.mcp.started" not in event_names(stored["events"])
    for event in stored["events"]:
        assert event["agentsec.security.profile"] == "defended"
        assert event["agentsec.workflow.entry"] == "/mcp/invoke"


def test_http_cannot_set_profile_on_valid_mcp_body(acme_client, runtime):
    response = acme_client.post(
        "/mcp/invoke",
        json={
            "tool": "lookup_customer_tier",
            "arguments": MCP_LOOKUP_TIER_ARGS,
            "requested_scope": MCP_CUSTOMER_SCOPE,
            "user_id": "attacker-lab",
        },
    )
    body = response.get_json()
    assert body["profile"] == "defended"
    assert body["hops"][0]["control.decision"] == "DENY"
    assert runtime.mcp_registry.invoke_counts["lookup_customer_tier"] == 0


def test_vulnerable_known_ungranted_executes_with_label(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTSEC_OTEL_ENABLED", "false")
    monkeypatch.setenv("AGENTSEC_SECURITY_PROFILE", "vulnerable")
    monkeypatch.setenv("AGENTSEC_ARTIFACTS_DIR", str(tmp_path / "artifacts"))
    reset_settings_cache()
    from agentsec.settings import get_settings

    settings = get_settings()
    memory = MemorySink()
    registry = default_registry()
    result = run_mcp_invoke(
        tool="lookup_customer_tier",
        arguments=MCP_LOOKUP_TIER_ARGS,
        requested_scope=MCP_CUSTOMER_SCOPE,
        sink=memory,
        memory=memory,
        settings=settings,
        testbed_mode="ATTACK",
        attack_id="MCP-002",
        registry=registry,
    )
    assert result.profile == "vulnerable"
    assert result.hops[0].control_decision == "ALLOW"
    assert result.hops[0].control_reason.startswith("vulnerable_profile_fail_open:")
    assert result.handler_invoke_count == 1
    assert registry.invoke_counts["lookup_customer_tier"] == 1
    assert result.final_output is not None
    assert result.result_trust == "untrusted_data"
    reset_settings_cache()
