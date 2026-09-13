from agentsec.mcp.fixtures import MCP_LOOKUP_POLICY_ARGS, MCP_POLICY_RESTRICTED_SCOPE, MCP_POLICY_SCOPE
from tests.helpers import assert_all_schema_valid, event_names


def test_http_restricted_scope_defended_denies(acme_client, runtime):
    response = acme_client.post(
        "/mcp/invoke",
        json={
            "tool": "lookup_policy",
            "arguments": MCP_LOOKUP_POLICY_ARGS,
            "requested_scope": MCP_POLICY_RESTRICTED_SCOPE,
            "user_id": "learner",
        },
    )
    body = response.get_json()
    assert response.status_code == 200
    assert body["attack_id"] == "MCP-003"
    assert body["testbed_mode"] == "ATTACK"
    assert body["hops"][0]["control.decision"] == "DENY"
    assert body["hops"][0]["control.reason"] == "scope_not_granted"
    assert body["handler_invoke_count"] == 0
    assert runtime.mcp_registry.invoke_counts["lookup_policy"] == 0
    stored = acme_client.get(f"/api/v1/runs/{body['run_id']}").get_json()
    assert_all_schema_valid(stored["events"])
    assert "agentsec.mcp.started" not in event_names(stored["events"])


def test_http_client_allowed_scope_does_not_override(acme_client, runtime):
    before = runtime.mcp_registry.invoke_total
    response = acme_client.post(
        "/mcp/invoke",
        json={
            "tool": "lookup_policy",
            "arguments": MCP_LOOKUP_POLICY_ARGS,
            "requested_scope": MCP_POLICY_RESTRICTED_SCOPE,
            "allowed_scope": MCP_POLICY_RESTRICTED_SCOPE,
        },
    )
    body = response.get_json()
    assert response.status_code == 400
    assert body["terminal"] == "run_failed"
    assert body["block_reason"] == "unknown_fields"
    assert body["handler_invoke_count"] == 0
    assert runtime.mcp_registry.invoke_total == before


def test_http_profile_spoof_does_not_override_server_profile(acme_client, runtime):
    response = acme_client.post(
        "/mcp/invoke",
        json={
            "tool": "lookup_policy",
            "arguments": MCP_LOOKUP_POLICY_ARGS,
            "requested_scope": MCP_POLICY_RESTRICTED_SCOPE,
            "security.profile": "vulnerable",
            "agentsec.security.profile": "vulnerable",
        },
    )
    body = response.get_json()
    assert response.status_code == 400
    assert body["profile"] == "defended"
    assert body["handler_invoke_count"] == 0
    stored = acme_client.get(f"/api/v1/runs/{body['run_id']}").get_json()
    for event in stored["events"]:
        assert event["agentsec.security.profile"] == "defended"


def test_http_scope_only_in_arguments_does_not_grant(acme_client, runtime):
    response = acme_client.post(
        "/mcp/invoke",
        json={
            "tool": "lookup_policy",
            "arguments": {
                "policy_id": "lending-basics",
                "requested_scope": MCP_POLICY_RESTRICTED_SCOPE,
                "scope": MCP_POLICY_RESTRICTED_SCOPE,
            },
        },
    )
    body = response.get_json()
    assert response.status_code == 400
    assert body["block_reason"] == "missing_requested_scope"
    assert body["handler_invoke_count"] == 0
    assert runtime.mcp_registry.invoke_counts["lookup_policy"] == 0


def test_http_whitespace_scope_does_not_grant(acme_client, runtime):
    response = acme_client.post(
        "/mcp/invoke",
        json={
            "tool": "lookup_policy",
            "arguments": MCP_LOOKUP_POLICY_ARGS,
            "requested_scope": "policy:read ",
        },
    )
    body = response.get_json()
    assert body["hops"][0]["control.decision"] == "ERROR"
    assert body["hops"][0]["control.reason"] == "unknown_scope"
    assert body["handler_invoke_count"] == 0
    assert runtime.mcp_registry.invoke_total == 0


def test_http_baseline_policy_read_still_mcp_001(acme_client, runtime):
    response = acme_client.post(
        "/mcp/invoke",
        json={
            "tool": "lookup_policy",
            "arguments": MCP_LOOKUP_POLICY_ARGS,
            "requested_scope": MCP_POLICY_SCOPE,
        },
    )
    body = response.get_json()
    assert body["attack_id"] == "MCP-001"
    assert body["testbed_mode"] == "BASELINE"
    assert body["hops"][0]["control.decision"] == "ALLOW"
    assert body["handler_invoke_count"] == 1
