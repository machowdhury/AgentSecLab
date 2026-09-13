from agentsec.mcp.fixtures import (
    MCP_LOOKUP_POLICY_ARGS,
    MCP_LOOKUP_TIER_ARGS,
    MCP_POLICY_SCOPE,
    MCP_CUSTOMER_SCOPE,
)
from tests.helpers import assert_all_schema_valid, event_names


def test_mcp_invoke_authorized_http(acme_client, runtime):
    response = acme_client.post(
        "/mcp/invoke",
        json={
            "tool": "lookup_policy",
            "arguments": MCP_LOOKUP_POLICY_ARGS,
            "requested_scope": MCP_POLICY_SCOPE,
            "user_id": "learner",
        },
    )
    body = response.get_json()
    assert response.status_code == 200
    assert body["attack_id"] == "MCP-001"
    assert body["testbed_mode"] == "BASELINE"
    assert body["handler_invoke_count"] == 1
    assert body["hops"][0]["control.decision"] == "ALLOW"
    assert runtime.mcp_registry.invoke_counts["lookup_policy"] == 1
    stored = acme_client.get(f"/api/v1/runs/{body['run_id']}").get_json()
    assert_all_schema_valid(stored["events"])
    assert "agentsec.mcp.started" in event_names(stored["events"])


def test_mcp_invoke_unauthorized_http_defended(acme_client, runtime):
    response = acme_client.post(
        "/mcp/invoke",
        json={
            "tool": "lookup_customer_tier",
            "arguments": MCP_LOOKUP_TIER_ARGS,
            "requested_scope": MCP_CUSTOMER_SCOPE,
        },
    )
    body = response.get_json()
    assert response.status_code == 200
    assert body["attack_id"] == "MCP-002"
    assert body["testbed_mode"] == "ATTACK"
    assert body["hops"][0]["control.decision"] == "DENY"
    assert body["handler_invoke_count"] == 0
    assert "agentsec.mcp.started" not in event_names(
        acme_client.get(f"/api/v1/runs/{body['run_id']}").get_json()["events"]
    )
