from agentsec.mcp.fixtures import MCP_LOOKUP_POLICY_RESTRICTED_ARGS, MCP_POLICY_SCOPE


def test_mcp004_restricted_resource_http_defended(acme_client, runtime):
    response = acme_client.post(
        "/mcp/invoke",
        json={
            "tool": "lookup_policy",
            "arguments": MCP_LOOKUP_POLICY_RESTRICTED_ARGS,
            "requested_scope": MCP_POLICY_SCOPE,
        },
    )
    body = response.get_json()
    assert response.status_code == 200
    assert body["attack_id"] == "MCP-004"
    assert body["testbed_mode"] == "ATTACK"
    assert body["hops"][0]["control.decision"] == "DENY"
    assert body["hops"][0]["control.reason"] == "resource_not_granted"
    assert body["handler_invoke_count"] == 0
    assert runtime.mcp_registry.invoke_counts["lookup_policy"] == 0


def test_duplicate_json_keys_rejected_before_authorize(acme_client, runtime):
    before = runtime.mcp_registry.invoke_total
    raw = (
        '{"tool":"lookup_policy","arguments":{"policy_id":"lending-basics",'
        '"policy_id":"executive-restricted"},"requested_scope":"policy:read"}'
    )
    response = acme_client.post("/mcp/invoke", data=raw, content_type="application/json")
    body = response.get_json()
    assert response.status_code == 400
    assert body["block_reason"] == "duplicate_json_keys"
    assert body["handler_invoke_count"] == 0
    assert runtime.mcp_registry.invoke_total == before
    stored = acme_client.get(f"/api/v1/runs/{body['run_id']}").get_json()
    names = [event["event.name"] for event in stored["events"]]
    assert "agentsec.mcp.started" not in names
    assert "agentsec.control.decision" not in names
