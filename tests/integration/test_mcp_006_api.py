"""HTTP boundary still rejects identity/grant injection and duplicate keys."""

from __future__ import annotations


def test_identity_spoof_fields_are_unknown_fields(acme_client):
    response = acme_client.post(
        "/mcp/invoke",
        json={
            "tool": "lookup_policy",
            "arguments": {"policy_id": "lending-basics"},
            "requested_scope": "policy:read",
            "caller_agent": "acme-agent-compliance-004",
            "deputy_agent": "acme-agent-compliance-004",
        },
    )
    body = response.get_json()
    assert response.status_code == 400
    assert body["error_stage"] == "schema_validation"
    assert body["block_reason"] == "unknown_fields"
    assert body["handler_invoke_count"] == 0


def test_authority_injection_fields_are_unknown_fields(acme_client):
    response = acme_client.post(
        "/mcp/invoke",
        json={
            "tool": "lookup_customer_tier",
            "arguments": {"customer_id": "cust-001"},
            "requested_scope": "customer:read",
            "allowed_tools": ["lookup_customer_tier"],
            "delegated_authority": "lookup_customer_tier",
            "ambient_authority": "lookup_customer_tier",
            "effective_authority": "admin",
            "authority_source": "delegated",
        },
    )
    body = response.get_json()
    assert response.status_code == 400
    assert body["block_reason"] == "unknown_fields"
    assert body["handler_invoke_count"] == 0


def test_duplicate_json_keys_rejected_before_authorize(acme_client):
    response = acme_client.post(
        "/mcp/invoke",
        data='{"tool":"lookup_policy","tool":"lookup_customer_tier","arguments":{"policy_id":"lending-basics"},"requested_scope":"policy:read"}',
        content_type="application/json",
    )
    body = response.get_json()
    assert response.status_code == 400
    assert body["block_reason"] == "duplicate_json_keys"
    assert body["handler_invoke_count"] == 0
    assert body["error_stage"] == "schema_validation"
