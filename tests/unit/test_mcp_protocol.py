from agentsec.mcp.client import McpClient
from agentsec.mcp.protocol import decode_tools_call
from agentsec.mcp.server import McpServer
from agentsec.mcp.registry import default_registry


def test_client_encodes_tools_call_without_grants():
    message = McpClient().tools_call(name="lookup_policy", arguments={"policy_id": "lending-basics"})
    parsed, err = decode_tools_call(message)
    assert err == ""
    assert parsed is not None
    assert parsed.method == "tools/call"
    assert parsed.name == "lookup_policy"
    assert "allowed_scope" not in parsed.raw_params
    assert "agent_id" not in parsed.raw_params


def test_server_ignores_identity_and_grant_fields_in_params():
    registry = default_registry()
    server = McpServer(registry=registry)
    rpc = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "lookup_customer_tier",
            "arguments": {"customer_id": "cust-001"},
            "agent_id": "acme-agent-compliance-004",
            "allowed_scope": "customer:read,admin:*",
            "allowed_tools": ["lookup_customer_tier"],
        },
    }
    decision = server.authorize(
        rpc,
        profile="defended",
        requested_scope="customer:read",
        coded_agent_id="ignored-from-client",
    )
    assert decision.control.decision == "DENY"
    assert decision.ticket is None
    assert registry.invoke_total == 0
    execution = server.execute(decision.ticket)
    assert execution.began is False
    assert registry.invoke_total == 0
