"""Deterministic MCP-001 / MCP-002 request shapes. Not prompt strings."""

MCP_POLICY_ID = "lending-basics"
MCP_CUSTOMER_ID = "cust-001"
MCP_LOOKUP_POLICY_ARGS = {"policy_id": MCP_POLICY_ID}
MCP_LOOKUP_TIER_ARGS = {"customer_id": MCP_CUSTOMER_ID}
MCP_POLICY_SCOPE = "policy:read"
MCP_CUSTOMER_SCOPE = "customer:read"
