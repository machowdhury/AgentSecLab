"""Coded MCP grants. Request JSON cannot supply or widen these values."""

from __future__ import annotations

from dataclasses import dataclass

MCP_AGENT_ID = "acme-agent-mcp-001"
MCP_AGENT_NAME = "MCP Policy Agent"
MCP_AGENT_DESCRIPTION = "Dedicated LAB-MCP-001 agent. Not a loan-pipeline hop."

ALLOWED_TOOLS = frozenset({"lookup_policy"})
ALLOWED_SCOPES = frozenset({"policy:read"})
ALLOWED_SCOPE_WIRE = "policy:read"


@dataclass(frozen=True)
class McpPolicy:
    agent_id: str
    allowed_tools: frozenset[str]
    allowed_scopes: frozenset[str]

    def allowed_scope_wire(self) -> str:
        return ",".join(sorted(self.allowed_scopes))


def coded_policy() -> McpPolicy:
    """Server-owned policy for the dedicated MCP agent."""
    return McpPolicy(
        agent_id=MCP_AGENT_ID,
        allowed_tools=ALLOWED_TOOLS,
        allowed_scopes=ALLOWED_SCOPES,
    )


def policy_unchanged_by_result(policy: McpPolicy, _tool_result: object) -> McpPolicy:
    """INV-002: tool results are data. They never become a new grant object."""
    del _tool_result
    return policy
