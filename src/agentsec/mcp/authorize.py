"""CTRL-MCP-001: server-side allow-list before tool execution (INV-001 / INV-008)."""

from __future__ import annotations

from dataclasses import dataclass

from agentsec.mcp.policy import McpPolicy

CONTROL_ID = "CTRL-MCP-001"
CONTROL_TYPE = "mcp_allowlist"

VULNERABLE_FAIL_OPEN_PREFIX = "vulnerable_profile_fail_open:"


@dataclass(frozen=True)
class McpControlResult:
    control_id: str
    control_type: str
    decision: str
    reason: str
    profile: str
    tool_name: str
    requested_scope: str
    allowed_scope: str
    error_stage: str | None = None

    @property
    def blocks_tool(self) -> bool:
        return self.decision in ("DENY", "ERROR")


def authorize_tool(
    *,
    tool_name: str,
    requested_scope: str,
    profile: str,
    policy: McpPolicy,
    tool_registered: bool,
) -> McpControlResult:
    allowed_scope = policy.allowed_scope_wire()
    if not tool_registered:
        return McpControlResult(
            control_id=CONTROL_ID,
            control_type=CONTROL_TYPE,
            decision="ERROR",
            reason="unknown_tool",
            profile=profile,
            tool_name=tool_name,
            requested_scope=requested_scope,
            allowed_scope=allowed_scope,
            error_stage="schema_validation",
        )

    granted = tool_name in policy.allowed_tools
    scope_ok = requested_scope in policy.allowed_scopes

    if granted and scope_ok:
        return McpControlResult(
            control_id=CONTROL_ID,
            control_type=CONTROL_TYPE,
            decision="ALLOW",
            reason="tool_granted",
            profile=profile,
            tool_name=tool_name,
            requested_scope=requested_scope,
            allowed_scope=allowed_scope,
        )

    if (not granted) and profile == "vulnerable":
        return McpControlResult(
            control_id=CONTROL_ID,
            control_type=CONTROL_TYPE,
            decision="ALLOW",
            reason=(
                f"{VULNERABLE_FAIL_OPEN_PREFIX}CTRL-MCP-001 known tool {tool_name} "
                "is not in mcp_policy_agent allowed_tools; lab profile intentionally "
                "returns ALLOW (fail-open) so the handler executes"
            ),
            profile=profile,
            tool_name=tool_name,
            requested_scope=requested_scope,
            allowed_scope=allowed_scope,
        )

    if not granted:
        return McpControlResult(
            control_id=CONTROL_ID,
            control_type=CONTROL_TYPE,
            decision="DENY",
            reason="tool_not_granted",
            profile=profile,
            tool_name=tool_name,
            requested_scope=requested_scope,
            allowed_scope=allowed_scope,
        )

    return McpControlResult(
        control_id=CONTROL_ID,
        control_type=CONTROL_TYPE,
        decision="DENY",
        reason="scope_not_granted",
        profile=profile,
        tool_name=tool_name,
        requested_scope=requested_scope,
        allowed_scope=allowed_scope,
    )


def evaluate_mcp_control(
    *,
    tool_name: str,
    requested_scope: str,
    profile: str,
    policy: McpPolicy,
    tool_registered: bool,
    authorize_fn=authorize_tool,
) -> McpControlResult:
    try:
        return authorize_fn(
            tool_name=tool_name,
            requested_scope=requested_scope,
            profile=profile,
            policy=policy,
            tool_registered=tool_registered,
        )
    except Exception as exc:
        return McpControlResult(
            control_id=CONTROL_ID,
            control_type=CONTROL_TYPE,
            decision="ERROR",
            reason=f"control_evaluation_failure:{type(exc).__name__}",
            profile=profile,
            tool_name=tool_name or "unknown",
            requested_scope=requested_scope or "unspecified",
            allowed_scope=policy.allowed_scope_wire(),
            error_stage="control_evaluation",
        )
