"""CTRL-MCP-001: server-side allow-list before tool execution (INV-001 / INV-008)."""

from __future__ import annotations

from dataclasses import dataclass

from agentsec.mcp.policy import McpPolicy
from agentsec.mcp.tools import TOOL_SPECS

CONTROL_ID = "CTRL-MCP-001"
CONTROL_TYPE = "mcp_allowlist"

VULNERABLE_FAIL_OPEN_PREFIX = "vulnerable_profile_fail_open:"
MCP002_FAIL_OPEN_REASON = (
    f"{VULNERABLE_FAIL_OPEN_PREFIX}CTRL-MCP-001 known tool "
)
MCP003_FAIL_OPEN_REASON = f"{VULNERABLE_FAIL_OPEN_PREFIX}scope_not_granted"


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


def _mcp002_fail_open_reason(tool_name: str) -> str:
    return (
        f"{MCP002_FAIL_OPEN_REASON}{tool_name} "
        "is not in mcp_policy_agent allowed_tools; lab profile intentionally "
        "returns ALLOW (fail-open) so the handler executes"
    )


def authorize_tool(
    *,
    tool_name: str,
    requested_scope: str,
    profile: str,
    policy: McpPolicy,
    tool_registered: bool,
    valid_scopes: frozenset[str] | None = None,
) -> McpControlResult:
    """Exact set membership. No prefix, regex, lowercase, or strip matching.

    Order: tool exists → tool granted → requested_scope in catalog → in grant.
    """
    allowed_scope = policy.allowed_scope_wire()
    catalog = valid_scopes
    if catalog is None and tool_registered:
        spec = TOOL_SPECS.get(tool_name)
        catalog = spec.valid_scopes if spec is not None else frozenset()
    if catalog is None:
        catalog = frozenset()

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
    if not granted:
        if profile == "vulnerable":
            return McpControlResult(
                control_id=CONTROL_ID,
                control_type=CONTROL_TYPE,
                decision="ALLOW",
                reason=_mcp002_fail_open_reason(tool_name),
                profile=profile,
                tool_name=tool_name,
                requested_scope=requested_scope,
                allowed_scope=allowed_scope,
            )
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

    if requested_scope not in catalog:
        return McpControlResult(
            control_id=CONTROL_ID,
            control_type=CONTROL_TYPE,
            decision="ERROR",
            reason="unknown_scope",
            profile=profile,
            tool_name=tool_name,
            requested_scope=requested_scope,
            allowed_scope=allowed_scope,
            error_stage="schema_validation",
        )

    if requested_scope not in policy.allowed_scopes:
        if profile == "vulnerable":
            return McpControlResult(
                control_id=CONTROL_ID,
                control_type=CONTROL_TYPE,
                decision="ALLOW",
                reason=MCP003_FAIL_OPEN_REASON,
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


def evaluate_mcp_control(
    *,
    tool_name: str,
    requested_scope: str,
    profile: str,
    policy: McpPolicy,
    tool_registered: bool,
    authorize_fn=authorize_tool,
    valid_scopes: frozenset[str] | None = None,
) -> McpControlResult:
    try:
        return authorize_fn(
            tool_name=tool_name,
            requested_scope=requested_scope,
            profile=profile,
            policy=policy,
            tool_registered=tool_registered,
            valid_scopes=valid_scopes,
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
