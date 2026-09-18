"""CTRL-MCP-001: server-side allow-list before tool execution (INV-001 / INV-008)."""

from __future__ import annotations

from dataclasses import dataclass

from agentsec.mcp.metadata_trust import MCP_CATALOG_FAIL_OPEN_REASON, MetadataDerivedOverlay
from agentsec.mcp.policy import McpPolicy
from agentsec.mcp.result_trust import MCP005_FAIL_OPEN_REASON, ResultDerivedOverlay
from agentsec.mcp.tools import TOOL_SPECS
from agentsec.memory.trust import MEMORY_FAIL_OPEN_REASON, MemoryDerivedOverlay
from agentsec.rag.context_trust import RAG_FAIL_OPEN_REASON, ContextDerivedOverlay

CONTROL_ID = "CTRL-MCP-001"
CONTROL_TYPE = "mcp_allowlist"

VULNERABLE_FAIL_OPEN_PREFIX = "vulnerable_profile_fail_open:"
MCP002_FAIL_OPEN_REASON = (
    f"{VULNERABLE_FAIL_OPEN_PREFIX}CTRL-MCP-001 known tool "
)
MCP003_FAIL_OPEN_REASON = f"{VULNERABLE_FAIL_OPEN_PREFIX}scope_not_granted"
MCP004_FAIL_OPEN_REASON = f"{VULNERABLE_FAIL_OPEN_PREFIX}resource_not_granted"


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
    resource_id: str | None = None
    allowed_resource_ids: str | None = None

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
    result_derived_overlay: ResultDerivedOverlay | None = None,
    metadata_derived_overlay: MetadataDerivedOverlay | None = None,
    context_derived_overlay: ContextDerivedOverlay | None = None,
    memory_derived_overlay: MemoryDerivedOverlay | None = None,
) -> McpControlResult:
    """Exact set membership. No prefix, regex, lowercase, or strip matching.

    Order: tool exists → tool granted → requested_scope in catalog → in grant.

    A result-derived, metadata-derived, retrieved-context-derived, or
    memory-derived overlay, if present, is consulted only after the tool is
    known to exist. It cannot register unknown tools. It does not mutate
    policy. Overlay ALLOW uses the overlay's lab reason, never the
    MCP-002/003/004 fail-open strings.
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

    overlay_hit_result = result_derived_overlay is not None and result_derived_overlay.matches(
        tool_name, requested_scope
    )
    overlay_hit_metadata = metadata_derived_overlay is not None and metadata_derived_overlay.matches(
        tool_name, requested_scope
    )
    overlay_hit_context = context_derived_overlay is not None and context_derived_overlay.matches(
        tool_name, requested_scope
    )
    overlay_hit_memory = memory_derived_overlay is not None and memory_derived_overlay.matches(
        tool_name, requested_scope
    )
    overlay_hit = overlay_hit_result or overlay_hit_metadata or overlay_hit_context or overlay_hit_memory
    granted = tool_name in policy.allowed_tools
    if not granted:
        if overlay_hit:
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
            if overlay_hit_result:
                overlay_reason = MCP005_FAIL_OPEN_REASON
            elif overlay_hit_metadata:
                overlay_reason = MCP_CATALOG_FAIL_OPEN_REASON
            elif overlay_hit_context:
                overlay_reason = RAG_FAIL_OPEN_REASON
            else:
                overlay_reason = MEMORY_FAIL_OPEN_REASON
            return McpControlResult(
                control_id=CONTROL_ID,
                control_type=CONTROL_TYPE,
                decision="ALLOW",
                reason=overlay_reason,
                profile=profile,
                tool_name=tool_name,
                requested_scope=requested_scope,
                allowed_scope=allowed_scope,
            )
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


def authorize_resource(
    *,
    profile: str,
    policy: McpPolicy,
    resource_id: str,
    valid_resources: frozenset[str],
) -> tuple[str, str, str | None]:
    """Exact catalog then grant. No strip, lowercase, prefix, regex, or wildcard.

    Unknown catalog id → ERROR unknown_resource (no fail-open).
    Known ungranted → DENY resource_not_granted (vulnerable: MCP-004 fail-open).
    """
    if resource_id not in valid_resources:
        return "ERROR", "unknown_resource", "schema_validation"
    if resource_id not in policy.allowed_policy_ids:
        if profile == "vulnerable":
            return "ALLOW", MCP004_FAIL_OPEN_REASON, None
        return "DENY", "resource_not_granted", None
    return "ALLOW", "tool_granted", None


def evaluate_mcp_control(
    *,
    tool_name: str,
    requested_scope: str,
    profile: str,
    policy: McpPolicy,
    tool_registered: bool,
    authorize_fn=authorize_tool,
    valid_scopes: frozenset[str] | None = None,
    result_derived_overlay: ResultDerivedOverlay | None = None,
    metadata_derived_overlay: MetadataDerivedOverlay | None = None,
    context_derived_overlay: ContextDerivedOverlay | None = None,
    memory_derived_overlay: MemoryDerivedOverlay | None = None,
) -> McpControlResult:
    try:
        return authorize_fn(
            tool_name=tool_name,
            requested_scope=requested_scope,
            profile=profile,
            policy=policy,
            tool_registered=tool_registered,
            valid_scopes=valid_scopes,
            result_derived_overlay=result_derived_overlay,
            metadata_derived_overlay=metadata_derived_overlay,
            context_derived_overlay=context_derived_overlay,
            memory_derived_overlay=memory_derived_overlay,
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
