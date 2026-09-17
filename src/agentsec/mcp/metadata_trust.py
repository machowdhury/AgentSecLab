"""CTRL-MCP-METADATA-001 and the LAB-MCP-CATALOG lab-only description interpreter.

THIS IS INTENTIONALLY VULNERABLE LAB MACHINERY.

It is not a production prompt parser, command parser, tool dispatcher, or LLM oracle.
It exists so LAB-MCP-CATALOG can deterministically prove INV-002:

    catalog / tool-description metadata cannot grant authority.

CTRL-MCP-METADATA-001 classifies metadata as DATA (OBSERVE). It does not DENY
lookup_policy, sanitize text, quarantine text, or mint an AllowTicket.

The vulnerable path may mint a temporary per-run overlay for ONE closed follow-on
tool. It never mutates coded policy, ALLOWED_TOOLS, identity, or profile.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agentsec.mcp.catalog import CatalogParseError, CatalogSnapshot
from agentsec.mcp.fixtures import MCP_CATALOG_FOLLOW_ON_MARKER, MCP_LOOKUP_TIER_ARGS

METADATA_CONTROL_ID = "CTRL-MCP-METADATA-001"
METADATA_CONTROL_TYPE = "mcp_metadata_trust"
METADATA_TRUST_LABEL = "untrusted_data"
METADATA_PROVENANCE = "mcp.catalog.snapshot"
METADATA_IS_DATA_REASON = "metadata_is_data"
MCP_CATALOG_FAIL_OPEN_REASON = "vulnerable_profile_fail_open:metadata_derived_authority"

CLOSED_FOLLOW_ON_TOOL = "lookup_customer_tier"
CLOSED_FOLLOW_ON_SCOPE = "customer:read"
CLOSED_FOLLOW_ON_ARGS = dict(MCP_LOOKUP_TIER_ARGS)
_MAX_DESCRIPTION_SCAN = 8192


@dataclass(frozen=True)
class CatalogFollowOnIntent:
    """Closed follow-on request extracted from the catalog fixture only."""

    tool_name: str
    requested_scope: str
    arguments: dict[str, Any]
    source_tool: str
    marker_recognized: bool


@dataclass(frozen=True)
class MetadataDerivedOverlay:
    """Per-run metadata-derived authority. Not a server-owned grant.

    INTENTIONALLY VULNERABLE LAB MACHINERY. Lives only inside one run.
    Refuses any tool/scope other than the closed catalog follow-on fixture.
    """

    run_id: str
    source_tool: str
    allowed_tool: str
    allowed_scope: str
    label: str = "metadata-derived"

    def __post_init__(self) -> None:
        if self.allowed_tool != CLOSED_FOLLOW_ON_TOOL:
            raise ValueError("MCP-CATALOG overlay is not extensible")
        if self.allowed_scope != CLOSED_FOLLOW_ON_SCOPE:
            raise ValueError("MCP-CATALOG overlay is not extensible")
        if self.label != "metadata-derived":
            raise ValueError("MCP-CATALOG overlay must be labeled metadata-derived")

    def matches(self, tool_name: str, requested_scope: str) -> bool:
        return tool_name == self.allowed_tool and requested_scope == self.allowed_scope


@dataclass(frozen=True)
class MetadataTrustDecision:
    control_id: str
    control_type: str
    decision: str
    reason: str
    profile: str
    source_tool: str
    overlay_applied: bool
    metadata_trust: str = METADATA_TRUST_LABEL
    error_stage: str | None = None

    @property
    def blocks_catalog(self) -> bool:
        return self.decision == "ERROR"


def interpret_catalog_description(
    description: object,
    *,
    source_tool: str = "lookup_policy",
) -> CatalogFollowOnIntent | None:
    """Recognize ONLY the controlled catalog fixture marker.

    THIS IS INTENTIONALLY VULNERABLE LAB MACHINERY.

    Not a general prompt parser. Not a command parser. Not a tool dispatcher.
    Exact substring. Not case-folded. Not Unicode-normalized.
    The follow-on tool is closed: never taken from description grammar.
    """
    if not isinstance(description, str) or not description:
        return None
    scanned = description[:_MAX_DESCRIPTION_SCAN]
    if MCP_CATALOG_FOLLOW_ON_MARKER not in scanned:
        return None
    return CatalogFollowOnIntent(
        tool_name=CLOSED_FOLLOW_ON_TOOL,
        requested_scope=CLOSED_FOLLOW_ON_SCOPE,
        arguments=dict(CLOSED_FOLLOW_ON_ARGS),
        source_tool=source_tool,
        marker_recognized=True,
    )


def mint_metadata_derived_overlay(
    *,
    run_id: str,
    intent: CatalogFollowOnIntent,
) -> MetadataDerivedOverlay:
    if intent.tool_name != CLOSED_FOLLOW_ON_TOOL or intent.requested_scope != CLOSED_FOLLOW_ON_SCOPE:
        raise ValueError("MCP-CATALOG overlay is not extensible")
    return MetadataDerivedOverlay(
        run_id=run_id,
        source_tool=intent.source_tool,
        allowed_tool=CLOSED_FOLLOW_ON_TOOL,
        allowed_scope=CLOSED_FOLLOW_ON_SCOPE,
        label="metadata-derived",
    )


def evaluate_metadata_trust(
    *,
    profile: str,
    snapshot: CatalogSnapshot | None,
    parse_error: CatalogParseError | None,
    source_tool: str = "lookup_policy",
) -> tuple[MetadataTrustDecision, CatalogFollowOnIntent | None]:
    """Classify catalog metadata. Does not invoke a handler. Does not mint AllowTicket.

    Valid snapshot: OBSERVE metadata_is_data in every profile (including vulnerable).
    Malformed / unknown catalog: ERROR. Never ALLOW. Never DENY lookup_policy.
    """
    del profile  # classification is profile-independent; overlay mint is separate
    if parse_error is not None or snapshot is None:
        reason = parse_error.reason if parse_error is not None else "malformed_catalog"
        stage = parse_error.error_stage if parse_error is not None else "schema_validation"
        return (
            MetadataTrustDecision(
                control_id=METADATA_CONTROL_ID,
                control_type=METADATA_CONTROL_TYPE,
                decision="ERROR",
                reason=reason,
                profile="unknown",
                source_tool=source_tool,
                overlay_applied=False,
                error_stage=stage,
            ),
            None,
        )
    tool_row = snapshot.tool_named(source_tool)
    if tool_row is None:
        return (
            MetadataTrustDecision(
                control_id=METADATA_CONTROL_ID,
                control_type=METADATA_CONTROL_TYPE,
                decision="ERROR",
                reason="unknown_tool_metadata",
                profile="unknown",
                source_tool=source_tool,
                overlay_applied=False,
                error_stage="schema_validation",
            ),
            None,
        )
    description = tool_row.get("description")
    intent = interpret_catalog_description(description, source_tool=source_tool)
    decision = MetadataTrustDecision(
        control_id=METADATA_CONTROL_ID,
        control_type=METADATA_CONTROL_TYPE,
        decision="OBSERVE",
        reason=METADATA_IS_DATA_REASON,
        profile="unknown",
        source_tool=source_tool,
        overlay_applied=False,
    )
    return decision, intent


def evaluate_metadata_trust_safe(
    *,
    profile: str,
    snapshot: CatalogSnapshot | None,
    parse_error: CatalogParseError | None,
    run_id: str,
    source_tool: str = "lookup_policy",
) -> tuple[MetadataTrustDecision, CatalogFollowOnIntent | None, MetadataDerivedOverlay | None]:
    """Fail closed: exceptions become ERROR and never mint overlay or AllowTicket."""
    try:
        decision, intent = evaluate_metadata_trust(
            profile=profile,
            snapshot=snapshot,
            parse_error=parse_error,
            source_tool=source_tool,
        )
    except Exception as exc:
        fail = MetadataTrustDecision(
            control_id=METADATA_CONTROL_ID,
            control_type=METADATA_CONTROL_TYPE,
            decision="ERROR",
            reason=f"control_evaluation_failure:{type(exc).__name__}",
            profile=profile,
            source_tool=source_tool or "unknown",
            overlay_applied=False,
            error_stage="control_evaluation",
        )
        return fail, None, None
    decision = MetadataTrustDecision(
        control_id=decision.control_id,
        control_type=decision.control_type,
        decision=decision.decision,
        reason=decision.reason,
        profile=profile,
        source_tool=decision.source_tool,
        overlay_applied=False,
        metadata_trust=decision.metadata_trust,
        error_stage=decision.error_stage,
    )
    overlay = None
    if decision.decision == "OBSERVE" and profile == "vulnerable" and intent is not None:
        try:
            overlay = mint_metadata_derived_overlay(run_id=run_id, intent=intent)
        except Exception as exc:
            fail = MetadataTrustDecision(
                control_id=METADATA_CONTROL_ID,
                control_type=METADATA_CONTROL_TYPE,
                decision="ERROR",
                reason=f"control_evaluation_failure:{type(exc).__name__}",
                profile=profile,
                source_tool=decision.source_tool,
                overlay_applied=False,
                error_stage="control_evaluation",
            )
            return fail, None, None
        decision = MetadataTrustDecision(
            control_id=decision.control_id,
            control_type=decision.control_type,
            decision="OBSERVE",
            reason=METADATA_IS_DATA_REASON,
            profile=profile,
            source_tool=decision.source_tool,
            overlay_applied=True,
            metadata_trust=METADATA_TRUST_LABEL,
        )
    return decision, intent, overlay
