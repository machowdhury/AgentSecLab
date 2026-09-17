"""CTRL-DELEGATION-001: delegated authority before a deputy MCP operation (INV-001).

Coded Credit caller may ask Compliance to run lookup_policy.
Compliance ambient also includes lookup_customer_tier.
Defended path consults the delegated set only.
Vulnerable path substitutes ambient deputy authority (labeled fail-open).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from agentsec.agents import COMPLIANCE, COMPLIANCE_ID, CREDIT, CREDIT_ID
from agentsec.mcp.fixtures import MCP_CUSTOMER_ID, MCP_POLICY_ID
from agentsec.mcp.policy import McpPolicy

CONTROL_ID = "CTRL-DELEGATION-001"
CONTROL_TYPE = "mcp_delegation"

DELEGATION_GRANTED_REASON = "delegation_granted"
DELEGATION_DENIED_REASON = "delegated_authority_not_granted"
MCP006_FAIL_OPEN_REASON = "vulnerable_profile_fail_open:ambient_deputy_authority"
UNKNOWN_CALLER_REASON = "unknown_caller"
UNKNOWN_DEPUTY_REASON = "unknown_deputy"
MISSING_CONTEXT_REASON = "missing_delegation_context"
MALFORMED_REASON = "malformed_delegation"
CONTROL_ERROR_REASON = "delegation_control_error"

AUTHORITY_DELEGATED = "delegated"
AUTHORITY_AMBIENT_DEPUTY = "ambient_deputy"

CODED_CALLER_ID = CREDIT_ID
CODED_CALLER_NAME = CREDIT.name
CODED_DEPUTY_ID = COMPLIANCE_ID
CODED_DEPUTY_NAME = COMPLIANCE.name
CODED_DELEGATOR_ID = CREDIT_ID

KNOWN_CALLER_IDS = frozenset({CREDIT_ID})
KNOWN_DEPUTY_IDS = frozenset({COMPLIANCE_ID})

DELEGATED_TOOLS = frozenset({"lookup_policy"})
DELEGATED_SCOPES = frozenset({"policy:read"})
DELEGATED_POLICY_IDS = frozenset({MCP_POLICY_ID})

DEPUTY_AMBIENT_TOOLS = frozenset({"lookup_policy", "lookup_customer_tier"})
DEPUTY_AMBIENT_SCOPES = frozenset({"policy:read", "customer:read"})
DEPUTY_AMBIENT_POLICY_IDS = frozenset({MCP_POLICY_ID})

CLIENT_AUTHORITY_KEYS = frozenset(
    {
        "allowed_tools",
        "allowed_scopes",
        "allowed_resources",
        "delegated_permissions",
        "delegated_authority",
        "deputy_authority",
        "ambient_authority",
        "effective_authority",
        "authority_source",
        "caller_agent",
        "delegator_agent",
        "deputy_agent",
        "caller_id",
        "deputy_id",
        "delegator",
        "agent_id",
        "gen_ai.agent.id",
        "effective_identity",
    }
)


@dataclass
class DelegationRequest:
    """Lab-runner request. Not HTTP JSON. Tests may mutate after evaluate; the ticket must not."""

    principal_id: str
    caller_agent_id: str
    deputy_agent_id: str
    tool: object
    requested_scope: object
    arguments: object
    extra: dict[str, Any] | None = None


@dataclass(frozen=True)
class DelegationTicket:
    """Immutable check/use bind. Minted only after CTRL-DELEGATION-001 ALLOW."""

    principal_id: str
    caller_agent_id: str
    deputy_agent_id: str
    tool: str
    requested_scope: str
    resource_id: str
    arguments: tuple[tuple[str, str], ...]
    authority_source: str
    decision: str
    reason: str

    def arguments_dict(self) -> dict[str, str]:
        return dict(self.arguments)


@dataclass(frozen=True)
class DelegationControlResult:
    control_id: str
    control_type: str
    decision: str
    reason: str
    profile: str
    tool_name: str
    requested_scope: str
    allowed_scope: str
    authority_source: str | None = None
    error_stage: str | None = None
    resource_id: str | None = None
    ticket: DelegationTicket | None = None

    @property
    def blocks_deputy(self) -> bool:
        return self.decision in ("DENY", "ERROR")


def delegated_policy() -> McpPolicy:
    """What Credit may ask Compliance to do. Not Compliance's ambient grant."""
    return McpPolicy(
        agent_id=COMPLIANCE_ID,
        allowed_tools=DELEGATED_TOOLS,
        allowed_scopes=DELEGATED_SCOPES,
        allowed_policy_ids=DELEGATED_POLICY_IDS,
    )


def deputy_ambient_policy() -> McpPolicy:
    """What Compliance may do for itself. Must not be effective authority on defended path."""
    return McpPolicy(
        agent_id=COMPLIANCE_ID,
        allowed_tools=DEPUTY_AMBIENT_TOOLS,
        allowed_scopes=DEPUTY_AMBIENT_SCOPES,
        allowed_policy_ids=DEPUTY_AMBIENT_POLICY_IDS,
    )


def caller_authority_policy() -> McpPolicy:
    """Credit's own grant (not the execute path). Distinct from deputy ambient."""
    return McpPolicy(
        agent_id=CREDIT_ID,
        allowed_tools=DELEGATED_TOOLS,
        allowed_scopes=DELEGATED_SCOPES,
        allowed_policy_ids=DELEGATED_POLICY_IDS,
    )


def grant_snapshot() -> dict[str, object]:
    delegated = delegated_policy()
    ambient = deputy_ambient_policy()
    caller = caller_authority_policy()
    return {
        "caller.tools": frozenset(caller.allowed_tools),
        "caller.scopes": frozenset(caller.allowed_scopes),
        "caller.resources": frozenset(caller.allowed_policy_ids),
        "delegated.tools": frozenset(delegated.allowed_tools),
        "delegated.scopes": frozenset(delegated.allowed_scopes),
        "delegated.resources": frozenset(delegated.allowed_policy_ids),
        "ambient.tools": frozenset(ambient.allowed_tools),
        "ambient.scopes": frozenset(ambient.allowed_scopes),
        "ambient.resources": frozenset(ambient.allowed_policy_ids),
    }


def coded_delegation_request(
    *,
    tool: str,
    arguments: dict[str, Any],
    requested_scope: str,
    principal_id: str,
) -> DelegationRequest:
    return DelegationRequest(
        principal_id=principal_id,
        caller_agent_id=CODED_CALLER_ID,
        deputy_agent_id=CODED_DEPUTY_ID,
        tool=tool,
        requested_scope=requested_scope,
        arguments=dict(arguments),
    )


def resource_id_from_arguments(tool: str, arguments: dict[str, Any]) -> str:
    if tool == "lookup_policy":
        value = arguments.get("policy_id")
    elif tool == "lookup_customer_tier":
        value = arguments.get("customer_id")
    else:
        value = arguments.get("policy_id") or arguments.get("customer_id")
    if isinstance(value, str) and value:
        return value
    return ""


def policy_for_authority_source(source: str) -> McpPolicy:
    if source == AUTHORITY_AMBIENT_DEPUTY:
        return deputy_ambient_policy()
    return delegated_policy()


def bind_deputy_call(ticket: DelegationTicket) -> tuple[str, str, dict[str, str], str]:
    """Downstream MCP must use ticket fields, not a later-mutated request."""
    return ticket.tool, ticket.requested_scope, ticket.arguments_dict(), ticket.deputy_agent_id


def evaluate_delegation(
    *,
    request: DelegationRequest,
    profile: str,
) -> DelegationControlResult:
    malformed = _malformed_reason(request)
    if malformed:
        return _error_result(profile, MALFORMED_REASON, request, "schema_validation")

    missing = _missing_reason(request)
    if missing:
        return _error_result(profile, MISSING_CONTEXT_REASON, request, "argument_validation")

    caller = str(request.caller_agent_id)
    deputy = str(request.deputy_agent_id)
    tool = str(request.tool)
    scope = str(request.requested_scope)
    arguments = dict(request.arguments)  # type: ignore[arg-type]
    resource_id = resource_id_from_arguments(tool, arguments)
    allowed_scope = delegated_policy().allowed_scope_wire()

    if caller not in KNOWN_CALLER_IDS:
        return _error_result(profile, UNKNOWN_CALLER_REASON, request, "schema_validation", tool=tool, scope=scope)
    if deputy not in KNOWN_DEPUTY_IDS:
        return _error_result(profile, UNKNOWN_DEPUTY_REASON, request, "schema_validation", tool=tool, scope=scope)

    in_delegated = tool in DELEGATED_TOOLS
    in_ambient = tool in DEPUTY_AMBIENT_TOOLS
    if in_delegated:
        source = AUTHORITY_DELEGATED
        reason = DELEGATION_GRANTED_REASON
        decision = "ALLOW"
    elif profile == "vulnerable" and in_ambient:
        source = AUTHORITY_AMBIENT_DEPUTY
        reason = MCP006_FAIL_OPEN_REASON
        decision = "ALLOW"
    else:
        source = AUTHORITY_DELEGATED
        reason = DELEGATION_DENIED_REASON
        decision = "DENY"

    ticket = None
    if decision == "ALLOW":
        frozen_args = tuple(sorted((str(k), str(v)) for k, v in arguments.items() if isinstance(v, str)))
        ticket = DelegationTicket(
            principal_id=str(request.principal_id),
            caller_agent_id=caller,
            deputy_agent_id=deputy,
            tool=tool,
            requested_scope=scope,
            resource_id=resource_id,
            arguments=frozen_args,
            authority_source=source,
            decision=decision,
            reason=reason,
        )
    return DelegationControlResult(
        control_id=CONTROL_ID,
        control_type=CONTROL_TYPE,
        decision=decision,
        reason=reason,
        profile=profile,
        tool_name=tool,
        requested_scope=scope,
        allowed_scope=allowed_scope,
        authority_source=source,
        resource_id=resource_id or None,
        ticket=ticket,
        error_stage=None,
    )


def evaluate_delegation_safe(
    *,
    request: DelegationRequest,
    profile: str,
    evaluate_fn: Callable[..., DelegationControlResult] | None = None,
) -> DelegationControlResult:
    fn = evaluate_fn or evaluate_delegation
    try:
        return fn(request=request, profile=profile)
    except Exception:
        return _error_result(profile, CONTROL_ERROR_REASON, request, "control_evaluation")


def _malformed_reason(request: DelegationRequest) -> str | None:
    extra = request.extra or {}
    if any(key in CLIENT_AUTHORITY_KEYS for key in extra):
        return MALFORMED_REASON
    if not isinstance(request.tool, str):
        return MALFORMED_REASON
    if not isinstance(request.requested_scope, str):
        return MALFORMED_REASON
    if not isinstance(request.arguments, dict):
        return MALFORMED_REASON
    if any(not isinstance(key, str) for key in request.arguments):
        return MALFORMED_REASON
    if any(isinstance(value, dict) for value in request.arguments.values()):
        return MALFORMED_REASON
    if not isinstance(request.principal_id, str):
        return MALFORMED_REASON
    if not isinstance(request.caller_agent_id, str):
        return MALFORMED_REASON
    if not isinstance(request.deputy_agent_id, str):
        return MALFORMED_REASON
    return None


def _missing_reason(request: DelegationRequest) -> str | None:
    if not str(request.caller_agent_id).strip():
        return MISSING_CONTEXT_REASON
    if not str(request.deputy_agent_id).strip():
        return MISSING_CONTEXT_REASON
    if not str(request.tool).strip():
        return MISSING_CONTEXT_REASON
    if not str(request.requested_scope).strip():
        return MISSING_CONTEXT_REASON
    if not str(request.principal_id).strip():
        return MISSING_CONTEXT_REASON
    return None


def _error_result(
    profile: str,
    reason: str,
    request: DelegationRequest,
    error_stage: str,
    *,
    tool: str | None = None,
    scope: str | None = None,
) -> DelegationControlResult:
    tool_name = tool if tool else (request.tool if isinstance(request.tool, str) and request.tool.strip() else "unknown")
    requested_scope = (
        scope
        if scope
        else (
            request.requested_scope
            if isinstance(request.requested_scope, str) and request.requested_scope.strip()
            else "unspecified"
        )
    )
    return DelegationControlResult(
        control_id=CONTROL_ID,
        control_type=CONTROL_TYPE,
        decision="ERROR",
        reason=reason,
        profile=profile,
        tool_name=tool_name,
        requested_scope=requested_scope,
        allowed_scope=delegated_policy().allowed_scope_wire(),
        authority_source=None,
        error_stage=error_stage,
        ticket=None,
    )
