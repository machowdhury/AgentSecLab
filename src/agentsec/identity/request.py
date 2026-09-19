"""Typed in-process A2A-shaped request. Extra keys are ERROR, not grants."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from agentsec.events import content_hash
from agentsec.identity.fixtures import (
    AMBIGUOUS_IDENTITY_KEYS,
    AUTHORITY_LIKE_FIELDS,
    CALLEE_AGENT_ID,
    CALLER_AGENT_ID,
    CLAIM_TRUST,
    KNOWN_AGENT_IDS,
    PRINCIPAL_ID,
    PRINCIPAL_TYPE,
)

ALLOWED_A2A_FIELDS = frozenset(
    {
        "principal",
        "caller_agent",
        "callee_agent",
        "requested_tool",
        "requested_scope",
        "resource",
        "delegation_claim",
    }
)

ALLOWED_DELEGATION_CLAIM_FIELDS = frozenset(
    {
        "claimed_scope",
        "claimed_tool",
        "claimed_resource",
    }
)


@dataclass(frozen=True)
class A2ADelegationRequest:
    """Immutable snapshot used for both identity OBSERVE and follow-on MCP authorize."""

    principal_id: str
    principal_type: str
    caller_agent_id: str
    callee_agent_id: str
    requested_tool: str
    requested_scope: str
    resource: str
    claimed_scope: str
    claimed_tool: str
    claimed_resource: str
    fingerprint: str

    def canonical_dict(self) -> dict[str, str]:
        return {
            "principal": self.principal_id,
            "caller_agent": self.caller_agent_id,
            "callee_agent": self.callee_agent_id,
            "requested_tool": self.requested_tool,
            "requested_scope": self.requested_scope,
            "resource": self.resource,
            "claimed_scope": self.claimed_scope,
            "claimed_tool": self.claimed_tool,
            "claimed_resource": self.claimed_resource,
            "claim_trust": CLAIM_TRUST,
        }

    def tool_arguments(self) -> dict[str, str]:
        if self.requested_tool == "lookup_policy":
            return {"policy_id": self.resource}
        if self.requested_tool == "lookup_customer_tier":
            return {"customer_id": self.resource}
        return {"resource": self.resource}


@dataclass(frozen=True)
class ParsedA2ADelegationRequest:
    ok: bool
    request: A2ADelegationRequest | None
    error_reason: str
    extra_fields: tuple[str, ...]
    error_stage: str | None = "schema_validation"


def parse_a2a_delegation_request(data: object) -> ParsedA2ADelegationRequest:
    """Validate shape before any security decision. Never copy extra keys into grants."""
    if not isinstance(data, dict):
        return _error("malformed_input")

    authority_extra = tuple(
        sorted(str(key) for key in data.keys() if key in AUTHORITY_LIKE_FIELDS and key not in ALLOWED_A2A_FIELDS)
    )
    if authority_extra:
        return _error("unknown_fields", extra=authority_extra)

    ambiguous = _ambiguous_identity_keys(data)
    if ambiguous:
        return _error("ambiguous_identity_keys", extra=ambiguous)

    extra = tuple(sorted(str(key) for key in data.keys() if key not in ALLOWED_A2A_FIELDS))
    if extra:
        return _error("unknown_fields", extra=extra)

    principal = data.get("principal")
    caller = data.get("caller_agent")
    callee = data.get("callee_agent")
    tool = data.get("requested_tool")
    scope = data.get("requested_scope")
    resource = data.get("resource")
    claim_obj = data.get("delegation_claim", None)

    if principal is None:
        return _error("missing_principal")
    if caller is None:
        return _error("missing_caller")
    if callee is None:
        return _error("missing_callee")
    if not isinstance(principal, str) or not principal.strip():
        return _error("missing_principal")
    if not isinstance(caller, str) or not caller.strip():
        return _error("missing_caller")
    if not isinstance(callee, str) or not callee.strip():
        return _error("missing_callee")
    if principal != PRINCIPAL_ID:
        return _error("unknown_principal")
    if caller not in KNOWN_AGENT_IDS:
        return _error("unknown_caller")
    if callee not in KNOWN_AGENT_IDS:
        return _error("unknown_callee")
    if caller == callee:
        return _error("unsupported_self_delegation")
    if caller != CALLER_AGENT_ID:
        return _error("unknown_caller")
    if callee != CALLEE_AGENT_ID:
        return _error("unknown_callee")

    if not isinstance(tool, str):
        return _error("empty_requested_tool" if tool in (None, "") else "invalid_tool_type")
    if not tool.strip():
        return _error("empty_requested_tool")
    if not isinstance(scope, str):
        return _error("invalid_scope_type")
    if not scope.strip():
        return _error("invalid_scope_type")
    if not isinstance(resource, str):
        return _error("invalid_resource")
    if not resource.strip():
        return _error("invalid_resource")

    claimed_scope = scope
    claimed_tool = tool
    claimed_resource = resource
    if claim_obj is not None:
        claim = _parse_delegation_claim(claim_obj)
        if isinstance(claim, str):
            return _error(claim)
        claimed_scope, claimed_tool, claimed_resource = claim
        if not claimed_scope:
            claimed_scope = scope
        if not claimed_tool:
            claimed_tool = tool
        if not claimed_resource:
            claimed_resource = resource

    snapshot = {
        "principal": principal,
        "caller_agent": caller,
        "callee_agent": callee,
        "requested_tool": tool,
        "requested_scope": scope,
        "resource": resource,
        "claimed_scope": claimed_scope,
        "claimed_tool": claimed_tool,
        "claimed_resource": claimed_resource,
        "claim_trust": CLAIM_TRUST,
    }
    request = A2ADelegationRequest(
        principal_id=principal,
        principal_type=PRINCIPAL_TYPE,
        caller_agent_id=caller,
        callee_agent_id=callee,
        requested_tool=tool,
        requested_scope=scope,
        resource=resource,
        claimed_scope=claimed_scope,
        claimed_tool=claimed_tool,
        claimed_resource=claimed_resource,
        fingerprint=content_hash(json.dumps(snapshot, sort_keys=True, separators=(",", ":"))),
    )
    return ParsedA2ADelegationRequest(
        ok=True,
        request=request,
        error_reason="",
        extra_fields=(),
        error_stage=None,
    )


def _parse_delegation_claim(claim_obj: object) -> tuple[str, str, str] | str:
    if not isinstance(claim_obj, dict):
        return "malformed_delegation_claim"
    extra = tuple(sorted(str(key) for key in claim_obj.keys() if key not in ALLOWED_DELEGATION_CLAIM_FIELDS))
    if extra:
        if any(key in AUTHORITY_LIKE_FIELDS for key in extra):
            return "unknown_fields"
        return "malformed_delegation_claim"
    claimed_scope = claim_obj.get("claimed_scope")
    claimed_tool = claim_obj.get("claimed_tool")
    claimed_resource = claim_obj.get("claimed_resource")
    if claimed_scope is None and claimed_tool is None and claimed_resource is None:
        return "malformed_delegation_claim"
    if claimed_scope is not None and not isinstance(claimed_scope, str):
        return "invalid_scope_type"
    if claimed_tool is not None and not isinstance(claimed_tool, str):
        return "malformed_delegation_claim"
    if claimed_resource is not None and not isinstance(claimed_resource, str):
        return "invalid_resource"
    return (
        claimed_scope if isinstance(claimed_scope, str) and claimed_scope.strip() else "",
        claimed_tool if isinstance(claimed_tool, str) and claimed_tool.strip() else "",
        claimed_resource if isinstance(claimed_resource, str) and claimed_resource.strip() else "",
    )


def _ambiguous_identity_keys(data: dict[str, Any]) -> tuple[str, ...]:
    found: list[str] = []
    for group in AMBIGUOUS_IDENTITY_KEYS:
        present = sorted(key for key in group if key in data)
        if len(present) > 1:
            found.extend(present)
    return tuple(found)


def _error(reason: str, extra: tuple[str, ...] = ()) -> ParsedA2ADelegationRequest:
    return ParsedA2ADelegationRequest(
        ok=False,
        request=None,
        error_reason=reason,
        extra_fields=extra,
        error_stage="schema_validation",
    )
