"""CTRL-IDENTITY-001: classify identity/delegation claims as untrusted data.

THIS CONTROL NEVER AUTHORIZES A TOOL.

OBSERVE means the claim was recorded. It is not ALLOW, not DENY, not a
verified identity, and not a grant. Overlay minting is a separate LAB
vulnerable-profile path consumed only by CTRL-MCP-001.
"""

from __future__ import annotations

from dataclasses import dataclass

from agentsec.identity.fixtures import (
    CLAIM_IS_NOT_GRANT_REASON,
    CLAIM_TRUST,
    CLOSED_PRIVILEGED_RESOURCE,
    CLOSED_PRIVILEGED_SCOPE,
    CLOSED_PRIVILEGED_TOOL,
)
from agentsec.identity.request import A2ADelegationRequest

IDENTITY_CONTROL_ID = "CTRL-IDENTITY-001"
IDENTITY_CONTROL_TYPE = "identity_claim_trust"
IDENTITY_FAIL_OPEN_REASON = "vulnerable_profile_fail_open:caller_identity_derived_authority"


@dataclass(frozen=True)
class IdentityDerivedOverlay:
    """Per-request caller-identity-derived authority. Not a server-owned grant.

    INTENTIONALLY VULNERABLE LAB MACHINERY. Lives only inside one run.
    Closed to lookup_customer_tier / customer:read / cust-001.
    """

    run_id: str
    allowed_tool: str
    allowed_scope: str
    allowed_resource: str
    request_fingerprint: str
    label: str = "caller-identity-derived"

    def __post_init__(self) -> None:
        if self.allowed_tool != CLOSED_PRIVILEGED_TOOL:
            raise ValueError("identity overlay is not extensible")
        if self.allowed_scope != CLOSED_PRIVILEGED_SCOPE:
            raise ValueError("identity overlay is not extensible")
        if self.allowed_resource != CLOSED_PRIVILEGED_RESOURCE:
            raise ValueError("identity overlay is not extensible")
        if self.label != "caller-identity-derived":
            raise ValueError("identity overlay must be labeled caller-identity-derived")

    def matches(self, tool_name: str, requested_scope: str) -> bool:
        return tool_name == self.allowed_tool and requested_scope == self.allowed_scope

    def matches_resource(self, resource_id: str) -> bool:
        return resource_id == self.allowed_resource


@dataclass(frozen=True)
class IdentityTrustDecision:
    control_id: str
    control_type: str
    decision: str
    reason: str
    profile: str
    claim_trust: str
    request: A2ADelegationRequest | None
    overlay_applied: bool
    error_stage: str | None = None

    @property
    def blocks_follow_on(self) -> bool:
        return self.decision in ("DENY", "ERROR")


def evaluate_identity_claim(
    *,
    request: A2ADelegationRequest,
    profile: str,
) -> IdentityTrustDecision:
    """Classify the frozen claim. Never ALLOW/DENY a tool. Never mint AllowTicket."""
    del profile
    return IdentityTrustDecision(
        control_id=IDENTITY_CONTROL_ID,
        control_type=IDENTITY_CONTROL_TYPE,
        decision="OBSERVE",
        reason=CLAIM_IS_NOT_GRANT_REASON,
        profile="unused",
        claim_trust=CLAIM_TRUST,
        request=request,
        overlay_applied=False,
        error_stage=None,
    )


def evaluate_identity_claim_safe(
    *,
    request: A2ADelegationRequest | None,
    profile: str,
    parse_error: str | None = None,
    parse_stage: str | None = None,
) -> IdentityTrustDecision:
    if parse_error:
        return IdentityTrustDecision(
            control_id=IDENTITY_CONTROL_ID,
            control_type=IDENTITY_CONTROL_TYPE,
            decision="ERROR",
            reason=parse_error,
            profile=profile,
            claim_trust=CLAIM_TRUST,
            request=None,
            overlay_applied=False,
            error_stage=parse_stage or "schema_validation",
        )
    try:
        if request is None:
            raise ValueError("missing frozen identity request")
        decision = evaluate_identity_claim(request=request, profile=profile)
        return IdentityTrustDecision(
            control_id=decision.control_id,
            control_type=decision.control_type,
            decision=decision.decision,
            reason=decision.reason,
            profile=profile,
            claim_trust=decision.claim_trust,
            request=request,
            overlay_applied=False,
            error_stage=None,
        )
    except Exception as exc:
        return IdentityTrustDecision(
            control_id=IDENTITY_CONTROL_ID,
            control_type=IDENTITY_CONTROL_TYPE,
            decision="ERROR",
            reason=f"control_evaluation_failure:{type(exc).__name__}",
            profile=profile,
            claim_trust=CLAIM_TRUST,
            request=None,
            overlay_applied=False,
            error_stage="control_evaluation",
        )


def mint_identity_overlay(
    *,
    request: A2ADelegationRequest,
    run_id: str,
    profile: str,
) -> IdentityDerivedOverlay | None:
    """LAB-only. Closed triple. Does not mutate coded policy. Does not persist."""
    if profile != "vulnerable":
        return None
    if (
        request.requested_tool != CLOSED_PRIVILEGED_TOOL
        or request.requested_scope != CLOSED_PRIVILEGED_SCOPE
        or request.resource != CLOSED_PRIVILEGED_RESOURCE
    ):
        return None
    return IdentityDerivedOverlay(
        run_id=run_id,
        allowed_tool=CLOSED_PRIVILEGED_TOOL,
        allowed_scope=CLOSED_PRIVILEGED_SCOPE,
        allowed_resource=CLOSED_PRIVILEGED_RESOURCE,
        request_fingerprint=request.fingerprint,
    )
