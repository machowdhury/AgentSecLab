"""LAB-AGENT-DELEGATION-001: in-process A2A-shaped identity / delegation runtime.

This package models security semantics only. It is not HTTP A2A, OAuth, OIDC,
SPIFFE/SPIRE, or an Agent Card service.
"""

from agentsec.identity.fixtures import (
    CALLEE_AGENT_ID,
    CALLER_AGENT_ID,
    IDENTITY_ATTACK_ID,
    PRINCIPAL_ID,
)
from agentsec.identity.request import A2ADelegationRequest, parse_a2a_delegation_request
from agentsec.identity.trust import (
    IDENTITY_CONTROL_ID,
    IDENTITY_FAIL_OPEN_REASON,
    IdentityDerivedOverlay,
)

__all__ = [
    "A2ADelegationRequest",
    "CALLEE_AGENT_ID",
    "CALLER_AGENT_ID",
    "IDENTITY_ATTACK_ID",
    "IDENTITY_CONTROL_ID",
    "IDENTITY_FAIL_OPEN_REASON",
    "IdentityDerivedOverlay",
    "PRINCIPAL_ID",
    "parse_a2a_delegation_request",
]
