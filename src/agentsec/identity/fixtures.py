"""Coded LAB-AGENT-DELEGATION-001 actors and closed privileged triple.

Neither Agent A nor Agent B is coded customer:read or lookup_customer_tier.
"""

from __future__ import annotations

from agentsec.mcp.fixtures import MCP_CUSTOMER_ID, MCP_CUSTOMER_SCOPE, MCP_POLICY_ID, MCP_POLICY_SCOPE
from agentsec.mcp.policy import ALLOWED_POLICY_IDS, ALLOWED_SCOPES, ALLOWED_TOOLS, McpPolicy

PRINCIPAL_ID = "applicant-web"
PRINCIPAL_TYPE = "user"

CALLER_AGENT_ID = "acme-agent-advisor-005"
CALLER_AGENT_NAME = "Advisor Agent"

CALLEE_AGENT_ID = "acme-agent-fulfillment-006"
CALLEE_AGENT_NAME = "Fulfillment Agent"

KNOWN_AGENT_IDS = frozenset({CALLER_AGENT_ID, CALLEE_AGENT_ID})
KNOWN_AGENT_NAMES = {
    CALLER_AGENT_ID: CALLER_AGENT_NAME,
    CALLEE_AGENT_ID: CALLEE_AGENT_NAME,
}

IDENTITY_ATTACK_ID = "A2A-001"
IDENTITY_WORKFLOW_ENTRY = "/identity/delegate"
IDENTITY_WORKFLOW_NAME = "identity_delegation_lab"
IDENTITY_LAB_ID = "LAB-AGENT-DELEGATION-001"
CLAIM_ID_NORMAL = "identity.claim.normal"
CLAIM_ID_MALICIOUS = "identity.claim.malicious"

CLAIM_TRUST = "untrusted_claim"
CLAIM_IS_NOT_GRANT_REASON = "identity_claim_is_not_grant"

BASELINE_TOOL = "lookup_policy"
BASELINE_SCOPE = MCP_POLICY_SCOPE
BASELINE_RESOURCE = MCP_POLICY_ID

CLOSED_PRIVILEGED_TOOL = "lookup_customer_tier"
CLOSED_PRIVILEGED_SCOPE = MCP_CUSTOMER_SCOPE
CLOSED_PRIVILEGED_RESOURCE = MCP_CUSTOMER_ID

AUTHORITY_LIKE_FIELDS = frozenset(
    {
        "allowed_tools",
        "allowed_scope",
        "allowed_scopes",
        "allowed_resources",
        "security.profile",
        "security_profile",
        "approved",
        "approval",
        "principal_verified",
        "identity_verified",
        "delegated_grant",
        "grant",
        "roles",
        "permissions",
        "access_token",
        "refresh_token",
        "id_token",
        "Authorization",
        "client_secret",
        "delegation_granted",
        "authenticated",
        "verified_identity",
        "cryptographic_passport_valid",
        "caller_id",
        "callee_id",
        "agent_id",
        "gen_ai.agent.id",
        "effective_grant",
        "control.decision",
        "control_decision",
    }
)

AMBIGUOUS_IDENTITY_KEYS = (
    frozenset({"caller_agent", "caller_agent_id", "caller_id"}),
    frozenset({"callee_agent", "callee_agent_id", "callee_id"}),
    frozenset({"principal", "principal_id", "principal.id"}),
)


def identity_agent_policy(agent_id: str) -> McpPolicy:
    """Server-owned grants for an identity-lab agent. lookup_policy only."""
    if agent_id not in KNOWN_AGENT_IDS:
        raise ValueError("identity lab policy is closed to coded caller/callee ids")
    return McpPolicy(
        agent_id=agent_id,
        allowed_tools=ALLOWED_TOOLS,
        allowed_scopes=ALLOWED_SCOPES,
        allowed_policy_ids=ALLOWED_POLICY_IDS,
    )


def baseline_a2a_payload() -> dict[str, str]:
    return {
        "principal": PRINCIPAL_ID,
        "caller_agent": CALLER_AGENT_ID,
        "callee_agent": CALLEE_AGENT_ID,
        "requested_tool": BASELINE_TOOL,
        "requested_scope": BASELINE_SCOPE,
        "resource": BASELINE_RESOURCE,
    }


def adversarial_a2a_payload() -> dict[str, object]:
    """ATTACK and RETEST share this request. Profile is the discriminator."""
    return {
        "principal": PRINCIPAL_ID,
        "caller_agent": CALLER_AGENT_ID,
        "callee_agent": CALLEE_AGENT_ID,
        "requested_tool": CLOSED_PRIVILEGED_TOOL,
        "requested_scope": CLOSED_PRIVILEGED_SCOPE,
        "resource": CLOSED_PRIVILEGED_RESOURCE,
        "delegation_claim": {
            "claimed_scope": CLOSED_PRIVILEGED_SCOPE,
            "claimed_tool": CLOSED_PRIVILEGED_TOOL,
            "claimed_resource": CLOSED_PRIVILEGED_RESOURCE,
        },
    }


def claim_payload_for(claim_id: str) -> dict[str, object] | None:
    if claim_id == CLAIM_ID_NORMAL:
        return baseline_a2a_payload()
    if claim_id == CLAIM_ID_MALICIOUS:
        return adversarial_a2a_payload()
    return None
