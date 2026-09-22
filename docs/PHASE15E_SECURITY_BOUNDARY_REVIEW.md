# Phase 15E — Security boundary review

CTRL-IDENTITY-001 remains OBSERVE `identity_claim_is_not_grant` / `untrusted_claim`.

It does **not**: ALLOW, DENY tool access, mint AllowTicket, authenticate the caller, verify cryptographic identity, modify `coded_policy()`, or grant scopes/tools.

CTRL-MCP-001 remains the sole TOOL PDP.

Client injection of authority-like fields is ERROR:

- profile, allowed_tools, allowed_scope, roles, permissions, grants, approved
- identity_verified, authenticated, delegated_grant
- caller/callee/principal substitution
- unknown fields, duplicate JSON keys, malformed experiment/claim
- overlay leakage: overlay is per-request; `coded_policy()` is unchanged after ATTACK
- concurrent ATTACK + RETEST: LIVE pair `110dd7a6-…` (vulnerable) and `7e4f74a8-…` (defended); distinct run.ids; no global policy mutation; AcmeBank health remained `security.profile=defended` afterward

HTTP never accepts the A2A body. Claim reconstruction is server-owned.

WHO AUTHENTICATED = NOT PROVEN / NOT MODELED. Do not emit `authenticated=true`.

No OAuth. No OIDC. No JWT validation. No SPIFFE/SPIRE. No real A2A transport.
