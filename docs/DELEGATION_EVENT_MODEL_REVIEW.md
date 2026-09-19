# Delegation / identity event model review

**Status:** Phase 12A **DESIGN**. Schema bump **implemented in 12B as 1.8.0**. This file remains design history; field names below were candidates. 12B resolutions are in `docs/SCHEMA_1_8_0.md`.

Parents: `docs/DELEGATION_LAB_SPECIFICATION.md`, `schemas/security_event.schema.json`.

---

## Reconstruction target

```text
principal → Agent A → A2A-shaped claim → Agent B → privileged request
        → CTRL-IDENTITY-001 OBSERVE → CTRL-MCP-001 → execution / non-execution
```

## Exists today (1.7.0) — do not invent duplicates

| Concept | Existing field | 12A decision |
|---------|----------------|--------------|
| Principal | `agentsec.principal.id`, `.type` | **REUSE** |
| Acting agent this hop | `gen_ai.agent.id` | **REUSE** (callee hop when B requests the tool) |
| Prior in-process hop | `agentsec.delegator.agent.id` | **REUSE later as attribution**; not A2A caller grant |
| Requested vs allowed scope | `agentsec.mcp.requested_scope`, `allowed_scope` | **REUSE** on MCP hop |
| MCP-006 authority set | `agentsec.delegation.authority.source` `delegated` \| `ambient_deputy` | **DO NOT OVERLOAD** |
| Run | `agentsec.run.id` | **REUSE** |
| Control | `agentsec.control.*` | **REUSE** + new control id/type in 1.8.0 |

## Missing — smallest 1.8.0 candidates (ideas, not committed names)

Only add in 12B if the runtime honestly populates them:

| Proposed idea | Why needed | Why not now |
|---------------|------------|-------------|
| `agentsec.identity.caller_agent_id` | Who requested (A) when B is the executing hop | Not in 1.7.0 as first-class A2A caller |
| `agentsec.identity.callee_agent_id` | Who was asked (B) | Hop agent id is B; caller still needed |
| `agentsec.identity.claim.trust` enum `untrusted_claim` | OBSERVE classification | Do not overload `memory_context_trust` / RAG enums |
| `agentsec.delegation.claimed_scope` | What the request **asked** to borrow | Distinct from `allowed_scope` |
| control type `identity_claim_trust` / CTRL-IDENTITY-001 | Observation control | New enum value requires 1.8.0 |
| attack id `A2A-001` | Closed attack enum | Schema bump |

Optional later (not first 1.8.0): `delegation.id`, `delegation.parent_id`, `delegation.provenance`, SPIFFE id, issuer/audience **without** token bodies.

## Do not invent

`session.id`, `invocation.id`, `tenant.id`, `gen_ai.tool.call.id`, `trusted_identity`, `delegation_granted=true` as a client field, JWT/access_token fields, `cryptographic_passport_valid`.

Grant snapshot `allowed_tools` remains a **TELEMETRY GAP**. Do not fake it.

## Privacy / secret model (locked)

**DO NOT INDEX OR PUT IN EVIDENCE PACKS:**

OAuth access / refresh / ID tokens, JWT bodies, API keys, cookies, `Authorization` headers, client secrets, private keys, certificates, full identity assertions, SVID bytes.

**MAY index (opaque):**

`principal.id`, agent ids, optional `delegation.id`, claimed/allowed **scope names**, resource ids, control decision/reason, issuer/audience **strings** only if a later lab models them without tokens.

If a token fingerprint is ever required: SHA-256 of bytes computed in-process, **never** the token. Prefer not to need it for A2A-001.

No hardcoded credentials. No fake production secrets. Lab “token” if mentioned in docs is the word `opaque` / `not-indexed`.

## Splunk questions (DESIGN ONLY — no SPL)

| Q | Question | Classification |
|---|----------|----------------|
| Q1 | Who initiated the delegation / A2A-shaped call? | **REQUIRES NEW TELEMETRY** (caller id first-class). PARTIALLY: hop-0 agent if a two-hop emit exists. |
| Q2 | Which principal was Agent A acting for? | **SUPPORTED NOW** (`principal.id`) if the runner copies it onto both hops |
| Q3 | Which agent called Agent B? | **REQUIRES NEW TELEMETRY** (caller vs `delegator.agent.id` semantics) |
| Q4 | What authority did Agent A possess? | **PARTIALLY SUPPORTED** (not indexed `allowed_tools`; coded docs only) |
| Q5 | What authority did A request B to exercise? | **PARTIALLY SUPPORTED** (`requested_scope` on B’s MCP hop) |
| Q6 | Did delegated/claimed authority expand vs coded grants? | **REQUIRES NEW TELEMETRY** + still no grant snapshot |
| Q7 | What scope/resource was requested? | **SUPPORTED NOW** on MCP control row |
| Q8 | What did CTRL-MCP-001 decide? | **SUPPORTED NOW** |
| Q9 | Did the handler start? | **SUPPORTED NOW** (`mcp.started`) as corroboration |
| Q10 | Complete or fail? | **SUPPORTED NOW** (`mcp.completed` / `mcp.failed`) |
| Q11 | Reconstruct the delegation chain? | **PARTIALLY SUPPORTED** (one hop). Multi-hop **NOT APPLICABLE** yet |
| Q12 | Did ATTACK and RETEST use the same request? | **REQUIRES** lab evidence docs + identical requested tool/scope/resource fields |
| Q13 | Which evidence proves authorization? | CTRL-MCP-001 row. **SUPPORTED NOW** once the hop exists |
| Q14 | Which evidence proves execution? | Runtime handler count **authoritative**; Splunk mcp.* **corroboration** |
| Q15 | Which evidence does NOT prove either? | Identity strings, OBSERVE, Agent Card, DET-MCP-001 silence, missing rows |

## CIM

**NOT APPLICABLE** for agentic identity-claim fields. Do not map `principal.id` to CIM `user` as if it were enterprise SSO.

## Stop

No `props.conf`, saved searches, or Studio datasources in 12A.

## 12B field-name resolution (implementation)

12B **ADDED** the candidate names above (caller/callee ids, `untrusted_claim`, `claimed_scope`, `identity_claim_trust`, `A2A-001`, `agent.identity.claim`, `identity_delegation_lab`, `/identity/delegate`).

**REJECTED** in 1.8.0: `session.id`, token fields, `authenticated=true`, `trusted_identity`, overloading `authority.source`.

**DEFERRED:** `delegation.id`, SPIFFE/issuer, grant snapshot `allowed_tools`.

See `docs/SCHEMA_1_8_0.md`. Splunk field discovery remains Phase 12C.

