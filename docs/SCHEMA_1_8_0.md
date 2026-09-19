# Schema 1.8.0 migration

**Status:** Phase 12B **IMPLEMENTED**. Phase 12C Splunk extraction **OBSERVED**.  
**File:** `schemas/security_event.schema.json`  
**Emitter:** `agentsec.schema.version` const **1.8.0** (`src/agentsec/experiment.py` `SCHEMA_VERSION`).  
**Evidence class:** pytest schema validation is **MEASURED**. Splunk field names: **OBSERVED** (`docs/PHASE12C_AGENT_DELEGATION_SPLUNK_VALIDATION.md`).

Parents: `docs/SCHEMA_1_7_0.md`, `docs/DELEGATION_EVENT_MODEL_REVIEW.md`.

---

## Why bump

Phase 12A identified that schema **1.7.0 cannot honestly carry LAB-AGENT-DELEGATION-001 evidence**:

- no first-class caller vs callee agent ids on an A2A-shaped hop
- no claim-trust classification distinct from memory/RAG `untrusted_data`
- no claimed scope distinct from coded `allowed_scope`
- `agentsec.control.type` had no `identity_claim_trust`
- attack enum had no `A2A-001`

12B emits live CTRL-IDENTITY-001 OBSERVE and follow-on CTRL-MCP-001. This bump is the smallest additive change. 1.7.0 field **meanings are unchanged**.

## What changed

| Item | 1.7.0 | 1.8.0 |
|------|-------|-------|
| `agentsec.schema.version` | const `1.7.0` | const **1.8.0** |
| `agentsec.attack.id` enum | … `MEMORY-001` | additive **`A2A-001`** |
| `agentsec.control.type` | … `memory_context_trust` | additive **`identity_claim_trust`** |
| `control.id` when type is `identity_claim_trust` | n/a | const **`CTRL-IDENTITY-001`** |
| `agentsec.trust_boundary` | … `agent.memory.store` | additive **`agent.identity.claim`** |
| `agentsec.identity.caller_agent_id` | absent | attribution string (not authn proof) |
| `agentsec.identity.callee_agent_id` | absent | attribution string (not authn proof) |
| `agentsec.identity.claim.trust` | absent | enum **`untrusted_claim`** |
| `agentsec.delegation.claimed_scope` | absent | scope the caller asked to borrow |
| `gen_ai.workflow.name` | … `memory_lab` | additive **`identity_delegation_lab`** |
| `agentsec.workflow.entry` | … `/memory/recall` | additive **`/identity/delegate`** |

## Field-name decisions (ADDED / REUSED / REJECTED / DEFERRED)

**ADDED**

- `agentsec.identity.caller_agent_id`
- `agentsec.identity.callee_agent_id`
- `agentsec.identity.claim.trust` = `untrusted_claim`
- `agentsec.delegation.claimed_scope`
- control type `identity_claim_trust` / `CTRL-IDENTITY-001`
- attack id `A2A-001`
- trust boundary `agent.identity.claim`
- workflow `identity_delegation_lab` / `/identity/delegate`

**REUSED**

- `agentsec.principal.id` / `.type`
- `gen_ai.agent.id` (callee on the executing hop)
- `agentsec.delegator.agent.id` (caller as prior in-process hop on hop.index >= 1)
- `agentsec.mcp.requested_scope` / `allowed_scope`
- `agentsec.mcp.resource.id`
- `run.id` / `sequence` / `control.*`

**REJECTED**

- `session.id`, `tenant.id`, `gen_ai.tool.call.id`, `invocation.id`
- token / JWT / Authorization header fields
- `authenticated=true`, `verified_identity=true`, `cryptographic_passport_valid=true`
- `trusted_identity`
- caller-supplied `allowed_tools`
- overloading `agentsec.delegation.authority.source` (`delegated` \| `ambient_deputy` remains MCP-006 only)

**DEFERRED**

- `delegation.id` / `delegation.parent_id` / `delegation.provenance`
- SPIFFE id, issuer/audience strings
- grant snapshot `allowed_tools` (still a **TELEMETRY GAP**)
- live A2A transport / Agent Card HTTP / OAuth / OIDC / SPIRE

## Compatibility

Python schema tests require **1.8.0** on emitted events. Loan / MCP-001 / 003 / 004 / 005 / 006 / catalog / RAG / memory runtime decisions are unchanged; only the version string moved.

Existing indexed 1.7.0 events remain valid historical evidence. New emitters only produce 1.8.0.

Phase 12C live discovery (fresh A/B/C, 2026-09-18): indexed names match the 1.8.0 additions (`agentsec.identity.caller_agent_id`, `callee_agent_id`, `claim.trust=untrusted_claim`, `agentsec.delegation.claimed_scope`, `CTRL-IDENTITY-001` / `identity_claim_trust`, `A2A-001`, `identity_delegation_lab`, `/identity/delegate`). `authenticated` / `verified_identity` / `allowed_tools` remain **NOT INDEXED**. Multivalue class B unchanged. **No `props.conf` change.** Privileged hop-1 `agentsec.mcp.resource.id` was **NOT INDEXED** on ATTACK/RETEST (runtime omitted it; not a schema rename). Details: `docs/AGENT_DELEGATION_SPLUNK_FIELD_CONTRACT.md`.

No Splunk `props.conf` change in 12B or 12C.
