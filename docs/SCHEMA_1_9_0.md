# Schema 1.9.0 migration

**Status:** Phase 13B **IMPLEMENTED**. Phase 13C Splunk extraction **VALIDATED**.  
**File:** `schemas/security_event.schema.json`  
**Emitter:** `agentsec.schema.version` const **1.9.0** (`src/agentsec/experiment.py` `SCHEMA_VERSION`).  
**Evidence class:** pytest schema validation is **MEASURED**. Splunk field names: **OBSERVED** (`docs/PHASE13C_GOAL_INTEGRITY_SPLUNK_VALIDATION.md`).

Parents: `docs/SCHEMA_1_8_0.md`, `docs/GOAL_INTEGRITY_EVENT_MODEL_REVIEW.md`.

---

## Why bump

Phase 13A identified that schema **1.8.0 cannot honestly carry LAB-AGENT-GOAL-INTEGRITY-001 evidence**:

- no first-class authoritative task id / hash / preview / provenance
- no instruction-trust classification distinct from memory/RAG `untrusted_data` or identity `untrusted_claim`
- no proposed goal / decision / reason
- `agentsec.control.type` had no `goal_integrity`
- attack enum had no `GOAL-001`

13B emits live CTRL-GOAL-INTEGRITY-001 then follow-on CTRL-MCP-001. This bump is the smallest additive change. 1.8.0 field **meanings are unchanged**.

## What changed

| Item | 1.8.0 | 1.9.0 |
|------|-------|-------|
| `agentsec.schema.version` | const `1.8.0` | const **1.9.0** |
| `agentsec.attack.id` enum | … `A2A-001` | additive **`GOAL-001`** |
| `agentsec.control.type` | … `identity_claim_trust` | additive **`goal_integrity`** |
| `control.id` when type is `goal_integrity` | n/a | const **`CTRL-GOAL-INTEGRITY-001`** |
| `agentsec.trust_boundary` | … `agent.identity.claim` | additive **`agent.task.contract`** |
| `agentsec.task.id` / `.hash` / `.preview` / `.provenance` | absent | server-owned contract |
| `agentsec.instruction.trust` | absent | enum **`untrusted_instruction`** |
| `agentsec.instruction.provenance` | absent | enum **`agentsec.goal.fixture`** |
| `agentsec.goal.proposed` / `.decision` / `.reason` | absent | interpreter proposal + integrity outcome |
| `gen_ai.workflow.name` | … `identity_delegation_lab` | additive **`goal_integrity_lab`** |
| `agentsec.workflow.entry` | … `/identity/delegate` | additive **`/goal/evaluate`** |
| `agentsec.content.influence.kind` | … `recalled_memory` | additive **`untrusted_instruction`** |

## Field-name decisions (ADDED / REUSED / REJECTED / DEFERRED)

**ADDED** — as in the table.

**REUSED** — `agentsec.principal.id`, `gen_ai.agent.id`, `run.id` / `sequence` / `control.*`, MCP tool events, `content.hash` / `preview`.

**REJECTED** — `session.id`, `tenant.id`, `gen_ai.tool.call.id`, token fields, `trusted_instruction`, client-supplied `authoritative_task`.

**DEFERRED** — grant snapshot `allowed_tools`; ATLAS mapping for GOAL-001.

## Compatibility

Python schema tests require **1.9.0** on emitted events. Loan / MCP / catalog / RAG / memory / identity runtime decisions are unchanged; only the version string moved.
