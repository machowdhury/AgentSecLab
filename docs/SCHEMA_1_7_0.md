# Schema 1.7.0 migration

**Status:** Phase 11B **IMPLEMENTED**. Splunk **NOT ATTEMPTED**.  
**File:** `schemas/security_event.schema.json`  
**Emitter:** `agentsec.schema.version` const **1.7.0** (`src/agentsec/experiment.py` `SCHEMA_VERSION`).  
**Evidence class:** pytest schema validation is **MEASURED**. Splunk: **NOT ATTEMPTED**.

Parents: `docs/SCHEMA_1_6_0.md`, `docs/MEMORY_EVENT_MODEL_REVIEW.md`.

## Why bump

Phase 11A identified that schema **1.6.0 cannot honestly carry LAB-MEMORY-001 evidence**:

- no write event distinct from recall
- no memory id / provenance / trust class
- no link from recall run to write `run.id`
- `agentsec.control.type` had no `memory_context_trust`

11B emits live `agentsec.memory.written`, `agentsec.memory.recalled`, and CTRL-MEMORY-CONTEXT-001 OBSERVE. This bump is the smallest additive change. 1.6.0 field **meanings are unchanged**.

## What changed

| Item | 1.6.0 | 1.7.0 |
|------|-------|-------|
| `agentsec.schema.version` | const `1.6.0` | const **1.7.0** |
| `event.name` | … `pipeline.stopped` | additive **`agentsec.memory.written`**, **`agentsec.memory.recalled`** |
| `agentsec.attack.id` enum | … `RAG-001` | additive **`MEMORY-001`** |
| `agentsec.control.type` | … `rag_context_trust` | additive **`memory_context_trust`** |
| `control.id` when type is `memory_context_trust` | n/a | const **`CTRL-MEMORY-CONTEXT-001`** |
| `agentsec.trust_boundary` | … `rag.retrieved.context` | additive **`agent.memory.store`** |
| `agentsec.memory.id` | absent | opaque fixture id |
| `agentsec.memory.trust` | absent | enum **`untrusted_data`** |
| `agentsec.memory.provenance` | absent | enum **`agentsec.memory.fixture`** |
| `agentsec.memory.source_run_id` | absent | UUID of the **write** run |
| `gen_ai.workflow.name` | … `rag_context_lab` | additive **`memory_lab`** |
| `agentsec.workflow.entry` | … `/rag/retrieve` | additive **`/memory/write`**, **`/memory/recall`** |
| `agentsec.content.influence.kind` | … `retrieved_context` | additive **`recalled_memory`** |

Reuse existing `agentsec.content.hash` and `agentsec.content.preview` for the **memory body**. Hash is SHA-256 over canonical UTF-8. Preview is ≤200 characters. The interpreter inspects the **full** body; preview is not the authorization input.

**Run correlation:** `agentsec.run.id` on a recall event **is** the destination/recall run. `agentsec.memory.source_run_id` is the write run. No `destination_run_id` field.

## What was not added

- `trusted_memory`, `memory_authorized`, `effective_grant`
- `memory_allowed_tools` / grant fields
- full memory body / full conversation
- `session.id`, `tenant.id`
- SANITIZE / QUARANTINE on the observation control
- DET-MEMORY SPL
- Overload of `agentsec.rag.context.trust` or `agentsec.mcp.result.trust`

CTRL-MEMORY-CONTEXT-001 **OBSERVE** is valid for BASELINE, ATTACK, and RETEST. Vulnerable ALLOW belongs on **CTRL-MCP-001**, not on the observation control.

## Compatibility

| Consumer | 11B expectation |
|----------|-----------------|
| Python schema tests | Require **1.7.0** on emitted events |
| Loan / MCP-001 / 003 / 004 / 005 / 006 / catalog / RAG runtime | Same decisions; version string is 1.7.0 |
| Q-MCP SPL / DET-MCP-001 / Q-SCANNER / Q-RAG | **Unchanged**. Searches do not filter schema.version. Do not rewrite SPL because the const moved. |

## Privacy

Telemetry may contain memory id, SHA-256, bounded preview, provenance, writer/reader agent id, source run, current recall run, and trust class.

Do **not** emit full memory by default, credentials, PII, customer records, secrets, or authorization tokens.

## Migration implications

Existing indexed 1.6.0 events remain valid historical evidence. New emitters only produce 1.7.0. Phase 11C must discover fields from fresh memory specimens rather than assuming 1.6.0 RAG field names apply to memory.
