# Schema 1.6.0 migration

**Status:** Phase 10B **IMPLEMENTED**. Phase 10C **SPLUNK VALIDATED**. Not a workshop.  
**File:** `schemas/security_event.schema.json`  
**Emitter:** `agentsec.schema.version` const **1.6.0** (`src/agentsec/experiment.py` `SCHEMA_VERSION`).  
**Evidence class:** pytest schema validation is **MEASURED**. Splunk: **NOT ATTEMPTED**.

Parents: `docs/SCHEMA_1_5_0.md`, `docs/RAG_EVENT_MODEL_REVIEW.md`.

## Why bump

Phase 10A identified that schema **1.5.0 cannot honestly carry LAB-RAG-001 evidence**:

- `agentsec.control.type` had no `rag_context_trust` (CTRL-RAG-CONTEXT-001 cannot reuse `mcp_result_trust` or `mcp_metadata_trust`)
- `agentsec.attack.id` had no `RAG-001`
- no field classified **retrieved context** as untrusted data

10B emits live `control.decision` bytes for CTRL-RAG-CONTEXT-001. This bump is the smallest additive change. 1.5.0 field **meanings are unchanged**.

## What changed

| Item | 1.5.0 | 1.6.0 |
|------|-------|-------|
| `agentsec.schema.version` | const `1.5.0` | const **1.6.0** |
| `agentsec.attack.id` enum | … `MCP-CATALOG-001` | additive **`RAG-001`** |
| `agentsec.control.type` | … `mcp_metadata_trust` | additive **`rag_context_trust`** |
| `control.id` when type is `rag_context_trust` | n/a | const **`CTRL-RAG-CONTEXT-001`** |
| `agentsec.trust_boundary` | … `mcp.catalog.metadata` | additive **`rag.retrieved.context`** |
| `agentsec.rag.context.trust` | absent | enum **`untrusted_data`**; required on RAG-CONTEXT-001 |
| `agentsec.rag.context.provenance` | absent | enum **`rag.local.fixture`**; required on RAG-CONTEXT-001 |
| `agentsec.rag.context.document.id` | absent | opaque fixture id; required on RAG-CONTEXT-001 |
| `gen_ai.workflow.name` | `loan_pipeline` \| `mcp_tool_lab` | additive **`rag_context_lab`** |
| `agentsec.workflow.entry` | `/process` \| `/mcp/invoke` | additive **`/rag/retrieve`** |
| `agentsec.content.influence.kind` | … `tool_request` | additive **`retrieved_context`** |

Reuse existing `agentsec.content.hash` and `agentsec.content.preview` for the **document body**. Hash is SHA-256 over canonical UTF-8. Preview is ≤200 characters. The interpreter inspects the **full** body; preview is not the authorization input.

Field naming follows catalog: `agentsec.mcp.metadata.trust` → `agentsec.rag.context.trust`. Document id is `agentsec.rag.context.document.id` (10B contract), not a parallel hash field.

## What was not added

- `trusted_document`, `document_authorized`, `effective_authority`
- `rag_allowed_tools` / `rag_granted_tools`
- full document / full prompt
- `event.name=agentsec.rag.retrieved` (control.decision is enough)
- `agentsec.rag.query.hash`
- `gen_ai.tool.call.id`
- SANITIZE / QUARANTINE
- DET-RAG SPL
- Overload of `agentsec.mcp.result.trust` or `agentsec.mcp.metadata.trust`

CTRL-RAG-CONTEXT-001 **OBSERVE** is valid for BASELINE, ATTACK, and RETEST. Vulnerable ALLOW belongs on **CTRL-MCP-001**, not on the observation control. Schema still allows ALLOW on `rag_context_trust` as a closed decision enum shared by all controls; 10B **does not emit** ALLOW on this control.

## Compatibility

| Consumer | 10B expectation |
|----------|-----------------|
| Python schema tests | Require **1.6.0** on emitted events |
| Loan / MCP-001 / 003 / 004 / 005 / 006 / catalog runtime | Same decisions; version string is 1.6.0 |
| Q-MCP SPL / DET-MCP-001 / Q-SCANNER | **Unchanged**. Searches do not filter schema.version. Phase 10C revalidated Q-MCP against 1.6.0 RAG specimens. |
