# Schema 1.5.0 migration

**Status:** Phase 8C **IMPLEMENTED**. Phase 8D Splunk indexing **VALIDATED**.  
**File:** `schemas/security_event.schema.json`  
**Emitter:** `agentsec.schema.version` const **1.5.0** (`src/agentsec/experiment.py` `SCHEMA_VERSION`).  
**Evidence class:** pytest schema validation is **MEASURED**. Splunk indexing of 1.5.0: **OBSERVED** (`docs/PHASE8D_MCP_CATALOG_SPLUNK_VALIDATION.md`).

Parents: `docs/SCHEMA_1_4_0.md`, `docs/MCP_CATALOG_POISONING_EVENT_MODEL_REVIEW.md`.

## Why bump

Phase 8B identified that schema **1.4.0 cannot honestly carry LAB-MCP-CATALOG evidence**:

- `agentsec.control.type` had no `mcp_metadata_trust` (CTRL-MCP-METADATA-001 cannot reuse `mcp_result_trust`)
- `agentsec.attack.id` had no `MCP-CATALOG-001`
- no field classified **catalog metadata** as untrusted data (must not overload `agentsec.mcp.result.trust`)

8C emits live `control.decision` bytes for METADATA-001. This bump is the smallest additive change. 1.4.0 field **meanings are unchanged**.

## What changed

| Item | 1.4.0 | 1.5.0 |
|------|-------|-------|
| `agentsec.schema.version` | const `1.4.0` | const **1.5.0** |
| `agentsec.attack.id` enum | … `MCP-006` | additive **`MCP-CATALOG-001`** |
| `agentsec.control.type` | … `mcp_delegation` | additive **`mcp_metadata_trust`** |
| `control.id` when type is `mcp_metadata_trust` | n/a | const **`CTRL-MCP-METADATA-001`** |
| `agentsec.trust_boundary` | … `mcp.tool.result` | additive **`mcp.catalog.metadata`** |
| `agentsec.mcp.metadata.trust` | absent | enum **`untrusted_data`**; required on METADATA-001 |
| `agentsec.mcp.metadata.provenance` | absent | enum **`mcp.catalog.snapshot`**; required on METADATA-001 |

Reuse existing `agentsec.content.hash` and `agentsec.content.preview` for the **description**. Hash is SHA-256 over canonical UTF-8 description bytes. Preview is ≤200 characters. The interpreter inspects the **full** description; preview is not the authorization input.

## What was not added

- `gen_ai.tool.call.id`
- `event.name=agentsec.mcp.catalog.observed` (control.decision is enough)
- catalog grant lists on the wire
- scanner finding fields on `otel:agentic:json`
- SANITIZE / QUARANTINE
- DET-MCP-CATALOG SPL (Phase 8D hunt `Q-MCP-CATALOG-AUTHORITY` is a Splunk artifact, not a schema field)
- Overload of `agentsec.mcp.result.trust`

## Compatibility

| Consumer | 8C expectation |
|----------|----------------|
| Python schema tests | Require **1.5.0** on emitted events |
| Loan / MCP-001 / 003 / 004 / 005 / 006 runtime | Same decisions; version string is 1.5.0 |
| Q-MCP SPL / DET-MCP-001 | **Unchanged**. Searches do not filter schema.version. Revalidated on 1.5.0 copies in Phase 8D |
| LAB-MCP-CATALOG hunt | `Q-MCP-CATALOG-AUTHORITY` consumes METADATA-001 fields; does not filter schema.version |
| LAB-MCP-005 / 006 catalog / Studio copy | Remain labeled 1.3.0 / 1.4.0 as **historical workshop metadata** |
