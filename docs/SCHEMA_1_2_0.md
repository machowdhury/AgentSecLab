# Schema 1.2.0 migration

**Status:** Phase 5B **IMPLEMENTED**. Additive over 1.1.0.  
**File:** `schemas/security_event.schema.json`  
**Emitter:** `agentsec.schema.version` const **1.2.0** (`src/agentsec/experiment.py` `SCHEMA_VERSION`).  
**Evidence class:** pytest schema validation is **MEASURED**. Splunk indexing of 1.2.0 fields: **OBSERVED** in Phase 5C (`docs/MCP004_SPLUNK_FIELD_VALIDATION.md`).

Parents: `docs/MCP_EVENT_MODEL.md` (1.1.0 MCP-001/003 field meanings), `docs/MCP004_EVENT_MODEL_REVIEW.md`.

---

## Why bump

MCP-004 introduces a new structured authorization dimension: **resource identity** and **server-owned resource grants**. Schema 1.1.0 has `additionalProperties: false`, so these keys are a real contract change, not an in-place enum tweak.

1.1.0 already had tool (`gen_ai.tool.name`) and scope (`requested_scope` / `allowed_scope`). Resource was only available as preview/hash of the argument blob. That is enough for content integrity. It is not a stable hunt field for “which resource was checked?”

## What changed

| Item | 1.1.0 | 1.2.0 |
|------|-------|-------|
| `agentsec.schema.version` | const `1.1.0` | const `1.2.0` |
| `agentsec.attack.id` enum | … `MCP-003` | additive **`MCP-004`** |
| `agentsec.mcp.resource.id` | absent | **optional** string |
| `agentsec.mcp.allowed_resource.ids` | absent | **optional** string |

All existing 1.0.0 / 1.1.0 field **meanings are unchanged**. Loan pipeline events emit version 1.2.0 with the same properties they had before. MCP-001 / MCP-003 events remain valid without the new resource fields (`lookup_customer_tier` omits them; MCP-003 DENY before arguments may still attach them when `policy_id` is present).

## Field semantics

### `agentsec.mcp.resource.id`

Exact opaque identifier used for authorization (the ticket `resource_id` after extraction). Lab fixture labels only (`lending-basics`, `executive-restricted`, or the exact unknown string requested). Not a dump of tool arguments. Never copied from a client grant field.

### `agentsec.mcp.allowed_resource.ids`

Server-owned grant set for this agent, stable comma-sorted. v1: `lending-basics`. **Never rewritten on fail-open.** Never copied from the request.

## What was not added

- `effective_resource`
- `resource.authorized`
- `gen_ai.tool.call.arguments` / full arguments
- customer / account identifiers
- secrets
- `agentsec.mcp.parameter.*` explosion

Preview (`agentsec.content.preview`, 200 chars) and `agentsec.content.hash` are unchanged.

## Compatibility

| Consumer | 5B expectation |
|----------|----------------|
| Python schema tests | Require **1.2.0** on emitted events |
| Loan / MCP-001 / MCP-003 runtime | Same decisions; version string is 1.2.0 |
| Q-MCP SPL / DET-MCP-001 | **Unchanged** in this phase. New fields are optional; existing indexed names still exist |
| LAB-MCP-001 / LAB-MCP-003 search catalogs | Remain labeled 1.1.0 against previously validated Splunk runs (historical). Do not retcon those catalogs in 5B |
| Splunk investigation of 1.2.0 resource fields | **Phase 5C VALIDATED** (`docs/PHASE5C_MCP004_SPLUNK_VALIDATION.md`) |

Consumers that hard-require const `1.1.0` on every event must be updated. Consumers that ignore unknown optional properties and already accept MCP control events continue to work if they tolerate the version string change.

## Privacy

Resource ids in this lab are **non-secret fixture labels**. Structured `resource.id` is the authorization object, not an invitation to log arbitrary arguments in later labs.
