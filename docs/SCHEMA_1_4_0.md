# Schema 1.4.0 migration

**Status:** Phase 7B **IMPLEMENTED**. Splunk **NOT ATTEMPTED**.  
**File:** `schemas/security_event.schema.json`  
**Emitter:** `agentsec.schema.version` const **1.4.0** (`src/agentsec/experiment.py` `SCHEMA_VERSION`).  
**Evidence class:** pytest schema validation is **MEASURED**. Splunk indexing of 1.4.0: **NOT ATTEMPTED**.

Parents: `docs/SCHEMA_1_3_0.md`, `docs/MCP006_EVENT_MODEL_REVIEW.md`.

## Why bump

Phase 7A identified that schema **1.3.0 cannot honestly carry MCP-006 evidence**:

- `agentsec.attack.id` had no `MCP-006`
- `agentsec.control.type` had no `mcp_delegation` (CTRL-DELEGATION-001 cannot reuse `mcp_allowlist` / CTRL-MCP-001)
- no field distinguished **delegated** vs **ambient_deputy** authority source

7B needs those facts as LIVE `control.decision` bytes. This bump is the smallest additive change. 1.3.0 field **meanings are unchanged**.

## What changed

| Item | 1.3.0 | 1.4.0 |
|------|-------|-------|
| `agentsec.schema.version` | const `1.3.0` | const **1.4.0** |
| `agentsec.attack.id` enum | … `MCP-005` | additive **`MCP-006`** |
| `agentsec.control.type` | … `mcp_result_trust` | additive **`mcp_delegation`** |
| `control.id` when type is `mcp_delegation` | n/a | const **`CTRL-DELEGATION-001`** |
| `gen_ai.tool.name` on that decision | n/a | **required** (requested operation) |
| `agentsec.delegation.authority.source` | absent | enum **`delegated` \| `ambient_deputy`**; required on ALLOW/DENY; omitted on ERROR |

Trust boundary for CTRL-DELEGATION-001 remains `acmebank.mcp.authorize`. A new enum value was not added.

## What was not added

- `gen_ai.tool.call.id`
- `agentsec.mcp.allowed_tools` / delegated grant lists on the wire
- `agentsec.delegation.caller.id` / `deputy.id` (reuse hop 0/1 + `delegator.agent.id`)
- `RESULT_DERIVED` on the authority-source enum
- SANITIZE / QUARANTINE
- New Q-MCP / DET-MCP-006 SPL

## Compatibility

| Consumer | 7B expectation |
|----------|----------------|
| Python schema tests | Require **1.4.0** on emitted events |
| Loan / MCP-001 / 003 / 004 / 005 runtime | Same decisions; version string is 1.4.0 |
| Q-MCP SPL / DET-MCP-001 | **Unchanged**. Searches do not filter schema.version |
| LAB-MCP-005 catalog / Studio copy | Remain labeled 1.3.0 as **historical workshop metadata** |
