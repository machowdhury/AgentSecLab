# Schema 1.3.0 migration

**Status:** Phase 6B **IMPLEMENTED**. Phase 6C **SPLUNK VALIDATED** (indexed 1.3.0 OBSERVE / RESULT-001 / MCP-005). Additive over 1.2.0.  
**File:** `schemas/security_event.schema.json`  
**Emitter:** `agentsec.schema.version` const **1.3.0** (`src/agentsec/experiment.py` `SCHEMA_VERSION`).  
**Evidence class:** pytest schema validation is **MEASURED**. Splunk indexing of 1.3.0 fields: **OBSERVED** (`docs/MCP005_SPLUNK_FIELD_VALIDATION.md`).

Parents: `docs/SCHEMA_1_2_0.md`, `docs/MCP005_EVENT_MODEL_REVIEW.md`.

---

## Why bump

Phase 6A identified that schema **1.2.0 cannot honestly carry MCP-005 evidence**:

- `agentsec.control.decision` had no `OBSERVE` (defended RESULT-001)
- `agentsec.control.type` had no `mcp_result_trust` (CTRL-MCP-RESULT-001 cannot reuse `mcp_allowlist` / CTRL-MCP-001)
- `agentsec.attack.id` had no `MCP-005`

Phase 6B needs those facts as LIVE `control.decision` bytes. Forcing 1.2.0 would mean either omitting RESULT-001 from events or emitting `ALLOW result_is_data` (forbidden: ALLOW means merge may proceed).

This bump is the smallest additive change that makes RESULT-001 and MCP-005 attributable. 1.2.0 field **meanings are unchanged**.

## What changed

| Item | 1.2.0 | 1.3.0 |
|------|-------|-------|
| `agentsec.schema.version` | const `1.2.0` | const **1.3.0** |
| `agentsec.attack.id` enum | … `MCP-004` | additive **`MCP-005`** |
| `agentsec.control.decision` | ALLOW / DENY / ERROR | additive **`OBSERVE`** |
| `agentsec.control.type` | … `mcp_allowlist` | additive **`mcp_result_trust`** |
| `control.id` when type is `mcp_result_trust` | n/a | const **`CTRL-MCP-RESULT-001`** |
| `trust_boundary` when type is `mcp_result_trust` | n/a | const **`mcp.tool.result`** |

OBSERVE uses the same operation flags as ALLOW at decision time: `attempted=false`, `executed=false`, **no** `operation.outcome`. OBSERVE is not DENY of the finished first tool.

## What was not added

- `gen_ai.tool.call.id` — preferred OTel name, still absent. This lab uses two **different** tool names plus `run.id` + `sequence`. Same-tool twice remains sequence-only. Documented limitation.
- `agentsec.mcp.allowed_tools` — follow-on CTRL-MCP-001 still emits coded `allowed_scope=policy:read` even when overlay ALLOWs `customer:read`
- SANITIZE / QUARANTINE / REQUIRE_APPROVAL
- `TRUSTED_DATA` or numeric trust scores
- Full tool result bodies
- New Q-MCP / DET-MCP-005 SPL **in 6B**. Phase 6C added hunt `Q-MCP-RESULT-AUTHORITY` only; **no** DET-MCP-005.

## Compatibility

| Consumer | 6B expectation |
|----------|----------------|
| Python schema tests | Require **1.3.0** on emitted events |
| Loan / MCP-001 / 003 / 004 runtime | Same decisions; version string is 1.3.0 |
| Q-MCP SPL / DET-MCP-001 | **Unchanged**. Searches do not filter schema.version |
| LAB-MCP-004 catalog / Studio copy | Remain labeled 1.2.0 as **historical workshop metadata** |
| Splunk investigation of OBSERVE / RESULT-001 | **Phase 6C VALIDATED** (`docs/MCP005_SPLUNK_VALIDATION.md`) |

## Privacy

Preview remains max **200** characters + `sha256:`. The MALICIOUS fixture keeps `SECURITY_OVERRIDE` and `lookup_customer_tier` inside that budget of compact result JSON.
