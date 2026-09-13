# MCP-003 event model review (schema 1.1.0)

**Status:** Phase 4A **DESIGN**. Phase 4B **kept 1.1.0**. Phase 4C **indexed the same 1.1.0 fields** (MEASURED). Additive enum value `MCP-003` on `agentsec.attack.id` only. **Did not bump schema version. Did not add `effective_scope`.**  
**Parents:** `docs/MCP_EVENT_MODEL.md`, `schemas/security_event.schema.json` 1.1.0.  
**Evidence class:** **DOCUMENTED** review. Phase 4B emission is **MEASURED**. Phase 4C indexed names are **OBSERVED** in `docs/MCP003_SPLUNK_FIELD_VALIDATION.md`.

---

## Decision

Schema **1.1.0 already contains** every field LAB-MCP-003 needs.

**Do not** bump to 1.2.0.  
**Do not** invent `effective_scope`.  
**Do not** add a second control event. Authorization remains `agentsec.control.decision` / CTRL-MCP-001.

If implementation later finds a genuine hole, the smallest additive change would be documented then. None is required now.

---

## Field sufficiency

| Concept | Existing field | MCP-003 use |
|---------|----------------|-------------|
| Tool | `gen_ai.tool.name` | Always `lookup_policy` on A/B/C |
| Method | `mcp.method.name` | `tools/call` |
| Requested scope | `agentsec.mcp.requested_scope` | A: `policy:read`. B/C: `policy:restricted:read` |
| Allowed scope | `agentsec.mcp.allowed_scope` | Always coded `policy:read` (wire). **Never rewritten** on fail-open |
| Decision | `agentsec.control.decision` | ALLOW / DENY / ERROR |
| Reason | `agentsec.control.reason` | `tool_granted` / `scope_not_granted` / `vulnerable_profile_fail_open:scope_not_granted` / `unknown_scope` |
| Operation flags | `agentsec.operation.*` | DENY: attempted=false, executed=false, outcome=prevented |
| Principal / agent | `agentsec.principal.id`, `gen_ai.agent.id` | Unchanged |
| Hunt key | `agentsec.run.id` | Unchanged. No `session.id` |
| Profile / mode | `agentsec.security.profile`, `agentsec.testbed.mode` | A defended BASELINE; B vulnerable ATTACK; C defended RETEST |

Control events already carry both scope fields (Q-MCP-SCOPE **VALIDATED**). DET-MCP-001 already copies those fields from DENY onto a later `mcp.started` row.

---

## What we will not add

| Tempting field | Why not |
|----------------|---------|
| `effective_scope` | Runtime does not compute a third value. Grant is `allowed_scope`. Request is `requested_scope`. Decision is ALLOW/DENY/ERROR. A third name would invite overwriting the grant. |
| `scope_relation` as an emitted field | Display helper in Q-MCP-SCOPE SPL only. |
| `agentsec.mcp.scope_violation` | Predecessor boolean. **DROP.** Decision + reason + two scope fields are enough. |
| Duplicate `agentsec.mcp.tool.name` | Already rejected in 1.1.0. |

---

## Reason strings (telemetry, not schema enum expansion)

Keep existing reasons. Add only these **string** reasons at implementation time (schema already allows reason as string):

| Reason | When |
|--------|------|
| `tool_granted` | Tool and requested scope both in grant (BASELINE) |
| `scope_not_granted` | Catalog-valid scope not in grant (RETEST) |
| `vulnerable_profile_fail_open:scope_not_granted` | Same mismatch, vulnerable ATTACK |
| `unknown_scope` | Token not in tool catalog (ERROR, not DENY) |
| existing `tool_not_granted` / `unknown_tool` / `control_evaluation_failure:…` | Unchanged MCP-001/002 / ERROR paths |

Do not encode requested or allowed into `reason` as a substitute for the two scope fields.

---

## Sequences vs LAB-MCP-001

Event **names** and operation flags are unchanged. Only the **story** on B/C changes (scope vs ungranted tool).

| Id | MCP-003 story | `mcp.started`? |
|----|---------------|----------------|
| A | Authorized scope ALLOW | yes → completed |
| B | Excessive scope, fail-open ALLOW | yes → completed |
| C | Excessive scope DENY | **no** |
| D | Malformed / unknown scope ERROR | **no** |
| E | Control evaluation ERROR | **no** |
| F | Valid ALLOW then handler failure | yes → `mcp.failed` |

Invariants for the emitter (already in 1.1.0):

- DENY before execution (no start)
- ERROR before execution (no start)
- `mcp.failed` means the governed operation **began** (`executed=true`, `outcome=error`) — not prevention
- ALLOW on the control event is **not** proof of execution; `mcp.started` / handler spy is

---

## Splunk / detection impact

No new indexed field names. Existing Q-MCP-* contracts remain valid. DET-MCP-001 remains the execution-after-DENY detector and already includes scope columns from the DENY event.

Phase 4C live indexing **resolved** the open “will Splunk see both scope fields on MCP-003 control events?” question: **yes** (`agentsec.mcp.requested_scope` / `agentsec.mcp.allowed_scope`, `mvcount=2`, collapse with `mvindex(mvdedup(…),0)`). `scope_relation` remains SPL-only. `effective_scope` remains absent. Schema stays **1.1.0**.

Q-MCP-SCOPE helper order: ERROR must be classified `not_a_grant` before mismatch, or `unknown_scope` is mislabeled `known_but_ungranted`. That is a display-helper defect, not a schema hole.

Live DET-MCP-001 on MCP-003 specimens: **0** rows. No DET-MCP-003.
