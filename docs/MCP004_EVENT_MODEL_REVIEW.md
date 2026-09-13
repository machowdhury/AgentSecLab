# MCP-004 event model review (schema 1.1.0)

**Status:** Phase 5A **DESIGN**. Phase 5B **implemented** schema **1.2.0** and emits the two proposed fields (`docs/SCHEMA_1_2_0.md`).  
**Parents:** `docs/MCP_EVENT_MODEL.md`, schema 1.2.0.  
**Evidence class:** 5A review remains **DOCUMENTED**. 5B emission is **MEASURED**.

---

## Decision (5A)

Schema **1.1.0 does not** have a structured resource-identity field.

| Need | 1.1.0 today |
|------|-------------|
| Tool | `gen_ai.tool.name` |
| Scopes | `agentsec.mcp.requested_scope` / `allowed_scope` |
| Decision / reason | `agentsec.control.decision` / `reason` |
| Argument blob | `agentsec.content.preview` (200 chars) + `agentsec.content.hash` |
| Full arguments | **Not emitted** (`gen_ai.tool.call.arguments` unused) |
| Resource id | **Absent** |
| Resource grant set | **Absent** |

**Do not** implement a schema change in 5A.  
**Do not** explode `agentsec.mcp.parameter.*`.  
**Do not** start logging full arguments.  
**Do not** add `effective_resource`.

---

## Is preview + hash enough?

**For content integrity:** yes. Q-MCP-PARAMS remains the answer to “what argument blob was hashed?”

**For resource authorization investigation:** **no**, not as a contract.

Reasons:

1. Preview is a **truncation** of `{tool, arguments, requested_scope}`. This lab’s tiny JSON happens to fit in 200 characters. That is accidental, not a field.
2. Hash does not name the resource or the grant.
3. Parsing preview JSON in SPL is not a stable hunt (quoting, truncation, key order).
4. MCP-003 already rejected hunting authority via unstructured text; it used first-class scope fields.

Resource ids in this lab (`lending-basics`, `executive-restricted`) are **non-secret fixture labels**, not customer ids, account numbers, or credentials. A structured field is therefore privacy-acceptable **if** it is only the authorization object, not a dump of all arguments.

---

## Proposed additive fields (5B or later — not approved as code)

Smallest pair, parallel to requested/allowed scope:

| Field | Meaning |
|-------|---------|
| `agentsec.mcp.resource.id` | Exact opaque identifier used for authorization (ticket `resource_id`) |
| `agentsec.mcp.allowed_resource.ids` | Coded grant set, stable `",".join(sorted(...))` (v1: `lending-basics`) |

Rules if implemented later:

- Emit on `agentsec.control.decision` for MCP-004 (and any invoke that performed a resource check).
- Never rewrite `allowed_resource.ids` on fail-open.
- Do not put extra argument keys into unbounded `parameter.*` fields.
- Do not emit `gen_ai.tool.call.arguments`.
- Add `MCP-004` to `agentsec.attack.id` enum (same pattern as MCP-003).

**Version lean:** bump to **1.2.0** when these properties are added. Schema 1.1.0 has `additionalProperties: false`; new keys are a real additive contract, not an in-place enum tweak. 5A does not perform that bump.

Until then, local `events.jsonl` still cannot honestly carry extra keys through the closed schema. Runtime implementation of MCP-004 **requires** the schema change before LIVE emission, or it cannot show structured resource evidence.

### 5B resolution

Chose **1.2.0**. Added optional `agentsec.mcp.resource.id` and `agentsec.mcp.allowed_resource.ids`. Added `MCP-004` to `agentsec.attack.id`. Did **not** add `effective_resource`, `resource.authorized`, or full arguments. Preview/hash unchanged. Splunk SPL for the new fields is still **not** written.

---

## Reason strings (telemetry, not schema enums)

Keep existing reasons. Add only these **strings** at implementation time:

| Reason | When |
|--------|------|
| `tool_granted` | Tool, scope, and resource all in grant (BASELINE) |
| `resource_not_granted` | Catalog-valid resource not in grant (RETEST) |
| `vulnerable_profile_fail_open:resource_not_granted` | Same mismatch, vulnerable ATTACK |
| `unknown_resource` | Id not in resource catalog (ERROR, not DENY) |
| existing `malformed_arguments` / `tool_not_granted` / `unknown_scope` / … | Unchanged |

Do not encode the resource id into `reason` as a substitute for the two proposed fields.

---

## Privacy / telemetry rules

- Default: preview + hash only for the request blob.
- Structured `resource.id` only after explicit schema approval (this review **proposes** it; 5A does not ship it).
- No secrets, no real customer ids, no account numbers, no credentials in fixtures or fields.
- Do not encourage later labs to log arbitrary arguments because MCP-004 indexed one resource id.

---

## Sequences vs LAB-MCP-003

Event **names** and operation flags stay the same. Story on B/C is **resource**, not scope.

| Id | MCP-004 story | `mcp.started`? |
|----|---------------|----------------|
| A | Authorized resource ALLOW | yes → completed |
| B | Ungranted resource, fail-open ALLOW | yes → completed |
| C | Ungranted resource DENY | **no** |
| D | Unknown resource ERROR | **no** |
| E | Malformed args ERROR | **no** |
| F | Control evaluation ERROR | **no** |
| G | Valid ALLOW then handler failure | yes → `mcp.failed` |

Invariants for the emitter (already in 1.1.0):

- DENY before execution
- ERROR before execution
- `mcp.failed` means the handler **began**
- ALLOW on the control event is **not** proof of execution

---

## Splunk / detection impact

Phase 5A: no new indexed names. Phase 5B emitted schema 1.2.0 resource fields. Phase 5C **indexed** them (OBSERVED).

Existing Q-MCP-* remain valid for identity, decision, scope (constant in this lab), params blob, execution, after-DENY. They do **not** filter `schema.version=1.1.0`. LAB-MCP-001 `catalog.json` `schema.version=1.1.0` is historical **metadata**.

`Q-MCP-RESOURCE-AUTHZ` is the structured resource hunt (one search). Preview/hash is not that hunt.

DET-MCP-001 remains the execution-after-DENY detector. It was **not** modified. Live MCP-004 specimens: 0 rows. SIMULATED resource fixture: 1 row, not indexed.

Do not create DET-MCP-004. Do not build Dashboard Studio in 5C.
