# MCP-006 event model review (schema 1.3.0)

**Status:** Phase 7A **DESIGN** left 1.3.0 unchanged. Phase 7B **implemented schema 1.4.0** (`docs/SCHEMA_1_4_0.md`). This file remains the 7A review plus the 7B bump note.  
**Parents:** `docs/MCP_EVENT_MODEL.md`, `docs/SCHEMA_1_3_0.md`, `docs/MCP006_LAB_SPECIFICATION.md`.  
**Evidence class:** **DOCUMENTED**. Current emission facts are **OBSERVED** from `schemas/security_event.schema.json`.

Do not emit MCP-006 / CTRL-DELEGATION-001 / `mcp_delegation` on the wire in this phase. Do not invent Splunk fields that the schema does not contain.

---

## Decision (7A)

Leave **`agentsec.security_event` 1.3.0 unchanged.**

MCP-006 needs a **new control**, a **new attack id**, and a way to record **which authority set** governed the decision. Today’s closed schema cannot honestly carry those facts (`additionalProperties: false`). Adding them is a **later additive bump** (same pattern as 5A→5B and 6A→6B). 7A does not perform that bump.

Do **not** overload `control.type=mcp_allowlist` / `CTRL-MCP-001` for delegation. That would make Splunk unable to tell tool authorization from delegated authorization.

Do **not** overload `mcp_result_trust` / `CTRL-MCP-RESULT-001`. That is INV-002.

Do **not** invent `gen_ai.tool.call.id` in SPL. Prefer that OTel name if a later bump adds call correlation. Canonical A/B/C use **different tools** plus `run.id` + `hop.index` + `sequence`.

---

## What 1.3.0 already has (OBSERVED)

| Need | 1.3.0 today |
|------|-------------|
| Caller vs deputy agent id | `gen_ai.agent.id` / `gen_ai.agent.name` per hop |
| Prior hop attribution | `agentsec.delegator.agent.id` — required hop ≥ 1; **forbidden hop 0**; description: “Deterministic attribution, **not A2A**” |
| Hop index | `agentsec.hop.index` 0–3 |
| Principal | `agentsec.principal.id` / `user.id` |
| Tool name | `gen_ai.tool.name` (required on MCP start/complete and on `mcp_allowlist` / `mcp_result_trust` decisions; **not** required on generic `control.decision`) |
| Decision / reason | ALLOW / DENY / ERROR / OBSERVE |
| MCP tool control | `control.type=mcp_allowlist` ⇒ `control.id` **const** `CTRL-MCP-001` |
| Result trust control | `control.type=mcp_result_trust` ⇒ `CTRL-MCP-RESULT-001` |
| Attack id | enum through **MCP-005** — **not MCP-006** |
| Control types | `input_inspection`, `schema_validation`, `mcp_allowlist`, `mcp_result_trust` — **no delegation type** |
| Trust boundaries | includes `acmebank.mcp.authorize`, `mcp.tool.execute`, `mcp.tool.result` — **no** `acmebank.mcp.delegate` |
| Requested / allowed scope | `agentsec.mcp.requested_scope` / `allowed_scope` |
| Resource ids | `agentsec.mcp.resource.id` / `allowed_resource.ids` |
| Allowed tools on the wire | **no** `agentsec.mcp.allowed_tools` (Phase 6C limitation still true) |
| Call correlation | `run.id`, `trace_id`, `span_id`, `parent_span_id`, `sequence` — **no** `gen_ai.tool.call.id` |
| Authority source | **absent** |
| Workflow entry | `/process` \| `/mcp/invoke` |

---

## Why 1.3.0 is not enough for honest MCP-006 evidence

### 1. Attack id MCP-006 is not in the enum

Emitting `agentsec.attack.id=MCP-006` today would fail schema validation. Do not fake it as MCP-001 or MCP-005.

### 2. CTRL-DELEGATION-001 cannot reuse `mcp_allowlist`

If `control.type=mcp_allowlist`, schema requires `control.id=CTRL-MCP-001`. Delegation is a different control, a different invariant emphasis, and a different fail-open reason.

### 3. Authority source cannot be reconstructed from existing grant fields

`allowed_scope` on hop 1 would show **whatever policy object was consulted**. On vulnerable ATTACK that would be deputy ambient (`customer:read`) — which **looks like a real grant** and hides the bug if we do not also record that the **delegated** set excluded the tool.

Phase 6C already cannot index `allowed_tools`. Splunk therefore **cannot** currently prove “credit’s delegated set vs compliance’s ambient set” from LIVE fields.

**Security question Splunk must eventually answer (Q5):** which authority set governed CTRL-DELEGATION-001?

That is why a later bump should add an explicit **authority source**, not another grant list copied into every row.

### 4. Identity fields are enough if hops are used correctly

Do **not** add `agentsec.delegation.caller.id` / `deputy.id` / `delegator.id` in the first bump unless hop reuse proves insufficient.

Proposed reconstruction:

| Question | Existing field (if 7B emits two hops as specified) |
|----------|-----------------------------------------------------|
| Who asked? | hop 0 `gen_ai.agent.id` = credit-002 |
| Who executed? | hop 1 `gen_ai.agent.id` = compliance-004 |
| Who delegated? | hop 1 `delegator.agent.id` = credit-002 (same as caller in this lab) |
| What was requested? | hop 0 `gen_ai.tool.name` on CTRL-DELEGATION-001 |
| Did execution begin? | hop 1 `agentsec.mcp.started` |

Overloading `delegator.agent.id` is **documented in-process attribution**, not A2A. MCP-005 already sets it to the same MCP agent on hop 1. MCP-006 would be the first MCP lab where delegator ≠ executor. That is a teaching feature, not a schema change.

### 5. OBSERVE is the wrong decision for this control

Delegation is ALLOW / DENY / ERROR. Do not emit OBSERVE for CTRL-DELEGATION-001. OBSERVE remains MCP-005 result-trust.

---

## Proposed later minimum telemetry (not implemented)

Additive bump (conceptual 1.4.0 — **name not reserved** until 7B):

| Addition | Why |
|----------|-----|
| `agentsec.attack.id` += `MCP-006` | attributable specimens |
| `agentsec.control.type` += `mcp_delegation` | distinct from MCP-001 and RESULT-001 |
| when type is `mcp_delegation`: `control.id` const `CTRL-DELEGATION-001` | closed pairing |
| require `gen_ai.tool.name` on that decision | requested operation |
| `agentsec.delegation.authority.source` enum **`delegated` \| `ambient_deputy`** | Q5; do **not** add `RESULT_DERIVED` here; do **not** add `SERVER_OWNED` unless 7B proves hop fields cannot say “grants are coded” |

Optional, only if hops prove unclear: `trust_boundary` += `acmebank.mcp.delegate`. Prefer **not** adding it if `mcp_delegation` already distinguishes the row. Smaller bump wins.

**Do not add in the first bump:**

- `agentsec.delegation.caller.id` / `deputy.id` / `delegator.id` (reuse hops)
- indexed `allowed_tools` / delegated-grant lists (nice for Q3/Q4; not required if Q5 + requested tool + decision exist; Q3/Q4 remain **runtime/manifest** answers)
- `gen_ai.tool.call.id` (still preferred later; not blocking A/B/C)
- RESULT_DERIVED on the delegation enum
- SANITIZE / QUARANTINE

---

## Correlation analysis

| Chain step | Current fields | Gap? |
|------------|----------------|------|
| Who initiated the run | `run.id`, principal | no |
| Caller hop | hop 0 agent id, parent_span | no, if hop 0 is emitted |
| Delegation decision | **no control type today** | **yes — 7B bump** |
| Deputy hop | hop 1 agent + delegator | no, if hop 1 is emitted |
| MCP authorize | CTRL-MCP-001 | no |
| MCP invoke | `mcp.started` + tool | no |

**Sufficient for designed A/B/C** once the control row exists: `run.id` + `hop.index` + `parent_span_id` + `sequence` + two agent ids + two different tool names.

**Still a gap (same as MCP-005):** two invocations of the **same** tool in one run have no `gen_ai.tool.call.id`. Abuse case 17 (repeated delegation) cannot be split in SPL without sequence-only heuristics. Document; do not invent a Splunk-only id.

Do not claim Splunk can reconstruct the chain from schema 1.3.0 LIVE bytes. It cannot emit the control.

---

## Privacy

Keep preview ≤200 + `sha256:`. Fixture identifiers only. Do not emit tickets’ full argument dumps or grant maps that include secrets (there are none in fixtures).

---

## 7B bump (implemented)

The 7A proposed minimum set was implemented as **1.4.0**. `gen_ai.tool.call.id` and grant lists were **not** added. See `docs/SCHEMA_1_4_0.md`.
