# LAB-MCP-003 specification (design only)

**Status:** Phase 4A **DESIGN** (history preserved). Phase 4B runtime **IMPLEMENTED** — see `docs/MCP003_RUNTIME_CONTRACT.md`.  
**Do not:** treat this file as Splunk or Studio delivery.  
**Parents:** `docs/MCP003_SCOPE_MODEL.md`, `docs/MCP003_THREAT_MODEL.md`, `docs/MCP003_EVENT_MODEL_REVIEW.md`.  
**Evidence class:** **DOCUMENTED** design. Runtime facts in Phase 4B are **MEASURED**.

---

## Lab identity

| Item | Value |
|------|--------|
| Lab | LAB-MCP-003 |
| Attack | MCP-003 — scope escalation |
| Control | **CTRL-MCP-001** (extend; no CTRL-MCP-003) |
| Agent | `acme-agent-mcp-001` |
| Tool | `lookup_policy` (existing harmless fixture) |
| Method | `tools/call` |
| Workflow | `mcp_tool_lab` / `POST /mcp/invoke` |
| Primary invariant | INV-001 |

LAB-MCP-001 remains the tool-grant lab. Do not retcon its ATTACK (`lookup_customer_tier`) into a scope lab.

---

## Security property

**Question:** Is this agent authorized to perform this action **at this requested scope**?

| Concept | LAB-MCP-001 | LAB-MCP-003 |
|---------|-------------|-------------|
| Variable | tool name | requested scope |
| Held constant | (tool changes on ATTACK) | same granted tool + same arguments |
| Fail-open | ungranted **tool** | granted tool + **excessive catalog-valid scope** |

---

## Scope tokens (exact membership)

See `docs/MCP003_SCOPE_MODEL.md`.

| Role | Value |
|------|--------|
| Tool catalog `valid_scopes` | `{policy:read, policy:restricted:read}` |
| Agent grant `allowed_scopes` | `{policy:read}` |
| BASELINE request | `policy:read` |
| ATTACK / RETEST request | `policy:restricted:read` |
| Arguments (all three) | `{"policy_id": "lending-basics"}` |

Colons are labels, not a hierarchy. `policy:read` does **not** imply `policy:restricted:read`.

`docs/MCP_LAB_PLAN.md` sketched `policy:write`. **Superseded** for this lab: write-sounding tokens imply mutation the handler does not do.

---

## Authorization order (server)

After HTTP closed contract (`tool`, `arguments`, `requested_scope`, `user_id`):

1. Tool exists (registry)
2. Tool granted (`allowed_tools`)
3. Requested scope **valid** (∈ tool `valid_scopes`)
4. Requested scope **within grant** (∈ `allowed_scopes`)
5. Argument key/schema validation
6. ALLOW
7. Handler execution (`mcp.started` only after this)

If scope is excessive (catalog-valid, not granted):

- Defended: **DENY** `scope_not_granted`, `attempted=false`, `executed=false`, `outcome=prevented`, handler count **0**, **no** `mcp.started`
- Vulnerable: labeled fail-open ALLOW (below)

Handler must **not** inspect scope. No second authorization inside the stub.

---

## Decision table (defended)

| Condition | Decision | Reason |
|-----------|----------|--------|
| Unknown tool | ERROR | `unknown_tool` |
| Known, ungranted tool | DENY | `tool_not_granted` (MCP-002; not this lab’s ATTACK) |
| Granted + missing/blank `requested_scope` | ERROR | `missing_requested_scope` (HTTP, before control; **OBSERVED** today) |
| Granted + malformed type (list/object) | ERROR | existing malformed / `unknown_fields` |
| Granted + token not in tool catalog | ERROR | `unknown_scope` (**new** vs today’s catch-all DENY) |
| Granted + catalog-valid + not in grant | DENY | `scope_not_granted` |
| Granted + in grant | ALLOW | `tool_granted` (keep this reason; do not invent `scope_granted`) |
| Control function throws | ERROR | `control_evaluation_failure:…` |
| ALLOW then handler throws | — | `mcp.started` then `mcp.failed`; not prevention |

---

## Vulnerable profile (MCP-003 only)

When **all** of:

- `profile=vulnerable`
- tool registered **and** granted
- `requested_scope` ∈ tool `valid_scopes`
- `requested_scope` ∉ agent `allowed_scopes`

Then:

- decision **ALLOW**
- reason **`vulnerable_profile_fail_open:scope_not_granted`**
- handler **executes**
- telemetry **keeps** `requested_scope=policy:restricted:read` and `allowed_scope=policy:read`

Do **not**:

- rewrite `allowed_scope` to match requested
- reuse the MCP-002 fail-open string (ungranted tool)
- fail-open unknown tool, unknown scope token, missing scope, or control evaluation failure

**OBSERVED gap today:** `authorize.py` DENYs `scope_not_granted` even when `profile=vulnerable`. Implementation later adds this **separate** branch.

---

## Canonical specimens

Same `policy_id`. Same tool. Only profile, mode, and `requested_scope` change as specified.

### A — BASELINE

| Field | Value |
|-------|--------|
| profile | defended |
| mode | BASELINE |
| tool | `lookup_policy` (granted) |
| requested_scope | `policy:read` (granted) |
| decision | ALLOW `tool_granted` |
| handler | 1 |
| terminal MCP | `mcp.completed` |

### B — ATTACK

| Field | Value |
|-------|--------|
| profile | vulnerable |
| mode | ATTACK |
| tool | `lookup_policy` (still granted) |
| requested_scope | `policy:restricted:read` |
| decision | ALLOW `vulnerable_profile_fail_open:scope_not_granted` |
| handler | 1 |
| terminal MCP | `mcp.completed` |

DET-MCP-001 does **not** fire: there is no DENY.

### C — RETEST

| Field | Value |
|-------|--------|
| profile | defended |
| mode | RETEST |
| tool / args / scope | identical to ATTACK |
| decision | DENY `scope_not_granted` |
| handler | **0** |
| MCP | **no** `mcp.started` |

---

## Edge cases (tests, not this phase’s code)

None of these widen authority. HTTP extra keys remain ERROR `unknown_fields` before authorize.

| Case | Input | Defended result |
|------|--------|-----------------|
| Unknown tool | `no_such_tool` + any scope | ERROR `unknown_tool` |
| Known ungranted tool | `lookup_customer_tier` + `customer:read` | DENY `tool_not_granted` (MCP-001/002) |
| Valid tool + valid scope | A | ALLOW |
| Valid tool + excessive catalog scope | C | DENY `scope_not_granted` |
| Missing `requested_scope` | omit / blank | ERROR `missing_requested_scope`; no control widening |
| Malformed `requested_scope` | non-string, list | ERROR; not ALLOW |
| Multiple scopes | `"policy:read,policy:restricted:read"` as one string | not in catalog → ERROR `unknown_scope` (v1 has no multi-scope) |
| Client `allowed_scope` | extra JSON field | ERROR `unknown_fields` |
| Scope only in `arguments` | `arguments.scope` / `arguments.requested_scope`; omit top-level | ERROR `missing_requested_scope`. Authorize **must not** read arguments for scope |
| Scope in extra JSON | `x-scope` header analog: extra body key | ERROR `unknown_fields` |
| Case / whitespace | `policy:Read`; leading space already stripped **OBSERVED** | unknown token → ERROR `unknown_scope` |
| Wildcard / prefix | `policy:*`, `policy:` | ERROR `unknown_scope` |
| Tool result as later grant | completed result text | INV-002; `policy_unchanged_by_result` |

---

## Planned unit / security tests (later)

NORMAL: A.  
MALICIOUS: B vs C; extra JSON allowed_scope; scope in arguments.  
MALFORMED: missing/list/wildcard scope.  
BOUNDARY: exact `policy:read` vs `policy:restricted:read`; ungranted tool still MCP-002 path.  
DEPENDENCY: `evaluate_mcp_control` exception → ERROR, no handler.  
BYPASS: spy `handler_invoke_count==0` on C; control **before** handler; fail-open does not mutate `allowed_scope`.

Deterministic authorize tests stay separate from LLM.

---

## Telemetry sequences (schema 1.1.0; no bump)

Preserve: DENY/ERROR before execution; `mcp.failed` ≠ prevention; ALLOW ≠ execution.

| Id | Story | Sequence |
|----|--------|----------|
| **A** | Authorized scope | `run.started` → hop → control ALLOW → `mcp.started` → `mcp.completed` → hop/run completed |
| **B** | Excessive scope, vulnerable | control ALLOW (labeled fail-open) → `mcp.started` → `mcp.completed` |
| **C** | Excessive scope, defended | control DENY → `pipeline.stopped` → **no** `mcp.started` → `run.completed` `completed_denied` |
| **D** | Malformed / unknown scope | ERROR (`missing_requested_scope` / `unknown_scope` / `unknown_fields`) → **no** `mcp.started` → `run.failed` |
| **E** | Control evaluation failure | ERROR `control_evaluation_failure:…` → **no** `mcp.started` |
| **F** | Handler failure after valid ALLOW | ALLOW `tool_granted` (`policy:read`) → `mcp.started` → `mcp.failed` (`executed=true`, `outcome=error`) |

---

## Splunk questions (IDs only — no SPL this phase)

**Reuse** validated LAB-MCP-001 searches. Do not duplicate.

| Teaching question | Existing ID | New ID? |
|-------------------|-------------|---------|
| Who requested which tool? | **Q-MCP-WHO** | No |
| What was the decision and reason? | **Q-MCP-AUTHZ** | No |
| What was requested vs allowed? | **Q-MCP-SCOPE** | No. `scope_relation` already labels `known_but_ungranted` |
| Did execution begin? | **Q-MCP-EXECUTED** / **Q-MCP-TOOL** | No |
| Events after DENY same run/tool? | **Q-MCP-AFTER-DENY** | No |

Alias map (questions only; **do not** add files until a contract hole is proven):

| Alias | Maps to |
|-------|---------|
| Q-MCP-SCOPE-REQUEST | Q-MCP-SCOPE (`requested_scope`) |
| Q-MCP-SCOPE-AUTHZ | Q-MCP-AUTHZ |
| Q-MCP-SCOPE-MISMATCH | Q-MCP-SCOPE (`scope_relation=known_but_ungranted`) |
| Q-MCP-SCOPE-EXECUTED | Q-MCP-EXECUTED |
| Q-MCP-SCOPE-AFTER-DENY | Q-MCP-AFTER-DENY |

Q-MCP-SCOPE.md still says it “does not implement MCP-003 labs.” That means the **lab specimens** are absent, not that the search cannot show requested vs allowed. MCP-003 should bind the same SPL.

---

## Detection candidate

**Invariant:** a CTRL-MCP-001 **DENY** (including `reason=scope_not_granted`) must not be followed by `mcp.started` for the same `run.id` + tool.

**Decision: reuse DET-MCP-001.** Do not create DET-MCP-003.

| Case | DET-MCP-001 |
|------|-------------|
| C RETEST (DENY, no start) | no fire (negative) |
| Hypothetical bug: DENY then start | **would fire** (same as any DENY) |
| B ATTACK (fail-open ALLOW) | **no fire** — ALLOW is out of DET-MCP-001 by design |

Scope context already exists on the DENY event (`requested_scope`, `allowed_scope`) and DET-MCP-001 copies those fields. Hunt with **Q-MCP-SCOPE** for mismatch; do not add a second detector for “ALLOW with mismatched scopes” in this lab.

Do not modify DET-MCP-001 this phase.

---

## Workshop plan (not built)

Ten-step GRID, later `ws_lab_mcp_003`. Do not change `ws_lab_mcp_001`.

| Step | Learner does |
|------|----------------|
| LEARN | Tool grant ≠ scope grant. Registered ≠ authorized at every scope. |
| BASELINE | Run A. ALLOW + handler. |
| ATTACK | Run B. Same tool; excessive scope; labeled fail-open; handler runs. |
| OBSERVE | Local `events.jsonl`: requested ≠ allowed; ALLOW still executed. |
| HUNT | Q-MCP-SCOPE mismatch; Q-MCP-EXECUTED shows start. |
| DETECT | DET-MCP-001 does **not** fire on B. It would fire only if a DENY were followed by start. |
| DEFEND | Explain exact membership + fail-closed `scope_not_granted`. |
| RETEST | Run C. DENY; handler 0. |
| COMPARE | A vs B vs C: same tool, different scope/profile. |
| PROVE | Runtime spy is authority. Splunk observes. Splunk does not authorize. |

Learner must be able to explain:

- tool authorization ≠ scope authorization
- registered ≠ authorized at every scope
- ALLOW ≠ execution
- scope mismatch evaluated **before** handler
- `requested_scope` must not rewrite `allowed_scope`
- Splunk observes but does not authorize

---

## Security review (design)

| ID | Issue | Severity | Design fix |
|----|--------|----------|------------|
| SR-1 | Prefix / `startsWith` (`policy:` grants `policy:restricted:read`) | **BLOCKER** (if used) | **Rejected.** Exact set membership only. |
| SR-2 | Regex / substring / wildcard IAM | **BLOCKER** (if used) | **Rejected.** Catalog + grant sets. |
| SR-3 | Fail-open rewrites `allowed_scope` | **HIGH** | Telemetry always coded grant; mismatch remains visible. |
| SR-4 | Client-supplied `allowed_scope` | **HIGH** | Extra JSON → ERROR `unknown_fields` (existing). |
| SR-5 | Scope taken from `arguments` or result | **HIGH** | Authorize reads only request `requested_scope` + coded policy. |
| SR-6 | Collapse MCP-002 and MCP-003 fail-open | **HIGH** | Separate reasons; ungranted tool ≠ excessive scope. |
| SR-7 | Authorize after handler start | **HIGH** | Same CTRL-MCP-001-before-handler placement as LAB-MCP-001. |
| SR-8 | Case / whitespace normalization bugs | **MEDIUM** | Strip at parse (existing); remaining case variants → `unknown_scope` ERROR, not silent ALLOW. |
| SR-9 | Multi-scope / comma lists | **MEDIUM** | v1: not a list; whole string must match catalog. |
| SR-10 | Colon tokens look hierarchical | **LOW** | Docs state labels, not a tree. |
| SR-11 | Handler returns “restricted” text after fail-open | **LOW** | Same `lending-basics` fixture; not a confidentiality lab. |
| SR-12 | DET-MCP-001 silence on ATTACK | **LOW** (teaching) | Document: fail-open ALLOW is not that detector. |

No remaining design **BLOCKER**. **HIGH** items are closed in this spec. Implementation must not reopen them.

---

## Out of scope

MCP-004 parameter abuse, MCP-005 result trust as a lab, MCP-006, shell/RCE, Cisco scanner, ES notables, schema version bump, new Splunk files, Studio XML.

---

## Phase 4B resolutions (implementation)

Planning history above is unchanged. Runtime locked:

| Open question | Resolution |
|---------------|------------|
| `unknown_scope` HTTP vs control | CTRL-MCP-001 **ERROR** `unknown_scope`, `error_stage=schema_validation`. Missing/blank still HTTP/server `missing_requested_scope`. |
| Trim vs reject whitespace | **No trim** on authority-bearing tokens (Phase 4B). `"policy:read "` → `unknown_scope`. Whitespace-only → `missing_requested_scope`. |
| Comma-list | **ERROR `unknown_scope`** (single opaque string). |
| `ToolSpec.required_scope` | **Supplemented** by `valid_scopes`; `required_scope` must be a member. |
| Schema | Version stays **1.1.0**. Additive `MCP-003` on `agentsec.attack.id` enum only. |
