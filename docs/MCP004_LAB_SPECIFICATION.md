# LAB-MCP-004 specification (design only)

**Status:** Phase 5A **DESIGN**. Do not treat this file as runtime, Splunk, or Studio delivery.  
**Parents:** `docs/MCP004_PARAMETER_MODEL.md`, `docs/MCP004_THREAT_MODEL.md`, `docs/MCP004_EVENT_MODEL_REVIEW.md`.  
**Evidence class:** **DOCUMENTED** design. Current runtime facts marked **OBSERVED**.

---

## Lab identity

| Item | Value |
|------|--------|
| Lab | LAB-MCP-004 |
| Attack | MCP-004 — parameter / resource authorization (IDOR-shaped substitution) |
| Control | **CTRL-MCP-001** (extend; no CTRL-MCP-004) |
| Agent | `acme-agent-mcp-001` |
| Tool | `lookup_policy` (existing harmless fixture + second catalog snippet) |
| Method | `tools/call` |
| Workflow | `mcp_tool_lab` / `POST /mcp/invoke` |
| Primary invariant | INV-001 |

LAB-MCP-001 remains the tool-grant lab. LAB-MCP-003 remains the scope lab. Do not retcon either.

---

## Security property

**Question:** Is this agent authorized to perform this permitted tool/scope operation against **this resource**?

| Concept | LAB-MCP-001 | LAB-MCP-003 | LAB-MCP-004 |
|---------|-------------|-------------|-------------|
| Variable | tool name | requested scope | `policy_id` |
| Held constant | — | same tool + same args | same **tool** + same **scope** |
| Fail-open | ungranted tool | granted tool + excessive catalog scope | granted tool+scope + known **ungranted resource** |

---

## Resource tokens (exact membership)

See `docs/MCP004_PARAMETER_MODEL.md`.

| Role | Value |
|------|--------|
| Tool | `lookup_policy` (granted) |
| Requested scope (all A/B/C) | `policy:read` (granted) |
| Resource catalog | `{lending-basics, executive-restricted}` |
| Agent grant `allowed_policy_ids` | `{lending-basics}` |
| BASELINE `policy_id` | `lending-basics` |
| ATTACK / RETEST `policy_id` | `executive-restricted` |
| Unknown teaching id | `does-not-exist` |

---

## Authorization order (server)

1. Tool exists  
2. Tool granted  
3. Requested scope valid  
4. Requested scope granted  
5. Argument schema valid  
6. Resource in server catalog  
7. Resource granted to agent  
8. ALLOW  
9. Handler (`mcp.started` only after this)

Handler must **not** be the ACL. No second authorization inside the stub beyond using the ticket identity.

---

## Decision table (defended)

| Condition | Decision | Reason |
|-----------|----------|--------|
| Unknown tool | ERROR | `unknown_tool` |
| Known, ungranted tool | DENY | `tool_not_granted` (MCP-002; not this ATTACK) |
| Unknown / ungranted scope | ERROR / DENY | existing MCP-003 reasons (not this ATTACK) |
| Missing/wrong-type/extra args | ERROR | `malformed_arguments` |
| Schema-valid id not in catalog | ERROR | `unknown_resource` |
| Catalog id not in grant | DENY | `resource_not_granted` |
| Tool + scope + resource granted | ALLOW | `tool_granted` (do not invent `resource_granted` as the ALLOW reason) |
| Control function throws | ERROR | `control_evaluation_failure:…` |
| ALLOW then handler throws | — | `mcp.started` then `mcp.failed`; not prevention |

---

## Vulnerable profile (MCP-004 only)

When **all** of:

- `profile=vulnerable`
- tool registered and granted
- scope catalog-valid and granted
- schema valid
- resource **known**
- resource **not** granted

Then ALLOW `vulnerable_profile_fail_open:resource_not_granted`. Handler executes. Grant telemetry unchanged.

Do not fail-open unknown resource or malformed arguments.

---

## Canonical specimens

Same tool. Same scope. Only profile, mode, and `policy_id` change as specified.

### A — BASELINE

| Field | Value |
|-------|--------|
| profile | defended |
| mode | BASELINE |
| tool | `lookup_policy` (granted) |
| requested_scope | `policy:read` (granted) |
| policy_id | `lending-basics` (granted) |
| decision | ALLOW `tool_granted` |
| handler | 1 |
| terminal MCP | `mcp.completed` |

### B — ATTACK

| Field | Value |
|-------|--------|
| profile | vulnerable |
| mode | ATTACK |
| tool / scope | same as A (still granted) |
| policy_id | `executive-restricted` |
| decision | ALLOW `vulnerable_profile_fail_open:resource_not_granted` |
| handler | 1 |
| terminal MCP | `mcp.completed` |

DET-MCP-001 does **not** fire: there is no DENY.

### C — RETEST

| Field | Value |
|-------|--------|
| profile | defended |
| mode | RETEST |
| tool / scope / args | identical to ATTACK |
| decision | DENY `resource_not_granted` |
| handler | **0** |
| MCP | **no** `mcp.started` |

Only profile/mode change between B and C.

### D — unknown resource (teaching, not RETEST)

`policy_id=does-not-exist`, defended → ERROR `unknown_resource`, handler 0.

### E — malformed argument

`{}` / `{"policy_id": 123}` → ERROR `malformed_arguments`, handler 0.

### F — control evaluation failure

ERROR `control_evaluation_failure:…`, handler 0, no `mcp.started`.

### G — handler failure after valid authorization

ALLOW `tool_granted` (`lending-basics`) → `mcp.started` → `mcp.failed` (`executed=true`, `outcome=error`).

---

## Edge cases (tests, not this phase’s code)

| Case | Input | Defended result |
|------|--------|-----------------|
| Extra HTTP `allowed_policy_ids` | extra body key | ERROR `unknown_fields` |
| Grant inside arguments | extra arg keys | ERROR `malformed_arguments` |
| Case / whitespace / homoglyph | not exact catalog id | ERROR `unknown_resource` |
| Wildcard / path-shaped | `../lending-basics`, `*` | ERROR `unknown_resource` (or malformed if not a string) |
| MCP-002 overlap | `lookup_customer_tier` | `tool_not_granted` / MCP-002 fail-open |
| MCP-003 overlap | `policy:restricted:read` + `lending-basics` | MCP-003 path |
| Result as later grant | completed text | INV-002 |

Canonical A/B/C packs should set `attack.id=MCP-004` explicitly (same pattern as MCP-003). HTTP `lookup_policy`+`policy:read`+`lending-basics` remains MCP-001 for LAB-MCP-001.

---

## Planned unit / security tests (later)

NORMAL: A.  
MALICIOUS: B vs C; extra JSON grants; IDOR substitution.  
MALFORMED: missing/int/array/extra keys.  
BOUNDARY: exact `lending-basics` vs `executive-restricted` vs `does-not-exist`; case/whitespace.  
DEPENDENCY: control exception → ERROR, no handler.  
BYPASS: spy `handler_invoke_count==0` on C and D; control **before** handler; fail-open does not mutate grant; ticket resource_id equals handler id.

Deterministic authorize tests stay separate from LLM.

---

## Telemetry sequences (no schema bump in 5A)

Preserve: ALLOW ≠ execution; DENY/ERROR before handler; `mcp.failed` ≠ prevention.

| Id | Story | Sequence |
|----|--------|----------|
| **A** | Authorized resource | control ALLOW → `mcp.started` → `mcp.completed` |
| **B** | Ungranted resource, vulnerable | control ALLOW (labeled fail-open) → `mcp.started` → `mcp.completed` |
| **C** | Ungranted resource, defended | control DENY → **no** `mcp.started` |
| **D** | Unknown resource | ERROR `unknown_resource` → **no** `mcp.started` |
| **E** | Malformed argument | ERROR `malformed_arguments` → **no** `mcp.started` |
| **F** | Control evaluation failure | ERROR → **no** `mcp.started` |
| **G** | Handler failure after valid ALLOW | ALLOW → `mcp.started` → `mcp.failed` |

---

## Splunk questions (IDs only — no SPL this phase)

| Teaching question | Existing ID | New ID? |
|-------------------|-------------|---------|
| Who requested which tool? | **Q-MCP-WHO** | No |
| What was the decision and reason? | **Q-MCP-AUTHZ** | No |
| What scope was requested vs allowed? | **Q-MCP-SCOPE** | No (held constant `policy:read`) |
| What argument **blob** was supplied? | **Q-MCP-PARAMS** | No — preview/hash; not a grant table |
| Did execution begin? | **Q-MCP-EXECUTED** / **Q-MCP-TOOL** | No |
| Events after DENY same run/tool? | **Q-MCP-AFTER-DENY** | No |
| What **resource** was requested, and was it granted? | none structured today | **Q-MCP-RESOURCE-AUTHZ** — **justified hunt** after schema fields exist. Do **not** create the file in 5A. |

**Why a new hunt id:** Q-MCP-PARAMS answers “what 200-character preview/hash of the request JSON.” It is not a stable `requested vs allowed resource` table. Parsing preview JSON is not a contract. That is the same reason MCP-003 did not hunt scope via preview.

Do not duplicate Q-MCP-AUTHZ. Do not write SPL in 5A.

---

## Detection vs hunt

**Invariant:** a CTRL-MCP-001 **DENY** (including `reason=resource_not_granted`) must not be followed by `mcp.started` for the same `run.id` + tool.

**Decision: reuse DET-MCP-001.** Do not create DET-MCP-004.

| Case | DET-MCP-001 |
|------|-------------|
| C RETEST (DENY, no start) | no fire (negative) |
| Hypothetical bug: DENY then start | **would fire** |
| B ATTACK (fail-open ALLOW) | **no fire** |
| D/E ERROR | **no fire** (ERROR is not DENY) |

### Correlation limitation (real, not a 5A code change)

DET-MCP-001 `eventstats` groups by `run_id, tool` only (**OBSERVED** in `DET-MCP-001.spl`).

This lab is **one invocation per run**. `run.id` + tool is sufficient.

If a **future** run issues two `lookup_policy` calls (e.g. DENY on `executive-restricted`, then ALLOW on `lending-basics`), a later `mcp.started` would match the earlier DENY. Resource identity or invocation identity would then be required. **Do not modify DET-MCP-001 in 5A.** Document the scaling limit.

Hunt with **Q-MCP-RESOURCE-AUTHZ** (later) for mismatch; detector stays the generic DENY→start invariant.

---

## Workshop plan (not built)

Ten-step GRID, later `ws_lab_mcp_004`. Do not change `ws_lab_mcp_001` or `ws_lab_mcp_003`.

| Step | Learner does |
|------|----------------|
| LEARN | Tool ≠ scope ≠ resource. Valid ≠ authorized. |
| BASELINE | Run A. ALLOW + handler. |
| ATTACK | Run B. Same tool/scope; other `policy_id`; labeled fail-open. |
| OBSERVE | Control before `mcp.started`; grant unchanged. |
| HUNT | Q-MCP-AUTHZ reason; later Q-MCP-RESOURCE-AUTHZ. |
| DETECT | DET-MCP-001 does **not** fire on B. |
| DEFEND | Exact membership; DENY before handler. |
| RETEST | Run C. DENY; handler 0. |
| COMPARE | A vs B vs C: same tool, same scope, different resource. |
| PROVE | Runtime spy is authority. Splunk observes. |

---

## Security review (design)

| ID | Issue | Severity | Design fix |
|----|--------|----------|------------|
| SR-1 | Prefix/regex/wildcard/path as resource match | **BLOCKER** (if used) | **Rejected.** Exact opaque ids. |
| SR-2 | Silent trim / case fold / Unicode normalize into ALLOW | **BLOCKER** (if used) | **Rejected.** Exact equality. |
| SR-3 | Handler `found:false` as the ACL (authorize after start) | **HIGH** | Catalog+grant **before** ticket; handler uses ticket id. |
| SR-4 | Client-supplied grant (`allowed_policy_ids`, `authorized=true`) | **HIGH** | Extra HTTP → `unknown_fields`; extra args → `malformed_arguments`. |
| SR-5 | Fail-open rewrites the resource grant | **HIGH** | Telemetry always coded `{lending-basics}`. |
| SR-6 | Collapse MCP-002/003/004 fail-open reasons | **HIGH** | Distinct `…:resource_not_granted`. |
| SR-7 | Collapse unknown resource with ungranted | **HIGH** | ERROR vs DENY, same as MCP-003. |
| SR-8 | Collapse malformed with ungranted | **HIGH** | Schema ERROR vs DENY `resource_not_granted`. |
| SR-9 | Authorize A, execute B (re-parse / copy drift) | **HIGH** | Ticket binds exact `resource_id`. |
| SR-10 | Scope used as resource (or the reverse) | **HIGH** | Specimens keep `policy:read`; resource is `policy_id`. |
| SR-11 | Full argument dump / secrets in telemetry | **HIGH** | Preview/hash retained; structured resource id only if approved (non-secret lab fixture). |
| SR-12 | Tool result grants a policy id | **HIGH** | INV-002; coded policy only. |
| SR-13 | DET-MCP-001 multi-invoke ambiguity | **MEDIUM** | Single invoke per run in this lab; document future need for resource/invocation key. Do not change DET-MCP-001 now. |
| SR-14 | ERROR vs DENY enumerates catalog via telemetry | **MEDIUM** | Accepted for teaching; no list API; no chatty client copy. |
| SR-15 | Duplicate JSON keys (parser last-wins) | **MEDIUM** | 5A: authorize and execute the **same** parsed dict. **5B:** reject duplicate keys before authorize (`duplicate_json_keys`). |
| SR-16 | `lookup_customer_tier` resource ACL omitted | **LOW** | Out of v1; MCP-002 remains tool-grant. |
| SR-17 | Agent-only grant (no principal ACL) | **LOW** | Documented lab simplification. |
| SR-18 | Restricted snippet visible on fail-open | **LOW** | Harmless lab text; still proves execution. |

No remaining design **BLOCKER**. **HIGH** items are closed in this spec. Implementation must not reopen them.

---

## Out of scope

MCP-005 result trust as a lab, MCP-006, shell/RCE, Cisco, MLTK, ES notables, schema file edits, new Splunk files, Studio XML, DET-MCP-004, principal-specific ACLs, multi-invoke runs.

---

## Open questions (for 5B, not blockers)

| Question | Lean | 5B resolution |
|----------|------|----------------|
| Schema 1.2.0 vs in-place additive 1.1.0 properties | Prefer **1.2.0** because `additionalProperties: false` and new investigation fields. 5A does not edit the schema. | **1.2.0 implemented** (`docs/SCHEMA_1_2_0.md`). |
| Generic HTTP error string vs exposing `reason` on `/mcp/invoke` | Keep existing lab hop fields; do not add a catalog-existence API. | Kept hop `control.reason`. No `list_policies` API. |
| Does `lookup_customer_tier` need `allowed_customer_ids` in the same control? | **No** for LAB-MCP-004. | No resource catalog on that tool; MCP-002 unchanged. |
