# MCP-005 event model review (schema 1.2.0)

**Status:** Phase 6A **DESIGN**. Schema **1.2.0 unchanged in 6A**.  
**Phase 6B:** schema **1.3.0 implemented** (`docs/SCHEMA_1_3_0.md`). This file remains the 6A review. Do not retcon it.

6A left 1.2.0 unchanged because design must not pretend OBSERVE/RESULT-001/`MCP-005` already existed on the wire. 6B performed the additive bump the 6A “proposed later set” described, minus `gen_ai.tool.call.id`.  
**Parents:** `docs/MCP_EVENT_MODEL.md`, `docs/SCHEMA_1_2_0.md`.  
**Evidence class:** **DOCUMENTED**. Current emission facts are **OBSERVED**.

---

## Decision (6A)

Leave **`agentsec.security_event` 1.2.0 unchanged.**

MCP-005 needs two tools in one run and a result-trust control. Today’s closed schema cannot honestly carry those new facts. Adding them is a **later additive bump** (same pattern as 5A → 5B for resource fields). 6A does not perform that bump.

Do **not** invent `agentsec.mcp.invocation.id` while `gen_ai.tool.call.id` already exists in OpenTelemetry GenAI (Development, not Stable). Prefer that name if a call-correlation field is added later.

Do **not** emit `gen_ai.tool.call.arguments` or `gen_ai.tool.call.result` (opt-in full body). Keep preview ≤200 + `sha256:`.

---

## What 1.2.0 already has (OBSERVED)

| Need | 1.2.0 today |
|------|-------------|
| Tool | `gen_ai.tool.name` |
| GenAI operation | `gen_ai.operation.name=execute_tool` on MCP start/complete |
| Decision / reason | `agentsec.control.decision` / `reason` — enum **ALLOW / DENY / ERROR only** |
| MCP allow-list control | `control.type=mcp_allowlist` ⇒ `control.id` **const** `CTRL-MCP-001` |
| Result trust | `agentsec.mcp.result.trust` — **`untrusted_data` only** |
| Result provenance | `agentsec.mcp.result.provenance` — **`mcp.tool.handler` only** |
| Preview / hash | `agentsec.content.preview` (max 200) + `agentsec.content.hash` |
| Attack id | enum includes MCP-001…MCP-004 — **not MCP-005** |
| Control type | enum `input_inspection`, `schema_validation`, `mcp_allowlist` — **no result-trust type** |
| Call correlation | `run.id`, `trace_id`, `span_id`, `parent_span_id`, `sequence` — **no** `gen_ai.tool.call.id` |
| Full result body | **Not emitted** |

`additionalProperties: false`. Extra keys cannot sneak through.

---

## Why 1.2.0 is not enough for honest MCP-005 evidence

### 1. OBSERVE is the correct RESULT-001 decision and is not in the enum

House vocabulary includes OBSERVE. Schema 1.2.0 does not.

Do **not** emit ALLOW `result_is_data` as a workaround. ALLOW means the dangerous merge may proceed. Defended does not merge.

Until a later schema adds OBSERVE, RESULT-001 must not be claimed as LIVE `control.decision` bytes.

### 2. CTRL-MCP-RESULT-001 cannot reuse `mcp_allowlist`

If `event.name=agentsec.control.decision` and `control.type=mcp_allowlist`, schema requires `control.id=CTRL-MCP-001`.

RESULT-001 is a different control. It needs a **new** `control.type` (e.g. `mcp_result_trust`) and `control.id=CTRL-MCP-RESULT-001`. That is additive. Not 6A.

### 3. Two tools in one run

Current MCP labs emit **one** `tools/call` per `run.id`. DET-MCP-001 and several Q-MCP hunts group by `run.id` + `tool`.

MCP-005 A/B/C use **two different** tool names (`lookup_policy`, then maybe `lookup_customer_tier`). `run.id` + `tool` + `sequence` is **almost** enough for this lab.

Same-tool twice later still needs `gen_ai.tool.call.id`.

### 4. Attack id

`agentsec.attack.id` has no `MCP-005`. Do not emit it until the enum grows.

---

## Correlation guidance (no new fields in 6A)

| Key | Use now (when implemented, still 1.2.0-legal) | Gap |
|-----|-----------------------------------------------|-----|
| `run.id` | Ties first complete to follow-on | One HTTP request today = one run |
| `gen_ai.tool.name` | Distinguishes first vs follow-on **in this lab** | Fails if the same tool runs twice |
| `agentsec.sequence` | Order | Not a call identity |
| `trace_id` / spans | Reconstruct parentage | Not a stable hunt key in current Q-MCP |
| `gen_ai.tool.call.id` | **Preferred later** OTel name | Not in 1.2.0 |

Optional later (minimize):

- `gen_ai.tool.call.id` on each `execute_tool` span / MCP start-complete
- optional parent call id (“influenced by”)
- optional follow-on requested tool on the **result-trust** control event
- optional `instruction_like` / `ordinary_data` **label** (not a decision)

Do not add unbounded `agentsec.mcp.result.*` explosion.

---

## Preview budget

`CONTENT_PREVIEW_MAX = 200` (**OBSERVED**). The MALICIOUS `summary` must keep `SECURITY_OVERRIDE` and `lookup_customer_tier` understandable **inside** 200 characters of the hashed result JSON.

That is a fixture-writing constraint, not a reason to raise the cap or log the full body.

Q-MCP-RESULT already answers preview/hash/trust/provenance. Do not rewrite it in 6A.

---

## Proposed later additive set (not approved as code)

Smallest set that makes RESULT-001 and MCP-005 attributable. Likely a **1.3.0** (name TBD at implementation):

| Change | Why |
|--------|-----|
| `agentsec.control.decision` += `OBSERVE` (and only add SANITIZE / QUARANTINE / REQUIRE_APPROVAL if a lab actually performs those ops) | Honest RESULT-001 defended decision |
| `agentsec.control.type` += `mcp_result_trust` | Distinct from `mcp_allowlist` |
| Allow `control.id=CTRL-MCP-RESULT-001` when type is `mcp_result_trust` | Do not loosen the CTRL-MCP-001 const |
| `agentsec.attack.id` += `MCP-005` | Attribution |
| Optional `gen_ai.tool.call.id` | Two (or N) calls per run |

Rules if implemented later:

- First-call CTRL-MCP-001 events stay `mcp_allowlist` / `CTRL-MCP-001`.
- RESULT-001 emits **after** first `mcp.completed`, **before** overlay use.
- Server-owned grant fields on follow-on CTRL-MCP-001 still show coded `{lookup_policy}`, even when vulnerable ALLOWs via overlay.
- Never rewrite `untrusted_data` to a trusted enum.
- Never emit full result bodies.

6A does **not** bump the schema.

---

## Sequences (design)

Event **names** for MCP start/complete stay the same. Story adds a result-trust row and a second allow-list row.

| Id | Story | Second `mcp.started`? |
|----|-------|------------------------|
| A | NORMAL result; OBSERVE; no follow-on | **no** |
| B | MALICIOUS; overlay ALLOW; follow-on ALLOW | **yes** → completed |
| C | MALICIOUS; OBSERVE; follow-on DENY | **no** |

Invariants for a later emitter:

- First DENY/ERROR still means no first `mcp.started` (unchanged).
- First `mcp.completed` on A/B/C (this lab’s first call is authorized).
- RESULT-001 OBSERVE means overlay **not** applied.
- Follow-on DENY means no second `mcp.started`.
- ALLOW on CTRL-MCP-001 is **not** proof of execution (unchanged).

---

## Existing Q-MCP coverage vs gaps

| Question | Already answers | MCP-005 gap |
|----------|-----------------|-------------|
| Q-MCP-WHO / AUTHZ / TOOL / SCOPE / RESOURCE-AUTHZ / EXECUTED | First-call identity and first execute | Follow-on is a **second** row of the same questions |
| Q-MCP-RESULT | Preview/hash of completed JSON | Does not say whether it mutated authority |
| **Q-MCP-RESULT-TRUST** (implemented) | **Classification:** `untrusted_data` on completed | **Does not** ask “was content used as authority?” despite the Phase 3A LAB_PLAN name |
| Q-MCP-AFTER-DENY / DET-MCP-001 | DENY then `mcp.started` for same `run.id`+tool | Preferred ATTACK B has **no DENY** |

Do not modify those SPL files in 6A.

Justified **future** question IDs (names only, no files):

| Future ID | Question | Why not reuse Q-MCP-RESULT-TRUST |
|-----------|----------|----------------------------------|
| **Q-MCP-RESULT-AUTHORITY** | Did RESULT-001 refuse mutation, and is server-owned `allowed_tools` still `{lookup_policy}`? | Existing Q-MCP-RESULT-TRUST is the **label** hunt and is VALIDATED |
| **Q-MCP-RESULT-FOLLOWON** | Which follow-on tool, which CTRL-MCP-001 decision/reason, did the second handler begin? | New story |

Phase 3A LAB_PLAN mapped “was returned content used as authority?” onto `Q-MCP-RESULT-TRUST`. **Implemented meaning wins.** Do not retcon the validated search.

---

## Privacy / telemetry rules

- Default: preview + hash only.
- No secrets, real customer records, credentials, or account numbers.
- `cust-001` / `standard` remain lab fixtures if the follow-on completes.
- Do not start logging full tool results because MCP-005 needs the marker visible.

---

## Splunk / detection impact

Phase 6A: no new indexed names. No new SPL. No Studio.

DET-MCP-001 is **not sufficient** for preferred vulnerability 2. Do not create DET-MCP-005 in 6A. See `docs/MCP005_DETECTION_MODEL.md`.
