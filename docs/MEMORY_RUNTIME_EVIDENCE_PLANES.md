# Memory runtime evidence planes

**Status:** Phase 11D DESIGN / ANALYSIS. No detector. No new SPL.  
**Parents:** `docs/PHASE11C_MEMORY_SPLUNK_VALIDATION.md`, `docs/MEMORY_SECURITY_MODEL.md`.

A SOC question that names only “was malicious memory detected?” is underspecified. Persistent-memory security splits the same incident into **five** evidence planes. Write and recall are **different `run.id` values**.

LIVE specimens (Phase 11C, not re-ingested):

| Spec | Write `run.id` (writer) | Recall `run.id` (destination) |
|------|-------------------------|-------------------------------|
| A BASELINE | `a8407246-7992-4ad8-bd02-cb701e150f30` | `914c41ce-5123-49eb-892c-c948295dbc46` |
| B ATTACK | `05f1d8d0-28b7-40ac-bbb9-1dc64b4ba464` | `b8737cd9-9b6b-48f2-acfa-178ae1446ddc` |
| C RETEST | `060a0a72-ceb5-4b99-8330-98de81d8ae5e` | `5d5b9d1b-092d-4ddb-8422-4092d289cd49` |

Do **not** substitute Phase 11B local IDs.

---

## The eight states (do not collapse)

| ID | State | Plane | Class | Authoritative evidence | LIVE ATTACK B | LIVE RETEST C | LIVE BASELINE A |
|----|-------|-------|-------|------------------------|---------------|---------------|-----------------|
| A | Memory written | 1 Persistence | **CONTEXT** | `agentsec.memory.written`; writer `run.id`; `memory.id`; SHA-256; provenance | MALICIOUS write (defended store-only) | **same MALICIOUS SHA-256** | NORMAL write |
| B | Memory later recalled | 2 Recall / trust | **CONTEXT** | `agentsec.memory.recalled`; destination `run.id`; `source_run_id` = writer | recall B | recall C | recall A |
| C | Recalled content classified as data | 2 Recall / trust | **CONTROL EVIDENCE** | CTRL-MEMORY-CONTEXT-001 OBSERVE `memory_context_is_data` + `untrusted_data` | OBSERVE | **same OBSERVE** | **same OBSERVE** |
| D | Recall influenced a follow-on REQUEST | 3 Influence / request | **HUNT** (also CONTEXT) | hop-1 `gen_ai.tool.name` / `requested_scope` | `lookup_customer_tier` / `customer:read` | **same REQUEST** | no follow-on |
| E | Follow-on DENIED | 4 Authorization | **CONTROL EVIDENCE** | hop-1 CTRL-MCP-001 DENY | no | DENY `tool_not_granted` | n/a |
| F | Follow-on ALLOWED | 4 Authorization | **CONTROL EVIDENCE** | hop-1 CTRL-MCP-001 ALLOW + reason | ALLOW overlay | no | n/a |
| G | Execution STARTED | 5 Execution | **EXECUTION EVIDENCE** | Runtime `ToolRegistry.invoke_counts`; Splunk `mcp.started` corroborates | handler **1**; `mcp.started` seq 8 | handler **0**; no start on COMPLETE copy | handler **0** |
| H | Execution COMPLETED or FAILED | 5 Execution | **EXECUTION EVIDENCE** | `mcp.completed` / `mcp.failed` + handler outcome | `mcp.completed` (no `mcp.failed`) | no mcp.* | no mcp.* |

**DETECTION** (existing): execution **after** DENY for the same recall `run.id` + tool — **DET-MCP-001**. None of A–H alone is that predicate. LIVE A/B/C: **0 rows** (correct).

**ATTACK and RETEST share planes 1–3** (same malicious fingerprint, same OBSERVE, same REQUEST). The discriminator is **plane 4**, then **plane 5**.

Malicious stored bytes are **not** authorization bypass. Overlay ALLOW is **not** automatically successful execution (`mcp.started` ≠ success). Missing Splunk start ≠ independent prevention (handler count is authoritative).

Do **not** collapse A–H into one “memory poisoning detected” event.

---

## Plane 1 — Persistence

**Question:** What was written, by which run/agent, with which fingerprint and provenance?

**Evidence:** `otel:agentic:json` `event.name=agentsec.memory.written`: `agentsec.memory.id`, `agentsec.content.hash`, `agentsec.memory.provenance`, `agentsec.memory.source_run_id` (equals writer `run.id`), `gen_ai.agent.id`, bounded preview.

**Authoritative:** runtime fixture bytes + SHA-256 of **full** content. Indexed hash corroborates when the copy is COMPLETE.

**Not this plane:** trust classification (empty on write in LIVE 11C), ALLOW/DENY, `mcp.started`, “malicious,” “safe.”

**Honest meaning:** bytes crossed `agent.memory.store`. Provenance is source identity, not trust. Stored ≠ trusted.

---

## Plane 2 — Recall / trust

**Question:** Which later run recalled it, did the fingerprint survive, and how was it classified?

**Evidence:** `agentsec.memory.recalled` + CTRL-MEMORY-CONTEXT-001 (`memory_context_trust`, OBSERVE `memory_context_is_data`, `untrusted_data`). `source_run_id` on recall points at the writer. Influence kind `recalled_memory`.

**Honest meaning:** classification. OBSERVE is not ALLOW. `untrusted_data` is not “malicious.” Recalled ≠ attack.

---

## Plane 3 — Influence / request

**Question:** Did recall lead to a privileged follow-on **request** (tool / scope / resource)?

**Evidence:** hop-1 request fields on the **recall** run: `gen_ai.tool.name`, `agentsec.mcp.requested_scope`. Resource id is **NOT APPLICABLE** on these specimens (no resource lab).

**Honest meaning:** intent. REQUEST ≠ GRANT. BASELINE has no follow-on; that is an observation, not proof of safety.

---

## Plane 4 — Authorization

**Question:** Was the follow-on request granted against server-owned policy?

**Evidence:** hop-1 CTRL-MCP-001 decision/reason; requested vs coded allowed **scope** (`policy:read`, not a tool list).

**Honest meaning:** coded policy (or the labeled per-recall-run overlay) decided. Splunk does not enforce. Overlay reason `vulnerable_profile_fail_open:memory_derived_authority` is a **lab** fail-open, not a production notable.

**Not indexed:** `allowed_tools` grant snapshot.

---

## Plane 5 — Execution

**Question:** Did the handler begin, complete, or fail?

**Evidence:** runtime `ToolRegistry.invoke_counts` is **authoritative**. Indexed `mcp.started` / `completed` / `failed` corroborate on a COMPLETE copy. Missing `mcp.started` is **not** independent non-execution proof.

**Honest meaning:** `mcp.started` = execution began, not success. `mcp.failed` = execution then error, not prevention. ALLOW ≠ execution.

---

## Combinations a detector might claim

| Claim | Planes | Distinguishes ATTACK vs RETEST? | Ready to publish? |
|-------|--------|----------------------------------|-------------------|
| Memory write | 1 | No (all write) | No — CONTEXT |
| Memory recall | 2 | No | No — CONTEXT |
| untrusted_data recall | 2 | No (A/B/C all OBSERVE) | No — CONTEXT |
| Recall + privileged REQUEST | 2+3 | No (B and C same request) | No — HUNT / CONTEXT |
| Recall + DENY | 2+4 | RETEST only | No — DENY is control success |
| Recall + ALLOW | 2+4 | ATTACK only in this lab | No — overlay / legitimate grants |
| Recall + execution | 2+5 | ATTACK only in this lab | No — missing grant snapshot |
| Write → later recall → REQUEST → execution | 1–5 | Yes in this lab | No — overlay REJECT; hunt already exists |
| DENY then `mcp.started` | 4+5 | Neither fires on A/B/C | Existing **DET-MCP-001** only |

---

## Correlation (cross-run)

Keys that work in this lab: writer `run.id` + destination `run.id` + `memory.id` + SHA-256 + recall `source_run_id` + `gen_ai.agent.id` + `sequence`. `memory.id` is fixture identity shared by ATTACK and RETEST — **not** a unique specimen key.

Do **not** invent `session.id`, `invocation.id`, or `allowed_tools`.
