# RAG runtime evidence planes

**Status:** Phase 10D DESIGN / ANALYSIS. No detector. No new SPL.  
**Parents:** `docs/PHASE10C_RAG_SPLUNK_VALIDATION.md`, `docs/RAG_CONTEXT_SECURITY_MODEL.md`.

A SOC question that names only “RAG poisoning” or “was RAG poisoned?” is underspecified. AgentSec splits the same incident into four evidence planes.

LIVE specimens (Phase 10C, not re-ingested):  
A `51f70fb9-994e-4dd4-9b36-cac6fb1e8232` · B `3a43d24f-9281-42f6-8375-1fb2efaa80ac` · C `bea97bae-491b-4b36-b52f-1417d2bad01b`.

---

## The ten states (do not collapse)

| ID | State | Plane | Authoritative evidence | LIVE ATTACK B | LIVE RETEST C | LIVE BASELINE A |
|----|-------|-------|------------------------|---------------|---------------|-----------------|
| A | Content retrieved | 1 Retrieval | Exact document.id + frozen content; indexed `agentsec.rag.context.document.id` | `doc.lending-policy.malicious` | **same id** | `doc.lending-policy.normal` |
| B | Provenance recorded | 1 Retrieval | `agentsec.rag.context.provenance` | `rag.local.fixture` | **same** | **same** |
| C | Classified untrusted_data | 2 Trust / influence | CTRL-RAG-CONTEXT-001 OBSERVE `retrieved_context_is_data` + `agentsec.rag.context.trust` | OBSERVE / `untrusted_data` | **same OBSERVE** | **same OBSERVE** |
| D | Retrieved content influenced a follow-on REQUEST | 2 Trust / influence | Closed interpreter → hop-1 request fields (`gen_ai.tool.name`, `requested_scope`) | `lookup_customer_tier` / `customer:read` | **same REQUEST** | no follow-on |
| E | Follow-on DENIED | 3 Authorization | CTRL-MCP-001 DENY | no | DENY `tool_not_granted` | n/a |
| F | Follow-on ALLOWED | 3 Authorization | CTRL-MCP-001 ALLOW + reason | ALLOW overlay | no | n/a |
| G | Execution STARTED | 4 Execution | Runtime `ToolRegistry.invoke_counts`; Splunk `mcp.started` corroborates | handler **1**; `mcp.started` seq 7 | handler **0**; no start | handler **0** |
| H | Execution COMPLETED | 4 Execution | `mcp.completed` + handler success | `mcp.completed` | no | no |
| I | Execution FAILED | 4 Execution | `mcp.failed` + executed=true, outcome=error | not this specimen | n/a | n/a |
| J | Execution AFTER a DENY | 4 after 3 | DET-MCP-001 predicate | no DENY | DENY respected (no start) | no DENY |

**ATTACK and RETEST share planes 1 and 2.** The discriminator is **plane 3**, then **plane 4**.

Malicious retrieved content is **not** authorization bypass. Authorization bypass (lab overlay ALLOW) is **not** automatically successful execution (`mcp.started` ≠ success; handler exception after ALLOW is still execution).

---

## Plane 1 — Retrieval

**Question:** What document was retrieved, from where, with which fingerprint?

**Evidence:** `otel:agentic:json` on CONTEXT-001: `agentsec.rag.context.document.id`, `agentsec.content.hash`, `agentsec.rag.context.provenance`, `agentsec.run.id`, `agentsec.sequence`.

**Authoritative:** runtime frozen `RetrievedContext` + SHA-256 of **full** content. Indexed hash corroborates when the copy is COMPLETE.

**Not this plane:** ALLOW/DENY, `mcp.started`, “malicious,” “safe.”

**Honest meaning:** bytes crossed `rag.retrieved.context`. Provenance is source identity, not trust.

---

## Plane 2 — Trust / influence

**Question:** How was retrieved content classified, and did it influence a follow-on REQUEST?

**Evidence:** CTRL-RAG-CONTEXT-001 (`rag_context_trust`, OBSERVE `retrieved_context_is_data`, `untrusted_data`); hop-1 **request** fields before treating decision as the story. Influence kind `retrieved_context` on CONTEXT-001.

**Honest meaning:** classification and intent. OBSERVE is not ALLOW. A follow-on **request** is not a grant. `untrusted_data` is not “malicious.”

---

## Plane 3 — Authorization

**Question:** Was the follow-on request granted against server-owned policy?

**Evidence:** hop-1 CTRL-MCP-001 decision/reason; `agentsec.mcp.requested_scope` vs `agentsec.mcp.allowed_scope` (coded **scope**, not a tool list).

**Honest meaning:** coded policy (or the labeled per-run overlay) decided. Splunk does not enforce. Overlay reason `vulnerable_profile_fail_open:retrieved_context_derived_authority` is a **lab** fail-open, not a production notable.

**Not indexed:** `allowed_tools` grant snapshot.

---

## Plane 4 — Execution

**Question:** Did the handler begin, complete, or fail?

**Evidence:** runtime `ToolRegistry.invoke_counts` is **authoritative**. Indexed `mcp.started` / `completed` / `failed` corroborate on a COMPLETE copy. Missing `mcp.started` is **not** independent non-execution proof.

**Honest meaning:** `mcp.started` = execution began, not success. `mcp.failed` = execution then error, not prevention. ALLOW ≠ execution.

---

## Combinations a detector might claim

| Claim | Planes | Distinguishes ATTACK vs RETEST? | Ready to publish? |
|-------|--------|----------------------------------|-------------------|
| untrusted_data retrieved | 1+2 | No (A/B/C all OBSERVE) | No — CONTEXT |
| Instruction-like preview | 1 | No (B and C identical) | No — REJECT as detector |
| Known malicious hash | 1 | No | No — lab fixture CONTEXT |
| Retrieval + privileged REQUEST | 1+2 | No (B and C same request) | No — HUNT / CONTEXT |
| Retrieval + DENY | 1+3 | RETEST only | No — DENY is control success |
| Retrieval + ALLOW | 1+3 | ATTACK only in this lab | No — ALLOW may be a real grant; overlay string is lab-only |
| Retrieval + execution | 1+4 | ATTACK only in this lab | No — missing grant snapshot |
| Retrieval + privileged REQUEST + ALLOW | 2+3 | Yes in this lab | No — overlay REJECT |
| Retrieval + REQUEST + execution | 2+4 | Yes in this lab | **TELEMETRY GAP** for “unauthorized” (no `allowed_tools`) |
| DENY then `mcp.started` | 3+4 | Neither fires on A/B/C | Existing **DET-MCP-001** only |

---

## Correlation within a run

Keys that work: `agentsec.run.id` + `sequence` + `hop.index` + `control.id`. Document fingerprint is CONTEXT-001 `agentsec.content.hash`, not hop-1 request hash.

Do **not** invent `gen_ai.tool.call.id`, `session.id`, or `allowed_tools`.
