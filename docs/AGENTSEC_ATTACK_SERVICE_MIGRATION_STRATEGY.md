# Attack Service migration strategy

**Status:** DESIGN (Phase 15A). **Do not add launchers from this file.**  
Locked: `ExperimentContext` / `ExperimentDefinition`; browser may send only `{lab_id, specimen_id, mode, execution}`; extra fields rejected; `known_lab_ids()` today = `{LAB-PI-001, LAB-MCP-001}`.

LIVE is not inherently better than REPLAY. LIVE is justified when a fresh `run.id`, equivalent RETEST, and server-owned profile difference teach more than a canonical pack.

---

## Decision questions (every candidate)

1. Can the attack be a server-owned `ExperimentDefinition`?  
2. Can ATTACK and RETEST use **equivalent adversarial input** (byte fingerprint)?  
3. Can profile/control difference stay server-owned?  
4. Can browser authority fields remain rejected?  
5. Can a fresh `run.id` be returned?  
6. Can execution stay isolated to AgentSec lab processes?  
7. Would LIVE actually improve learning vs REPLAY?

If any of 1–6 fail, prefer REPLAY or DESIGN EXERCISE.

---

## Per-lab feasibility

### LAB-PI-001 — already LIVE

Yes to all. Loan `POST /process`. RETEST = same ATK-002, secure profile. **No further launcher work.**

### LAB-MCP-001 — already LIVE

Yes to all. `POST /mcp/invoke`. RETEST = same `lookup_customer_tier` request, `mcp_authz_enforced`. **No further launcher work.**

### LAB-MCP-003 — small

| Question | Answer |
|----------|--------|
| ExperimentDefinition? | YES — same invoke, different `requested_scope` specimens |
| Equivalent RETEST? | YES — same excessive-scope bytes, enforced profile |
| Server-owned profile? | YES — reuse mcp vulnerable vs enforced |
| Reject browser grants? | YES — existing allowlist |
| Fresh run.id? | YES |
| Isolated? | YES — in-process MCP |
| LIVE improves learning? | YES — scope DENY/ERROR is more convincing as a run the learner launched |

**Work:** small (new definitions + `/labs/LAB-MCP-003` page + manifest). No new PDP.

### LAB-MCP-004 — small

Same as 003 with resource/parameter specimens. **Q-MCP-RESOURCE-AUTHZ** already exists. LIVE improves “syntactically valid ≠ authorized arguments.”

### LAB-MCP-005 — moderate

Two-hop: authorized first invoke, then result-influenced follow-on. Definitions must freeze **both** hops and the malicious result bytes for RETEST equivalence. Do not let the browser supply result text. If the launcher cannot freeze the result payload, **REPLAY**.

### LAB-MCP-CATALOG — moderate

Must freeze catalog fixture + first authorized tool + follow-on request. Metadata OBSERVE must not be exposable as a grant toggle. LIVE helps if the learner sees the same description bytes on ATTACK and RETEST. Otherwise REPLAY is honest.

### LAB-SCANNER-RUNTIME-EVIDENCE — no launcher

Scanner CLI + imported JSON. Not an Attack Service experiment. LIVE Attack Service would **mis-teach** “launch the scanner to authorize the tool.” **REPLAY / DESIGN EXERCISE only.**

### LAB-RAG-CONTEXT — moderate

`POST /rag/retrieve` exists. Follow-on MCP must be server-owned. Freeze retrieved document id and bytes. LIVE helps REQUEST≠GRANT after retrieval. If retrieve and invoke cannot stay one closed definition (or a linked pair), REPLAY.

### LAB-MEMORY-001 — moderate / architectural-lite

Requires **write run** then **recall run**. Attack Service is currently one definition → one `run.id`. Options (15B+ design, not 15A): (a) two sequential launches bound by a server-owned `memory_key`; (b) REPLAY of a canonical pair. LIVE improves INV-003 only if the learner sees persistence across runs they launched. Do not fake a single-run “memory attack.”

### LAB-MCP-006 — moderate

Two-agent in-process pipeline. Freeze caller, deputy, requested tool. RETEST = same confused-deputy request, enforced delegation+MCP. LIVE useful. Browser must not name deputy grants.

### LAB-AGENT-DELEGATION-001 — architectural

No Studio yet. Identity claims must remain untrusted. No A2A transport. LIVE only as in-process `POST /identity/delegate` definitions. Until a workshop exists, **REPLAY + DESIGN EXERCISE**. Building a launcher without a lesson is the wrong order.

### LAB-AGENT-GOAL-INTEGRITY-001 — moderate

`POST /goal/evaluate` exists. Freeze task + tool. RETEST = same GOAL-001 expansion, enforced goal control. MCP remains sole tool PDP. LIVE useful for “same tool, different task outcome.”

---

## Recommended implementation sequence for launchers (not 15A)

1. MCP-003, MCP-004 (small, same route)  
2. MCP-005 **or** catalog (INV-002; pick one hop story first)  
3. RAG  
4. Memory (linked runs)  
5. MCP-006  
6. Goal  
7. Identity (after Studio)  
8. Never: scanner as Attack Service LIVE  

PI-001 and MCP-001 stay the compatibility canaries. New definitions must not change their frozen payloads or profiles.
