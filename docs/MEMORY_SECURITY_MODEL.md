# Agent memory security model

**Status:** Phase 11A **DESIGN**. Runtime **ABSENT**. Schema **1.6.0 unchanged**.  
**Primary invariant:** INV-003.  
**Evidence class:** **DOCUMENTED**.

Parents: `docs/MEMORY_PREDECESSOR_ANALYSIS.md`, `docs/RAG_CONTEXT_SECURITY_MODEL.md`.

---

## WHAT IS IT?

**Agent memory security** asks whether bytes that an agent **stored** and later **recalled** may change what the agent is allowed to do.

The write can be **valid**. The recall can be **the right record**. Successful persistence is not permission. Successful recall is not a grant.

## WHY DOES IT EXIST?

Agents persist state so later runs are useful: preferences, summaries, “remember that.” That store is **attacker-reachable** whenever a prior turn, tool result, retrieved document, or peer can cause a write. Industry names the persistence cut **memory poisoning** (OWASP ASI06 memory path). Unlike RAG, the poison **survives** the original session.

Authorization is still a server-owned grant. A memory store is a **source of data**, not a source of authority.

## HOW DOES IT WORK? (planned)

```
RUN 1  (WRITE)
  User / lab fixture
        |
        v
  Memory write  (DATA lands in store)
        |
        v
  Persistent memory store

RUN 2  (RECALL)  — different run.id
  Memory recall  (DATA)
        |
        v
  Observation  (CTRL-MEMORY-CONTEXT-001)
        |
        v
  Agent may form REQUEST
        |
        v
  CTRL-MCP-001  (server-owned authorization)
        |
     +--+--+
     |     |
   ALLOW  DENY
     |     |
  execute  X
```

**MEMORY IS PERSISTED DATA.**  
**PERSISTENCE != TRUST.**  
**PROVENANCE != AUTHORITY.**  
**RECALL != GRANT.**  
**MEMORY-DERIVED REQUEST != AUTHORIZATION.**

## WHERE DOES IT SIT IN AGENTSEC?

After RAG 10A–10E. Parallel to RAG, **not** a second RAG lab.

| Lab | Untrusted object | Observation | Authz |
|-----|------------------|-------------|-------|
| LAB-MCP-005 | Tool result | CTRL-MCP-RESULT-001 | CTRL-MCP-001 |
| LAB-RAG-001 | Retrieved document | CTRL-RAG-CONTEXT-001 | CTRL-MCP-001 |
| **LAB-MEMORY-001** | Recalled memory | **CTRL-MEMORY-CONTEXT-001** | **CTRL-MCP-001** |

## WHAT IS THE TRUST BOUNDARY?

Proposed: `agent.memory.store`.

Three distinct facts:

| Fact | Example | Grants tools? |
|------|---------|---------------|
| **Memory provenance** | `agentsec.memory.fixture` | No |
| **Content trust** | `untrusted_data` | No |
| **Authorization** | CTRL-MCP-001 / coded `allowed_tools` | Yes — server-owned |

Stored successfully ≠ trusted instruction. Do **not** invent `trusted_memory=true` because the record is in our store.

## WHAT COULD AN ATTACKER CONTROL?

In the lab: the **memory body** written in run 1 (MALICIOUS fixture).

The attacker must **not** control: coded grants, profile (except the labeled vulnerable overlay on recall), `run.id`, identity, approval, Splunk.

## WHAT CAN GO WRONG?

- Treating `MemorySink` as agent memory
- Reusing CTRL-RAG-CONTEXT-001 for recalls
- Collapsing write and recall into one `run.id`
- Treating persistence as trust promotion
- Letting memory JSON contain `allowed_tools`
- Global grant mutation
- LLM as the invariant
- Splunk as authorization
- Turning 11A into A2A / multi-tenant isolation theater

## SECURITY PROPERTY (validated against invariants)

**Persisted memory may influence reasoning or create a REQUEST, but cannot independently mint or widen tools, scopes, resources, identity, delegation, approvals, or authorization configuration.**

| Clause | Invariant |
|--------|-----------|
| Untrusted memory must not become trusted instruction | **INV-003** (verbatim purpose) |
| Recalled data cannot independently authorize | **INV-002** |
| Overlay ALLOW is labeled, not silent fail-open | **INV-008** |
| Write/recall/request/authz/execute reconstructable | **INV-007** |

This wording **does not replace** INV-003. It is the composition used by the lab.

## WHAT TELEMETRY SHOULD EXIST? (concepts — not indexed fields yet)

Write: memory id, hash, preview, provenance, writer agent, **source run**.  
Recall: same id/hash, **destination run**, OBSERVE, optional follow-on authz/execution.

Full memory bodies, PII, secrets, and conversation dumps are **not** default evidence.

## HOW WILL SPLUNK SHOW IT?

After 11C field discovery. Questions first (`docs/MEMORY_EVENT_MODEL_REVIEW.md`). No SPL in 11A. CIM **NOT APPLICABLE** until events exist. Prefer reuse of Q-MCP-* for the follow-on hop.

## WHAT CONTROL COULD CHANGE THE RESULT?

Defended CTRL-MCP-001 **DENY** `tool_not_granted` on the RECALL run. The malicious memory **stays the same**.

## WHAT TEST WOULD PROVE THE LOGIC? (later 11B)

Same malicious hash on ATTACK recall and RETEST recall. ATTACK handler 1. RETEST handler 0. Overlay reason not a production IOC.

---

## Security review (design)

| Risk | Lab rule |
|------|----------|
| Client-supplied trust labels | Forbidden. Trust is server-owned `untrusted_data`. |
| Memory-supplied `allowed_tools` / scopes / identity / approval | Forbidden in fixtures and parser. |
| Global policy mutation | Overlay is per-recall-run only. |
| Cross-user / cross-tenant leakage | Out of lab; identity chapter. |
| Full-memory / secret logging | Preview + hash only. |
| DENY-after-execute | Forbidden. Check before handler. |
| Silent fail-open | Only labeled `vulnerable_profile_fail_open:memory_derived_authority`. |
| LLM-as-security-invariant | Closed interpreter + CTRL-MCP-001. |
| Splunk-as-authorization | Evidence only. |
| ML-as-authorization | Forbidden. |
