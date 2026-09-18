# LAB-MEMORY-001 runtime contract

**Status:** Phase 11B **IMPLEMENTED + LOCALLY VALIDATED**. Not Splunk-validated. Not a workshop. Not a detector.  
**Schema:** `agentsec.security_event` **1.7.0** (additive over 1.6.0).  
**Controls:** CTRL-MEMORY-CONTEXT-001 (OBSERVE) + CTRL-MCP-001 (reuse; follow-on).  
**Evidence class:** pytest and local bundles are **MEASURED** / **OBSERVED**. Splunk: **NOT ATTEMPTED**.

Parents: `docs/MEMORY_LAB_SPECIFICATION.md`, `docs/SCHEMA_1_7_0.md`.

## WHAT IS IT?

A deterministic local fixture store persists one preference record. A later run recalls the **same bytes**. CTRL-MEMORY-CONTEXT-001 classifies those bytes as **data**. A closed interpreter may emit a follow-on **REQUEST** for `lookup_customer_tier`. CTRL-MCP-001 still authorizes that request against **server-owned** grants. Memory cannot mint an AllowTicket.

## WHY DOES IT EXIST?

RAG proved retrieved context cannot grant authority **inside one run**. This lab proves persisted memory cannot grant authority **across two `run.id` values** (INV-003). Successful write is not trust. Successful recall is not a grant.

## HOW DOES IT WORK?

```text
POST /memory/write  {memory_id}
        │
        ▼
WRITE RUN  (distinct run.id)
        │
        ▼
InProcessMemoryStore.write_fixture
        │
        ▼
agentsec.memory.written
        │
        ▼
POST /memory/recall  {memory_id}
        │
        ▼
RECALL RUN  (different run.id)
        │
        ▼
immutable MemoryRecord snapshot
        │
        ▼
CTRL-MEMORY-CONTEXT-001
        OBSERVE memory_context_is_data   (every valid recall, every profile)
        ERROR  unknown / malformed / recall failure
        │
        ▼
closed interpreter (exact AGENT MEMORY NOTE substring on FULL content)
        │
        ▼  (ATTACK / vulnerable + marker only)
per-recall-run MemoryDerivedOverlay
        │
        ▼  (if marker recognized)
hop 1  CTRL-MCP-001 lookup_customer_tier / customer:read
        overlay → ALLOW memory_derived_authority → handler 1
        no overlay → DENY tool_not_granted → handler 0, no mcp.started
```

CTRL-MEMORY-CONTEXT-001 does **not** DENY a tool, ALLOW a tool, sanitize, quarantine, or mint AllowTicket. OBSERVE means data crossed `agent.memory.store`. It does not mean the memory is safe. OBSERVE is not ALLOW.

## WHERE DOES IT SIT?

`POST /memory/write` and `POST /memory/recall` → `src/agentsec/memory/pipeline.py`. Store: `src/agentsec/memory/store.py`. Control: `src/agentsec/memory/trust.py`. Workflow `memory_lab`. Agent `acme-agent-memory-001`. Not `/process`. Not `/mcp/invoke`. Not `/rag/retrieve`.

## TRUST BOUNDARY

`agent.memory.store` (MEMORY-CONTEXT-001) then `acmebank.mcp.authorize` (CTRL-MCP-001). Provenance `agentsec.memory.fixture` is not trust. Trust `untrusted_data` is not authorization.

## AUTHORITY

| Authoritative | Non-authoritative |
|---------------|-------------------|
| coded identity | persisted memory bytes |
| server-owned tool/scope/resource grants | AGENT MEMORY NOTE text |
| AllowTicket | HTTP extras |
| explicit per-recall-run overlay in ATTACK only | provenance, preview, hash, write success |

`coded_policy()` remains `{lookup_policy}` / `{policy:read}` / `{lending-basics}`. The overlay never rewrites `ALLOWED_TOOLS`.

## ERROR MODEL

| Condition | Decision | Follow-on |
|-----------|----------|-----------|
| unknown memory id | ERROR `unknown_memory_id` | none |
| empty memory id | ERROR `empty_memory_id` | none |
| duplicate memory id | ERROR `duplicate_memory_id` | none |
| grant-like fields on write | ERROR `malformed_memory_write` / HTTP `unknown_fields` | none |
| invalid content type | ERROR `invalid_content_type` | none |
| invalid provenance | ERROR `invalid_provenance` | none |
| oversized fixture | ERROR `oversized_memory` | none |
| control evaluation exception | ERROR fail-closed | none |
| recall failure | ERROR | none |
| handler failure after ALLOW | mcp.failed; executed=true; outcome=error | handler counted |

Unknown/malformed memory is **ERROR**, not authorization **DENY**. ERROR does not fail open.

## CHECK / USE

Recall returns a frozen `MemoryRecord`. The interpreter and the follow-on request use that snapshot. The runtime does not re-read mutable store content after classification.

## FAILURE ORDER (actual)

1. HTTP / request validation  
2. write_fixture / recall exact membership  
3. CTRL-MEMORY-CONTEXT-001 (recall only)  
4. closed interpreter (full content)  
5. CTRL-MCP-001  
6. handler (only after ALLOW)

Write never forms a follow-on request.
