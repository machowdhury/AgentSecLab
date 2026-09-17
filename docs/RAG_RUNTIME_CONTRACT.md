# LAB-RAG-001 runtime contract

**Status:** Phase 10B **IMPLEMENTED + LOCALLY VALIDATED**. Not Splunk-validated. Not a workshop. Not a detector.  
**Schema:** `agentsec.security_event` **1.6.0** (additive over 1.5.0).  
**Controls:** CTRL-RAG-CONTEXT-001 (OBSERVE) + CTRL-MCP-001 (reuse; follow-on).  
**Evidence class:** pytest and local bundles are **MEASURED** / **OBSERVED**. Splunk: **NOT ATTEMPTED**.

Parents: `docs/RAG_LAB_SPECIFICATION.md`, `docs/SCHEMA_1_6_0.md`.

## WHAT IS IT?

A deterministic local fixture retriever returns one policy document. CTRL-RAG-CONTEXT-001 classifies those bytes as **data**. A closed interpreter may emit a follow-on **REQUEST** for `lookup_customer_tier`. CTRL-MCP-001 still authorizes that request against **server-owned** grants. Retrieved context cannot mint an AllowTicket.

## WHY DOES IT EXIST?

MCP-005 proved **tool result** data cannot grant authority. Catalog proved **metadata** cannot. This lab is the **retrieved-context** sibling (INV-002). Valid retrieval is not permission.

## HOW DOES IT WORK?

```text
POST /rag/retrieve  {document_id}
        │
        ▼
request validation (unknown fields ERROR)
        │
        ▼
exact-id retrieve  (no embeddings, no case-fold, no fallback)
        │
        ▼
validate RetrievedContext (frozen snapshot)
        │
        ▼
SHA-256 fingerprint of FULL content
        │
        ▼
CTRL-RAG-CONTEXT-001
        OBSERVE retrieved_context_is_data   (every valid doc, every profile)
        ERROR  unknown / malformed / retrieval failure
        │
        ▼
closed interpreter (exact AGENT NOTE substring on FULL content)
        │
        ▼  (ATTACK / vulnerable + marker only)
per-run ContextDerivedOverlay
        │
        ▼  (if marker recognized)
hop 1  CTRL-MCP-001 lookup_customer_tier / customer:read
        overlay → ALLOW retrieved_context_derived_authority → handler 1
        no overlay → DENY tool_not_granted → handler 0, no mcp.started
```

CTRL-RAG-CONTEXT-001 does **not** DENY a tool, ALLOW a tool, sanitize, quarantine, or mint AllowTicket. OBSERVE means data crossed `rag.retrieved.context`. It does not mean the document is safe. OBSERVE is not ALLOW.

## 10A semantic resolution

10A ATTACK table listed CTRL-RAG-CONTEXT-001 ALLOW. **10B implements OBSERVE on all profiles for valid documents**, matching catalog METADATA-001. The one deliberate failure is the **per-run overlay consulted by CTRL-MCP-001**, reason `vulnerable_profile_fail_open:retrieved_context_derived_authority`. The retrieved document is never “authorized.”

## WHERE DOES IT SIT?

`POST /rag/retrieve` → `run_rag_retrieve` in `src/agentsec/rag/pipeline.py`. Retriever: `src/agentsec/rag/retriever.py`. Control: `src/agentsec/rag/context_trust.py`. Workflow `rag_context_lab` / `/rag/retrieve`. Agent `acme-agent-rag-001`. Not `/process`. Not `/mcp/invoke`.

## TRUST BOUNDARY

`rag.retrieved.context` (RAG-CONTEXT-001) then `acmebank.mcp.authorize` (CTRL-MCP-001). Provenance `rag.local.fixture` is not trust. Trust `untrusted_data` is not authorization.

## AUTHORITY

| Authoritative | Non-authoritative |
|---------------|-------------------|
| coded identity | retrieved documents |
| server-owned tool/scope/resource grants | AGENT NOTE text |
| AllowTicket | HTTP extras, LLM output |
| explicit per-run overlay in ATTACK only | provenance, preview, hash |

`coded_policy()` remains `{lookup_policy}` / `{policy:read}` / `{lending-basics}`. The overlay never rewrites `ALLOWED_TOOLS`.

## FAILURE ORDER (actual)

1. HTTP / request validation  
2. retrieve(`document_id`) exact membership  
3. `validate_retrieved_context`  
4. fingerprint FULL content  
5. CTRL-RAG-CONTEXT-001 OBSERVE or ERROR  
6. closed interpretation of the **same** frozen `.content`  
7. follow-on request formation (interpreter only)  
8. CTRL-MCP-001  
9. AllowTicket  
10. handler begins (`ToolRegistry.call_handler` increments first)

No follow-on handler before downstream ALLOW.

## NON-GOALS

SPL, DET-RAG, Dashboard Studio, Phase 10C, embeddings, LangChain, garak, Promptfoo, PyRIT, NeMo, memory poisoning, A2A, rug-pull.
