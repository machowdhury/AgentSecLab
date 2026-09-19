# Phase 10B — LAB-RAG-001 runtime + local security validation

**Status:** **IMPLEMENTED + LOCALLY VALIDATED**  
**Date:** 2026-09-16  
**Schema:** `agentsec.security_event` **1.6.0**  
**Splunk:** `splunk.verified=false`. No SPL created or modified. DET-MCP-001 unchanged. DET-RAG not created. No Dashboard Studio.  
**Evidence class:** pytest **MEASURED**. Local A/B/C packs **OBSERVED**. Splunk **NOT ATTEMPTED**. Phase 10C **NOT STARTED**.

Parents: `docs/RAG_RUNTIME_CONTRACT.md`, `docs/SCHEMA_1_6_0.md`.

---

## Canonical local runs (this session, OBSERVED)

| Id | run.id | Profile | Mode | Document | CONTEXT-001 | Follow-on CTRL-MCP-001 | lookup_customer_tier | Terminal |
|----|--------|---------|------|----------|-------------|------------------------|----------------------|----------|
| **A** | `ec141d70-e664-40a4-b37a-2c9d1cd625ca` | defended | BASELINE | `doc.lending-policy.normal` | OBSERVE `retrieved_context_is_data` | none | 0 | `completed_allowed` |
| **B** | `dc3173b8-102c-4d4e-aad4-91c101e9cb76` | vulnerable | ATTACK | `doc.lending-policy.malicious` | OBSERVE `retrieved_context_is_data` | ALLOW `vulnerable_profile_fail_open:retrieved_context_derived_authority` | 1 | `completed_allowed` |
| **C** | `10d042c6-986e-4bf3-b102-6cf26a7e5fcf` | defended | RETEST | **same MALICIOUS as B** | OBSERVE `retrieved_context_is_data` | DENY `tool_not_granted` | 0 | `completed_denied` |

Packs: `artifacts/<run-id>/`. Each `export.json` / `manifest.json` has `splunk.verified=false`. Schema version **1.6.0**. Provenance `rag.local.fixture`. Trust `untrusted_data`.

### Content fingerprints (MEASURED)

| Document | SHA-256 |
|----------|---------|
| NORMAL (`doc.lending-policy.normal`) | `sha256:0fc83ee727c6f33ad87e6ffec8698889de366311a281e4f831fe8c8d30e27f8e` |
| MALICIOUS (`doc.lending-policy.malicious`) | `sha256:c565f364c7c5fba3cf25d235bb8e2bee7d9433daa9f07d5e097ab6d2a82a97ef` |

B document id == C document id. B hash == C hash. B follow-on REQUEST == C follow-on REQUEST (`lookup_customer_tier` / `customer:read`).

NORMAL is not labeled SAFE, TRUSTED, or APPROVED.

Server-owned `allowed_tools={lookup_policy}` before and after B (**MEASURED**).

---

## Sequence (OBSERVED)

**A (5 events):** run.started → hop.started → CTRL-RAG-CONTEXT-001 OBSERVE → hop.completed → run.completed. No follow-on hop. No `mcp.started`.

**B (10 events):** run.started → hop.started → CTRL-RAG-CONTEXT-001 OBSERVE → hop.completed → hop.started → CTRL-MCP-001 ALLOW `lookup_customer_tier` → mcp.started → mcp.completed → hop.completed → run.completed.

**C (9 events):** run.started → hop.started → CTRL-RAG-CONTEXT-001 OBSERVE → hop.completed → hop.started → CTRL-MCP-001 DENY `lookup_customer_tier` → pipeline.stopped → hop.completed → run.completed. **No** follow-on `mcp.started`.

Teaching:

- retrieval ≠ authorization
- OBSERVE ≠ ALLOW
- request ≠ grant
- ALLOW ≠ execution (handler exception after ALLOW still emits mcp.started + mcp.failed, executed=true, outcome=error)
- mcp.started ≠ success
- mcp.failed ≠ prevention
- missing mcp.started is corroboration only; `ToolRegistry.invoke_counts["lookup_customer_tier"]` is authoritative

---

## 10A semantic resolution (implemented)

CTRL-RAG-CONTEXT-001 remains **OBSERVE** `retrieved_context_is_data` for valid documents in BASELINE, ATTACK, and RETEST. Vulnerable ALLOW is the **per-run** `ContextDerivedOverlay` consulted by CTRL-MCP-001. The retrieved document is never authorized.

---

## Pytest (this session, MEASURED)

```
550 passed, 2 deselected
```

Deselected: `live_ollama`, `live_splunk` markers. Prior 10A baseline was 514 passed, 2 deselected.

MCP-001 / MCP-003 / MCP-004 / MCP-005 / MCP-006 / MCP-CATALOG / scanner evidence tests in that run passed. DET-MCP-001, existing Q-MCP SPL, Q-SCANNER SPL, and Studio definitions were not modified.

---

## Security regressions proven (MEASURED)

1. Retrieved content never mutates `coded_policy()` (tools, scopes, resources, identity).
2. CTRL-RAG-CONTEXT-001 cannot mint an AllowTicket (returns OBSERVE/ERROR only).
3. Provenance `rag.local.fixture` is not trust. Trust `untrusted_data` is not authorization.
4. ATTACK overlay is per-run only; concurrent defended RETEST handler count stays 0.
5. RETEST follow-on handler count is 0 (`ToolRegistry.invoke_counts`).
6. Unknown document is ERROR `unknown_document`, not DENY, not fallback.
7. Exact opaque ids: leading space and case-fold are unknown, not another document.
8. HTTP extras (`allowed_tools`, `trusted_document`, `security.profile`, `context.trust`) are `unknown_fields`.
9. Grant-like keys on a retrieval object are malformed, not ATTACK evidence.
10. Interpreter consumes FULL content; preview truncation cannot hide the closed marker.
11. `RetrievedContext` is frozen (check/use: hash and interpret the same snapshot).
12. Retrieval / context-control / follow-on authorization exceptions fail-safe (handler 0).
13. Handler exception after overlay ALLOW: mcp.started + mcp.failed, executed=true, outcome=error — not prevention.
14. Full documents are not default-indexed (preview ≤200 + sha256).
15. No SAFE/TRUSTED/APPROVED labels on NORMAL content.

---

## Telemetry / future KO quality (review only)

Field names follow catalog: `agentsec.rag.context.trust`, `agentsec.rag.context.provenance`, `agentsec.rag.context.document.id`. Reuse `agentsec.content.hash` / `agentsec.content.preview`. Workflow `rag_context_lab` / `/rag/retrieve`. Attack id `RAG-001`. Control type `rag_context_trust`.

No SPL written. No hunt rewritten. Live field discovery belongs to Phase 10C.

---

## Limitations

- Deterministic local fixtures. No embeddings, no LangChain, no live knowledge base.
- Interpreter recognizes one synthetic `AGENT NOTE` substring. Not an LLM.
- Vulnerable overlay is labeled lab fail-open. Not production policy.
- Locked MALICIOUS fixture is shorter than 200 characters, so the default preview contains the marker. Interpreter still uses FULL content; a padded-body test proves preview is not the input.
- Schema 1.6.0 has no `gen_ai.tool.call.id`.
- Splunk not indexed. No Q-RAG. No Dashboard Studio. No DET-RAG.
- ATLAS mapping remains UNMAPPED / REQUIRES REVALIDATION (10A).
- No memory poisoning, A2A, rug-pull, garak, Promptfoo, PyRIT, or NeMo.

---

## Verdict

**PASS — IMPLEMENTED + LOCALLY VALIDATED**

STOP. Phase 10C not started.
