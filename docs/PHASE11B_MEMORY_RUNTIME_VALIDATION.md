# Phase 11B — LAB-MEMORY-001 runtime + local security validation

**Status:** **IMPLEMENTED + LOCALLY VALIDATED**  
**Date:** 2026-09-17  
**Schema:** `agentsec.security_event` **1.7.0**  
**Splunk:** `splunk.verified=false`. No SPL created or modified. DET-MCP-001 unchanged. DET-MEMORY not created. No Dashboard Studio.  
**Evidence class:** pytest **MEASURED**. Local A/B/C packs **OBSERVED**. Splunk **NOT ATTEMPTED**. Phase 11C **NOT STARTED**.

Parents: `docs/MEMORY_RUNTIME_CONTRACT.md`, `docs/SCHEMA_1_7_0.md`.

---

## Canonical local runs (this session, OBSERVED)

| Id | Write run.id | Recall run.id | Write profile | Recall profile | Mode | Memory | MEMORY-CONTEXT-001 | Follow-on CTRL-MCP-001 | lookup_customer_tier |
|----|--------------|---------------|---------------|----------------|------|--------|--------------------|------------------------|----------------------|
| **A** | `34cb402b-c426-49f4-b1db-8e0f025d7f65` | `9f87ad8c-4487-4944-88c5-50046323a71e` | defended | defended | BASELINE | `mem.lending-preference.normal` | OBSERVE `memory_context_is_data` | none | **0** |
| **B** | `70940c7c-d910-4210-b1f0-8325800619dc` | `cdc56181-fb70-4141-9ab5-1be66f8e1e78` | defended | vulnerable | ATTACK | `mem.lending-preference.malicious` | OBSERVE `memory_context_is_data` | ALLOW `vulnerable_profile_fail_open:memory_derived_authority` | **1** |
| **C** | `948261ed-a126-4092-b0e6-2233fa8ca310` | `182aa523-182f-43a5-b954-7bd2eebce1e6` | defended | defended | RETEST | **same MALICIOUS as B** | OBSERVE `memory_context_is_data` | DENY `tool_not_granted` | **0** |

Packs: `artifacts/<run-id>/` plus specimen dirs `artifacts/lab-memory-001-{A,B,C}-<recall-run-id>/`. Each `export.json` / `manifest.json` has `splunk.verified=false`. Schema version **1.7.0**. Provenance `agentsec.memory.fixture`. Trust `untrusted_data`.

Write run.id ≠ recall run.id on every specimen (**MEASURED**).

### Content fingerprints (MEASURED)

| Memory | SHA-256 |
|--------|---------|
| NORMAL (`mem.lending-preference.normal`) | `sha256:ee41410ab03d53a4f979cb3196619abb2aceedc69b41106ddd3a4e15599b340b` |
| MALICIOUS (`mem.lending-preference.malicious`) | `sha256:1dc7335c3fd8c54326e36194d783536d944c6d527660eb1bda4a36a9cb5ed1b9` |

B memory id == C memory id. B hash == C hash. B follow-on REQUEST == C follow-on REQUEST (`lookup_customer_tier` / `customer:read`).

NORMAL is not labeled SAFE, TRUSTED, APPROVED, or BENIGN.

Server-owned `allowed_tools={lookup_policy}` before and after B (**MEASURED**).

---

## Sequence (OBSERVED)

**A WRITE:** run.started → hop.started → `agentsec.memory.written` → hop.completed → run.completed. No follow-on. No `mcp.started`.

**A RECALL:** run.started → hop.started → `agentsec.memory.recalled` → CTRL-MEMORY-CONTEXT-001 OBSERVE → hop.completed → run.completed. No follow-on hop. Handler **0**.

**B WRITE:** store-only (defended). Overlay is **not** minted on write.

**B RECALL:** OBSERVE then CTRL-MCP-001 ALLOW overlay reason then `mcp.started` then `mcp.completed`. Handler **1**. Overlay `run_id` equals the recall run, not the write run.

**C WRITE:** same MALICIOUS bytes as B.

**C RECALL:** OBSERVE then CTRL-MCP-001 DENY `tool_not_granted` then pipeline.stopped. **No** follow-on `mcp.started`. `operation.attempted=false`, `executed=false`, `outcome=prevented`. Handler **0**. `ToolRegistry.invoke_counts["lookup_customer_tier"]` is authoritative.

Teaching:

- persistence ≠ trust
- recall ≠ grant
- OBSERVE ≠ ALLOW
- SAME MEMORY / SAME REQUEST / DIFFERENT AUTHORIZATION
- ALLOW ≠ execution (handler exception after ALLOW still emits mcp.started + mcp.failed)
- missing mcp.started is corroboration only

---

## Pytest (this session, MEASURED)

```
601 passed, 2 deselected
```

Command:

```
uv run --extra test python -m pytest tests -q --tb=line \
  -m "not live_ollama and not live_splunk"
```

Deselected: `live_ollama`, `live_splunk`. Prior 11A baseline was 573 passed, 2 deselected.

MCP-001 / MCP-003 / MCP-004 / MCP-005 / MCP-006 / MCP-CATALOG / scanner evidence / RAG-CONTEXT tests in that run passed. DET-MCP-001, existing Q-MCP SPL, Q-SCANNER SPL, Q-RAG SPL, and Studio definitions were not modified.

---

## Security regressions proven (MEASURED)

1. Memory never mutates `coded_policy()` (tools, scopes, resources, identity).
2. CTRL-MEMORY-CONTEXT-001 cannot mint an AllowTicket (returns OBSERVE/ERROR only).
3. Provenance `agentsec.memory.fixture` is not trust. Trust `untrusted_data` is not authorization.
4. Grant-like write fields (`allowed_tools`, profile, approval, identity, delegation) are rejected.
5. Unknown / empty / duplicate / malformed memory is ERROR, not DENY, and does not fail open.
6. Overlay is bound to the recall `run.id`. A later defended recall of the same store does not inherit it.
7. Check/use uses the frozen recall snapshot, not a second store read.
8. Preview ≤200. No `agentsec.memory.content` field. Interpreter uses full snapshot content.
9. Handler exception after ALLOW is execution (`mcp.failed`, executed=true), not prevention.
10. Splunk is not used as enforcement. `splunk.verified=false`.

---

## Schema 1.7.0 (MEASURED)

Additive bump 1.6.0 → 1.7.0. Existing MCP/RAG field meanings unchanged. New: `agentsec.memory.*`, `memory_context_trust`, `MEMORY-001`, `agent.memory.store`, `memory_lab`, `/memory/write`, `/memory/recall`, `recalled_memory`. No `trusted_memory`. No `session.id` property. No `memory_allowed_tools`.

---

## Limitations

- In-process store only. Not a production memory service.
- Closed interpreter, not an LLM memory implementation.
- No vector database, LangChain, LangGraph, or Agent Memory Guard.
- No Splunk ingest, Q-MEMORY, DET-MEMORY, or Dashboard Studio.
- Fixture strings are synthetic lab data, not an authorization protocol.
- Write run of ATTACK is defended store-only; the vulnerable overlay is recall-run only by design (11A).

---

## Verdict

**PASS — MEMORY RUNTIME IMPLEMENTED + LOCALLY VALIDATED**

Do not start Phase 11C from this file. Do not ingest these packs into Splunk. Do not write SPL.
