# Phase 8C — LAB-MCP-CATALOG runtime + local security validation

**Status:** **IMPLEMENTED + LOCALLY VALIDATED**  
**Date:** 2026-09-15  
**Schema:** `agentsec.security_event` **1.5.0**  
**Splunk:** `splunk.verified=false`. No SPL changed. DET-MCP-001 unchanged. DET-MCP-CATALOG not created. Scanners not wired.  
**Evidence class:** pytest **MEASURED**. Local A/B/C packs **OBSERVED**. Splunk **NOT ATTEMPTED**.

Parents: `docs/MCP_CATALOG_POISONING_RUNTIME_CONTRACT.md`, `docs/SCHEMA_1_5_0.md`.

---

## Canonical local runs (this session, OBSERVED)

| Id | run.id | Profile | Mode | Catalog | METADATA-001 | Follow-on CTRL-MCP-001 | lookup_policy | lookup_customer_tier | Terminal |
|----|--------|---------|------|---------|--------------|------------------------|---------------|----------------------|----------|
| **A** | `e7e35b7c-541d-405c-86d1-ef2bdc687f04` | defended | BASELINE | NORMAL | OBSERVE `metadata_is_data` | none | 1 | 0 | `completed_allowed` |
| **B** | `414bb714-1268-4242-b866-47d5294ba06c` | vulnerable | ATTACK | MALICIOUS | OBSERVE `metadata_is_data` | ALLOW `vulnerable_profile_fail_open:metadata_derived_authority` | 1 | 1 | `completed_allowed` |
| **C** | `39958d1b-274e-4ef1-a27d-2aa4f4820070` | defended | RETEST | **same MALICIOUS as B** | OBSERVE `metadata_is_data` | DENY `tool_not_granted` | 1 | 0 | `completed_denied` |

Trace ids: A `ba3013a37f637fb0d9e5a78b20e3445c`; B `a7b321a170021cea8d422b6d060184b4`; C `2e3d159eaeb0df5ce131f4814190e9fa`.

Event counts: A **8**; B **13**; C **12**.

B and C description hashes are identical: `sha256:9d0745320ca79852f2fbd7145bf074fcd353e290c18ba16fd02d801f9f3375b1`.

Server-owned `allowed_tools={lookup_policy}` before and after B and C (**MEASURED** in pytest + these packs).

Packs: `artifacts/<run-id>/`. Each `export.json` has `splunk.verified=false`. `manifest.json` includes `schema.version=1.5.0`, catalog fixture, description hash/preview, metadata decision, follow-on decision, handler counts.

## Sequence (OBSERVED)

**A:** METADATA-001 OBSERVE → CTRL-MCP-001 ALLOW `lookup_policy` → mcp.started → mcp.completed. No follow-on.

**B:** METADATA-001 OBSERVE → CTRL-MCP-001 ALLOW `lookup_policy` → mcp.started/completed → CTRL-MCP-001 ALLOW `lookup_customer_tier` (overlay) → mcp.started/completed.

**C:** METADATA-001 OBSERVE → CTRL-MCP-001 ALLOW `lookup_policy` → mcp.started/completed → CTRL-MCP-001 DENY `lookup_customer_tier` → pipeline.stopped. **No** follow-on `mcp.started`.

Authoritative non-execution for C: `ToolRegistry.invoke_counts["lookup_customer_tier"]=0`. Missing Splunk rows are not proof.

## Pytest (this session, MEASURED)

```
430 passed, 2 deselected
```

Deselected: `live_ollama`, `live_splunk` markers. Prior 8B baseline was 384 passed, 2 deselected.

MCP-001 / MCP-003 / MCP-004 / MCP-005 / MCP-006 tests in that run passed (no security-critical regression). DET-MCP-001, existing Q-MCP SPL, and Studio definitions were not modified.

## Security regressions proven (MEASURED)

1. Malicious metadata does not mutate `coded_policy()`.
2. METADATA-001 cannot mint an AllowTicket (returns OBSERVE/ERROR only).
3. Defended follow-on still reaches CTRL-MCP-001.
4. RETEST follow-on handler count is 0.
5. ATTACK overlay is per-run only; a later run does not inherit it.
6. Result-data MCP-005 path still cannot widen grants.
7. HTTP extras (`catalog_fixture`, `metadata.trust`, `allowed_tools`, `security.profile`) are `unknown_fields`.
8. No `should_block_from_scanner`; scanners are unwired.
9. Malformed/unknown catalog is ERROR, not DENY, and creates no authority.
10. ALLOW remains separate from execution (`mcp.failed` after overlay ALLOW still counts as execution).
11. OBSERVE is not ALLOW and not DENY.
12. Preview truncation cannot hide the closed marker from the full-description interpreter.

## Limitations

- In-process tools/list-shaped snapshot. Not a complete MCP transport.
- Interpreter recognizes one synthetic marker only. Not an LLM and not a product parser.
- Vulnerable overlay is labeled lab fail-open. Not production policy.
- Schema 1.5.0 has no `gen_ai.tool.call.id`.
- Splunk not indexed. No Q-MCP-CATALOG. No Dashboard Studio. No DET-MCP-CATALOG.
- Catalog integrity / rug-pull / `list_changed` not claimed.

## Verdict

**PASS — IMPLEMENTED + LOCALLY VALIDATED**

STOP. Phase 8D not started.
