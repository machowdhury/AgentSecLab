# Phase 10E — RAG / retrieved-context SOC investigation workshop

**Date:** 2026-09-16  
**View:** `ws_lab_rag_context`  
**Verdict:** PASS — RAG CHAPTER COMPLETE FOR THE DESIGNED PHASE 10A–10E PATH. This file does not authorize Phase 11, embeddings, memory security, A2A, rug-pull, Agent Scan, or DET-RAG.

## Purpose

Teach learners how a SOC investigates retrieved-context / indirect prompt-injection evidence without collapsing retrieval, trust, authorization, and execution.

Learner question: **what can I prove from the evidence?** Not: did the RAG attack happen?

## Hard stops (observed in this phase)

- No runtime authorization change
- Schema remains **1.6.0**
- No DET-RAG
- DET-MCP-001 unchanged
- No Q-RAG-INJECTION / Q-RAG-MALICIOUS / Q-RAG-POISONED
- No embeddings, LangChain, garak, Promptfoo, PyRIT, NeMo
- Phase 11 not started. No memory. No A2A. No rug-pull. No Agent Scan.

## Evidence used (validated earlier)

BASELINE `51f70fb9-994e-4dd4-9b36-cac6fb1e8232`  
ATTACK `3a43d24f-9281-42f6-8375-1fb2efaa80ac`  
RETEST `bea97bae-491b-4b36-b52f-1417d2bad01b`  
NORMAL hash `sha256:0fc83ee727c6f33ad87e6ffec8698889de366311a281e4f831fe8c8d30e27f8e`  
MALICIOUS hash `sha256:c565f364c7c5fba3cf25d235bb8e2bee7d9433daa9f07d5e097ab6d2a82a97ef`

ATTACK and RETEST share the malicious document, hash, provenance, follow-on tool, and requested scope.

ATTACK path: retrieve → OBSERVE → REQUEST → ALLOW → START → COMPLETE (handler 1)  
RETEST path: retrieve → OBSERVE → REQUEST → DENY → no START (handler 0)

## Workshop flow

LEARN → BASELINE → ATTACK → OBSERVE → HUNT → DETECT → DEFEND → RETEST → COMPARE → PROVE

## Evidence-plane model

1 RETRIEVAL  
2 TRUST / INFLUENCE  
3 AUTHORIZATION  
4 EXECUTION

RETRIEVED CONTENT IS DATA. REQUEST != GRANT. OBSERVE != ALLOW. ALLOW != EXECUTION. SPLUNK != ENFORCEMENT.

## Dashboard

GRID 1440 / 12. Tokens: Hunt, BASELINE, ATTACK, RETEST. Hunt defaults to BASELINE.

Searches reused (bind only): Q-RAG-CONTEXT-AUTHORITY, Q-MCP-WHO, Q-MCP-AUTHZ, Q-MCP-TOOL, Q-MCP-EXECUTED, Q-MCP-AFTER-DENY, DET-MCP-001-POSITIVE-CONTROL (SIMULATED). OBSERVE sequence is a Studio view of indexed fields, not a new hunt file.

Rebuild: `python3 scripts/build_lab_rag_context_dashboard.py`

## Detection teaching

DETECTION ANALYZED — NO NEW RAG DETECTOR.

DET-MCP-001 BASELINE = 0 (no DENY). ATTACK = 0 (ALLOW path). RETEST = 0 (DENY respected). 0 rows is CORRECT. 0 rows != SAFE.

FUTURE — NOT IMPLEMENTED behavioral panel. ANOMALY != INCIDENT. ML MAY PRIORITIZE INVESTIGATION. ML MUST NOT GRANT OR DENY AUTHORITY.

## UI / KO

Pass-1 HIGH: COMPARE card hashes truncated; LEARN progression inequalities clipped. Fixed with wrap-safe fingerprints and taller LEARN/COMPARE panels. Pass-2: 10/10 tabs, 4/4 tokens, ATTACK/RETEST same MALICIOUS hash visible. KO review: PUBLISH / REUSE. CIM NOT APPLICABLE. DET-RAG DO NOT CREATE. DET-MCP-001 UNCHANGED.

See `docs/reviews/ui-review-ws-lab-rag-context-2026-09-16.md` and `docs/reviews/splunk-ko-review-rag-workshop-2026-09-16.md`.

## Contract tests

`uv run --extra test python -m pytest tests -q --tb=line -m "not live_ollama and not live_splunk"` → **568 passed, 2 deselected**.

Playwright: 10/10 tabs, 4/4 LIVE tokens (`docs/screenshots/lab-rag-context/pass2_validation.json`). Pytest does **not** prove Splunk rendering.

## Limitations

- Pytest does not prove Splunk rendering.
- Playwright captures Studio canvases; GRID below the fold may clip.
- Four global inputs ellipsize UUIDs; full ids/hashes are on LEARN, ATTACK, RETEST, COMPARE, and PROVE.
- Studio default empty graphic (“No search results returned”) can override `noDataMessage`. Markdown still teaches 0 rows != SAFE.
- 768 three-column auto-scale is not a claimed responsive design.
- No WCAG certification.
- Handler count remains authoritative; missing Splunk `mcp.started` is corroboration only.

## Stop

Phase 11 not started. No DET-RAG. No runtime/schema change. No embeddings. No A2A. No rug-pull. No Agent Scan.
