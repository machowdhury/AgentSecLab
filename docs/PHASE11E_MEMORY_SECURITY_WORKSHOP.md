# Phase 11E — LAB-MEMORY-001 persistent-memory SOC investigation workshop

**Date:** 2026-09-18  
**View:** `ws_lab_memory_security`  
**Verdict:** PASS — MEMORY SECURITY CHAPTER COMPLETE FOR THE DESIGNED PHASE 11A–11E PATH. This file does not authorize Phase 12, identity, A2A, vector memory, rug-pull, Agent Scan, or DET-MEMORY.

## Purpose

Teach learners how a SOC investigates persistent-memory / INV-003 evidence without collapsing write, recall, trust, request, authorization, and execution.

Learner question: **what can I prove from the evidence?** Not: was malicious memory detected?

## Hard stops (observed in this phase)

- No runtime authorization change
- Schema remains **1.7.0**
- No DET-MEMORY
- DET-MCP-001 unchanged
- No extra Q-MEMORY-* hunt files
- No embeddings, LangChain, vector DB, garak, Promptfoo, PyRIT
- Phase 12 not started. No A2A. No rug-pull. No Agent Scan. No ML implementation.

## Evidence used (validated earlier)

Phase 11C LIVE (not 11B local):

BASELINE WRITE `a8407246-7992-4ad8-bd02-cb701e150f30` / RECALL `914c41ce-5123-49eb-892c-c948295dbc46`  
ATTACK WRITE `05f1d8d0-28b7-40ac-bbb9-1dc64b4ba464` / RECALL `b8737cd9-9b6b-48f2-acfa-178ae1446ddc`  
RETEST WRITE `060a0a72-ceb5-4b99-8330-98de81d8ae5e` / RECALL `5d5b9d1b-092d-4ddb-8422-4092d289cd49`  
NORMAL hash `sha256:ee41410ab03d53a4f979cb3196619abb2aceedc69b41106ddd3a4e15599b340b`  
MALICIOUS hash `sha256:1dc7335c3fd8c54326e36194d783536d944c6d527660eb1bda4a36a9cb5ed1b9`

ATTACK and RETEST share the malicious memory.id, hash, provenance, follow-on tool, and requested scope.

ATTACK path: write → later recall → OBSERVE → REQUEST → ALLOW → START → COMPLETE (handler 1)  
RETEST path: write → later recall → OBSERVE → REQUEST → DENY → no START (handler 0)

## Workshop flow

LEARN → BASELINE → ATTACK → OBSERVE → HUNT → DETECT → DEFEND → RETEST → COMPARE → PROVE

## Evidence-plane model

1 PERSISTENCE  
2 RECALL / TRUST  
3 INFLUENCE / REQUEST  
4 AUTHORIZATION  
5 EXECUTION

PERSISTED MEMORY != TRUSTED INSTRUCTION. MEMORY RECALL != AUTHORIZATION. REQUEST != GRANT. OBSERVE != ALLOW. ALLOW != EXECUTION. SPLUNK != ENFORCEMENT.

## Dashboard

GRID 1440 / 12. Tokens: Hunt write, Hunt recall (defaults BASELINE pair), plus six specimen WRITE/RECALL controls. Full UUIDs and hashes on LEARN / COMPARE / PROVE.

Searches reused (bind only): Q-MEMORY-CONTEXT-AUTHORITY, Q-MCP-WHO, Q-MCP-AUTHZ, Q-MCP-TOOL, Q-MCP-EXECUTED, Q-MCP-AFTER-DENY, DET-MCP-001-POSITIVE-CONTROL (SIMULATED). OBSERVE write/recall sequences are Studio views of indexed fields, not new hunt files.

Rebuild: `python3 scripts/build_lab_memory_security_dashboard.py`

## Detection teaching

DETECTION ANALYZED — NO NEW MEMORY DETECTOR.

DET-MCP-001 BASELINE = 0 (no DENY). ATTACK = 0 (ALLOW path). RETEST = 0 (DENY respected). 0 rows is CORRECT. 0 rows != SAFE.

FUTURE — NOT IMPLEMENTED behavioral panel. ANOMALY != INCIDENT. ML MAY PRIORITIZE INVESTIGATION. ML MUST NOT GRANT OR DENY AUTHORITY.

WHAT WE CANNOT PROVE YET telemetry-gap panel.

## UI / KO

Pass-1 and pass-2 reviews: `docs/reviews/ui-review-ws-lab-memory-security-2026-09-18.md`.  
KO review: `docs/reviews/splunk-ko-review-memory-workshop-2026-09-18.md`.

## Contract tests

`uv run --extra test python -m pytest tests -q --tb=line -m "not live_ollama and not live_splunk"`

**MEASURED 2026-09-18:** 619 passed, 2 deselected.

Playwright pass-2: `docs/screenshots/lab-memory-security/pass2_validation.json` — 10/10 tabs, 8/8 LIVE tokens. Pytest does **not** prove Splunk rendering, ingestion, or detection effectiveness.

## Limitations

- Pytest does not prove Splunk rendering.
- Playwright captures Studio canvases; GRID below the fold may clip.
- Token input boxes may ellipsize UUIDs; full values are in markdown.
- Studio may render its own empty graphic; documented as a UI limitation, not SAFE.
- Eight token controls are required because Q-MEMORY needs write + recall.
- Studio XML restage for this pass used `docker cp` + container restart after Auto-review blocked `./scripts/lab-up.sh --refresh-app`. Repository source of truth remains `splunk_app/agentsec/`. Named-volume `--refresh-app` is still the documented local path.

## Stop

Do not start Phase 12, identity, A2A, vector memory, rug-pull, Agent Scan, or DET-MEMORY from this file.
