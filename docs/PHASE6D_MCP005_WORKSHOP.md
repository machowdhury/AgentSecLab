# Phase 6D — LAB-MCP-005 workshop and Dashboard Studio

**Date:** 2026-09-14  
**View:** `ws_lab_mcp_005` (`/en-US/app/agentsec/ws_lab_mcp_005`)  
**Builder:** `scripts/build_lab_mcp_005_dashboard.py`  
**Schema:** `agentsec.security_event` **1.3.0** (unchanged in this phase)  
**Evidence class:** OBSERVED (Splunk Web + Playwright) unless marked MEASURED / SIMULATED / DOCUMENTED.

Phase 6A/6B/6C are PASS. This phase does **not** change runtime authorization, schema 1.3.0, DET-MCP-001, or Q-MCP SPL logic. No DET-MCP-005. No MCP-006. Rejected hunt `Q-MCP-RESULT-FOLLOWON` is not published.

---

## WORKSHOP FLOW

Ten GRID tabs:

LEARN → BASELINE → ATTACK → OBSERVE → HUNT → DETECT → DEFEND → RETEST → COMPARE → PROVE

Learning story:

- LAB-MCP-001: may the agent call this **tool**?
- LAB-MCP-003: may the agent call this tool at this **scope**?
- LAB-MCP-004: may the agent call this tool at this scope for **this resource**?
- LAB-MCP-005: can **data returned by the authorized tool** alter future authority?

Core question: The tool was authorized and executed correctly. Can data returned by that tool change what the agent is authorized to do next? Defended answer: **NO**.

---

## DASHBOARD STRUCTURE

| Tab | Teaching | Bound searches |
|-----|----------|----------------|
| LEARN | Core question; ladder; server-owned vs result-derived; trust boundary | Markdown + three cards |
| BASELINE | NORMAL result; derived absent; no follow-on | AUTHORITY What Happened, AUTHZ, TOOL, EXECUTED |
| ATTACK | Initial invoke not the failure; overlay ALLOW | AUTHORITY What Happened, AUTHZ, TOOL, EXECUTED |
| OBSERVE | Sequence; What Happened; bounded preview | Sequence, AUTHORITY, RESULT, WHO |
| HUNT | Primary AUTHORITY; extra RESULT-001 rows explained | AUTHORITY, AUTHZ, RESULT-TRUST, EXECUTED, TOOL |
| DETECT | NO NEW DETECTOR; DET-MCP-001 silent; LIVE 0; SIMULATED | Q-MCP-AFTER-DENY + `makeresults` SIMULATED |
| DEFEND | Data cannot create permission; LIMITED server evidence | Markdown |
| RETEST | Same malicious hash; DENY; runtime 0 | AUTHORITY What Happened, AUTHZ, TOOL, EXECUTED |
| COMPARE | Three cards BASELINE / ATTACK / RETEST | AUTHORITY × 3 |
| PROVE | Evidence hierarchy; correlation limitation | AUTHORITY on Hunt token |

Tokens (Phase 6C fresh LIVE specimens):

| Token | Default run.id |
|-------|----------------|
| `run_id` (Hunt) | `3013aa39-fe08-4b58-9898-f3abb092ac06` (BASELINE A) |
| `baseline_run_id` | same A |
| `attack_run_id` | `f3f48182-df57-4b38-b069-17a199dc4939` |
| `retest_run_id` | `0ab10594-a7fc-48b6-81bf-4cbca54a64c6` |

---

## BASELINE / ATTACK / RETEST (Phase 6C facts, workshop presentation)

BASELINE: defended, NORMAL hash `sha256:2c258a80…beb68e`, hop-0 ALLOW, RESULT-001 OBSERVE, derived absent, no follow-on, policy handler 1 / tier 0, 8=8.

ATTACK: vulnerable, MALICIOUS hash `sha256:f7d67b15…30c358`, hop-0 ALLOW (not the failure), RESULT-001 ALLOW overlay, derived **present**, follow-on `lookup_customer_tier` ALLOW overlay (not server grant), follow-on handler **1**, 13=13.

RETEST: defended, **same MALICIOUS hash**, derived absent, follow-on DENY `tool_not_granted`, runtime follow-on handler **0**, Splunk: no indexed follow-on execution event observed, 12=12.

---

## DETECT

DETECTION ANALYZED — NO NEW DETECTOR. DET-MCP-001 LIVE A/B/C = 0. SIMULATED positive control = 1 (`makeresults`, NOT INDEXED). Silence on ATTACK is expected (ALLOW path, not DENY-then-start).

---

## REJECTED SPL CONFIRMATION

`Q-MCP-RESULT-FOLLOWON` is absent from dataSources, search files, savedsearches, and learner SPL. Named only as rejected / not published. **PASS**.

---

## LIVE SPLUNK UI

Playwright 10/10 tabs. Four tokens MEASURED. Indexed What Happened rows OBSERVED for A/B/C. DETECT left empty OBSERVED; right SIMULATED OBSERVED.

After `--refresh-app`, Splunk Web served the view; **HEC health did not return HTTP 200** (empty reply). Do not claim the local lab was READY for new ingest during pass-2. No new LIVE specimens were generated in 6D.

---

## UI REVIEW

Pass-1: 0 BLOCKER / 4 HIGH / 5 MEDIUM / 3 LOW (`docs/reviews/ui-review-ws-lab-mcp-005-2026-09-14.md`).  
Pass-2: **0 BLOCKER / 0 HIGH**. Residual MEDIUM/LOW accepted.

---

## TEST RESULTS

`.venv/bin/python -m pytest tests -q --tb=line -m "not live_ollama and not live_splunk"`  
**312 passed, 2 deselected** (2026-09-14, this session).

XML/JSON parse and match. Ten tabs. Tokens resolve. Validated SPL bind-only. DET-MCP-001 unchanged. No DET-MCP-005. Schema remains 1.3.0.

---

## FILES CHANGED

Workshop, Studio definition/XML, nav, lab-up/lab-ready/splunk_app_init, dashboard/workshop tests, screenshot script, this document, learning note, UI review, IMPLEMENTATION_STATUS.

Not changed: MCP-005 runtime, schema, DET-MCP-001.spl, Q-MCP-*.spl logic.

---

## PHASE 6D VERDICT

**VALIDATED** for the workshop/Dashboard Studio teaching surface on Phase 6C LIVE indexed copies.

MCP-005 final: IMPLEMENTED + LOCALLY VALIDATED + SPLUNK VALIDATED + WORKSHOP VALIDATED. Detection: **DETECTION ANALYZED — NO NEW DETECTOR**.

STOP. Do not start MCP-006. Do not create DET-MCP-005. Do not modify runtime authorization. Do not modify schema 1.3.0.
