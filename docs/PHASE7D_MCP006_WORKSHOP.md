# Phase 7D — LAB-MCP-006 workshop and Dashboard Studio

**Date:** 2026-09-15  
**View:** `ws_lab_mcp_006` (`/en-US/app/agentsec/ws_lab_mcp_006`)  
**Builder:** `scripts/build_lab_mcp_006_dashboard.py`  
**Schema:** `agentsec.security_event` **1.4.0** (unchanged in this phase)  
**Evidence class:** OBSERVED (Splunk Web + Playwright) unless marked MEASURED / SIMULATED / DOCUMENTED.

Phase 7A/7B/7C are PASS. This phase does **not** change runtime authorization, schema 1.4.0, DET-MCP-001, or Q-MCP SPL logic. No DET-MCP-006. No MCP-007. Rejected hunts `Q-MCP-AMBIENT-USE`, `Q-MCP-DELEGATION-CHAIN`, `Q-MCP-DELEGATION-EXECUTED`, and `Q-MCP-DELEGATION-AUTHORITY` are not published.

---

## WORKSHOP FLOW

Ten GRID tabs:

LEARN → BASELINE → ATTACK → OBSERVE → HUNT → DETECT → DEFEND → RETEST → COMPARE → PROVE

Learning story:

- LAB-MCP-001: can this agent call this **tool**?
- LAB-MCP-003: can this agent call the tool at this **scope**?
- LAB-MCP-004: can this agent operate on this **resource**?
- LAB-MCP-005: can **tool-result data** widen later authority?
- LAB-MCP-006: can a **deputy** use authority the **caller** did not delegate?

Core question: The deputy may possess authority — but did the caller actually delegate that authority for this operation?

DEPUTY AUTHORITY ≠ CALLER AUTHORITY. DEPUTY AUTHORITY ≠ DELEGATED AUTHORITY.

---

## DASHBOARD STRUCTURE

| Tab | Teaching | Bound searches |
|-----|----------|----------------|
| LEARN | Core question; caller vs deputy; delegated vs ambient; trust boundary | Markdown + three cards |
| BASELINE | Legitimate `lookup_policy` delegation | DELEGATION What Happened, AUTHZ, WHO, EXECUTED |
| ATTACK | Ambient substitution; fail-open ALLOW | DELEGATION What Happened, AUTHZ, TOOL, EXECUTED |
| OBSERVE | Sequence; IDENTITY / AUTHORITY / CONTROL / EXECUTION | Sequence, WHO, DELEGATION, AUTHZ, EXECUTED |
| HUNT | Primary DELEGATION; rejected hunts named | DELEGATION, WHO, AUTHZ, EXECUTED, TOOL |
| DETECT | NO NEW DETECTOR; DET-MCP-001 silent; LIVE 0; SIMULATED | Q-MCP-AFTER-DENY + `makeresults` SIMULATED |
| DEFEND | Two controls, two questions; LIMITED server evidence | Markdown |
| RETEST | Same request as ATTACK; DENY; runtime 0 | DELEGATION What Happened, AUTHZ, TOOL, EXECUTED |
| COMPARE | Three cards BASELINE / ATTACK / RETEST | Markdown only (wide hunt kept off COMPARE) |
| PROVE | Evidence hierarchy; correlation limitation | DELEGATION on Hunt token |

Tokens (Phase 7C fresh LIVE specimens):

| Token | Default run.id |
|-------|----------------|
| `run_id` (Hunt) | `1cf98c4d-1bd8-4df5-be70-b82419e2c2b2` (BASELINE A) |
| `baseline_run_id` | same A |
| `attack_run_id` | `d7524a4e-8da6-4171-8867-d2a2168128ac` |
| `retest_run_id` | `50f7ec04-7524-41c0-95a8-3b1ef4d91dc4` |

---

## BASELINE / ATTACK / RETEST (Phase 7C facts, workshop presentation)

BASELINE: defended, `lookup_policy` / `policy:read` / `lending-basics`, source=`delegated`, ALLOW `delegation_granted`, MCP ALLOW `tool_granted`, policy handler 1 / tier 0, 10=10.

ATTACK: vulnerable, `lookup_customer_tier` / `customer:read` / `cust-001`, source=`ambient_deputy`, ALLOW `vulnerable_profile_fail_open:ambient_deputy_authority`, MCP ALLOW `tool_granted` (not caller grant), tier handler **1**, 10=10. Request hash `sha256:ea33191fceeb105e47270f6839bb98addfb7245a32534138192b23e1fab9a419`.

RETEST: defended, **same request as ATTACK**, source=`delegated`, DENY `delegated_authority_not_granted`, no downstream MCP, runtime handler **0**, Splunk: no indexed MCP execution-start event observed, `deputy_not_on_indexed_hop1`, 6=6.

---

## DETECT

DETECTION ANALYZED — NO NEW DETECTOR. DET-MCP-001 LIVE A/B/C = 0. SIMULATED positive control = 1 (`makeresults`, NOT INDEXED). Silence on ATTACK is expected (ALLOW path, not DENY-then-start).

---

## REJECTED SPL CONFIRMATION

`Q-MCP-AMBIENT-USE`, `Q-MCP-DELEGATION-CHAIN`, `Q-MCP-DELEGATION-EXECUTED`, and `Q-MCP-DELEGATION-AUTHORITY` are absent from dataSources, search files, savedsearches, and learner SPL. Named only as rejected / not published. **PASS**.

---

## LIVE SPLUNK UI

Playwright 10/10 tabs. Four tokens MEASURED (complete UUIDs in DOM `input_value`, not visual ellipsis). Indexed What Happened rows OBSERVED for A/B/C. DETECT left empty OBSERVED; right SIMULATED OBSERVED.

After `--refresh-app`, Splunk Web served the view; **HEC health did not return HTTP 200** (empty reply). Do not claim the local lab was READY for new ingest during pass-2. No new LIVE specimens were generated in 7D.

---

## UI REVIEW

Pass-1: 0 BLOCKER / 4 HIGH / 5 MEDIUM / 3 LOW (`docs/reviews/ui-review-ws-lab-mcp-006-2026-09-15.md`).  
Pass-2: **0 BLOCKER / 0 HIGH**. Residual MEDIUM/LOW accepted.

---

## LOGIC PROOF

`docs/reviews/mcp006-phase7d-logic-proof.md`. Workshop does not teach deputy permission as caller permission, execution as authorization, empty Splunk as prevention, or detector silence as “no attack.”

---

## TEST RESULTS

`.venv/bin/python -m pytest tests -q --tb=line -m "not live_ollama and not live_splunk"`  
**368 passed, 2 deselected** (2026-09-15, this session).

XML/JSON parse and match. Ten tabs. Tokens resolve. Validated SPL bind-only. DET-MCP-001 unchanged. No DET-MCP-006. Schema remains 1.4.0.

---

## FILES CHANGED

Workshop, Studio definition/XML, nav, lab-up/lab-ready/splunk_app_init, dashboard/workshop tests, screenshot script, this document, learning note, UI review, logic proof, IMPLEMENTATION_STATUS, MCP_LAB_PLAN.

Not changed: MCP-006 runtime, schema 1.4.0, DET-MCP-001.spl, Q-MCP-*.spl logic.

---

## PHASE 7D VERDICT

**VALIDATED** for the workshop/Dashboard Studio teaching surface on Phase 7C LIVE indexed copies.

MCP-006 final: IMPLEMENTED + LOCALLY VALIDATED + SPLUNK VALIDATED + WORKSHOP VALIDATED. Detection: **DETECTION ANALYZED — NO NEW DETECTOR**.

STOP. Do not start MCP-007. Do not start A2A. Do not create DET-MCP-006. Do not modify runtime authorization. Do not modify schema 1.4.0.
