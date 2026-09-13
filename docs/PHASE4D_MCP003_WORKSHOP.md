# Phase 4D — LAB-MCP-003 workshop and Dashboard Studio

**Date:** 2026-09-12  
**View:** `ws_lab_mcp_003` (`/en-US/app/agentsec/ws_lab_mcp_003`)  
**Builder:** `scripts/build_lab_mcp_003_dashboard.py`  
**Evidence class:** OBSERVED (Splunk Web + Playwright) unless marked MEASURED / SIMULATED.

Phase 4C is VALIDATED. This phase does **not** change runtime authorization, schema 1.1.0, DET-MCP-001, or Q-MCP SPL.

---

## WORKSHOP FLOW

Ten GRID tabs, same lifecycle as LAB-MCP-001:

LEARN → BASELINE → ATTACK → OBSERVE → HUNT → DETECT → DEFEND → RETEST → COMPARE → PROVE

Learning story:

- LAB-MCP-001: may this agent call this **tool**?
- LAB-MCP-003: may this agent call this tool **at this requested_scope**?

The tool (`lookup_policy`) is granted. The excessive requested scope (`policy:restricted:read`) is not.

---

## DASHBOARD STRUCTURE

| Tab | Teaching | Bound searches |
|-----|----------|----------------|
| LEARN | Catalog vs grant vs request; three states; exact membership | Markdown only |
| BASELINE | Granted `policy:read` ALLOW | AUTHZ, SCOPE, TOOL, EXECUTED + What Happened |
| ATTACK | Vulnerable fail-open; grant unchanged | AUTHZ, SCOPE, TOOL, EXECUTED + What Happened |
| OBSERVE | Sequence: control before `mcp.started` | Sequence table |
| HUNT | Reuse Q-MCP; Hunt token defaults to BASELINE A | AUTHZ, SCOPE, TOOL, EXECUTED |
| DETECT | DET-MCP-001 reuse; LIVE 0; SIMULATED PC | Q-MCP-AFTER-DENY + `makeresults` SIMULATED |
| DEFEND | Defended DENY; unknown `policy:write` panel | AUTHZ, SCOPE, EXECUTED + unknown AUTHZ/SCOPE/EXECUTED |
| RETEST | DENY `scope_not_granted`; handler 0 | AUTHZ, SCOPE, TOOL, EXECUTED + What Happened |
| COMPARE | Three-way BASELINE / ATTACK / RETEST | AUTHZ / SCOPE / EXECUTED × 3 |
| PROVE | Evidence hierarchy; runtime vs Splunk vs detector | Markdown only |

Tokens (Phase 4C fresh LIVE specimens):

| Token | Default run.id |
|-------|----------------|
| `run_id` (Hunt) | `5b089682-1d5a-49a7-ac43-967265fd6bc6` (BASELINE A) |
| `baseline_run_id` | same A |
| `attack_run_id` | `b466ad12-72ec-44b7-be28-aacfaf2c25b1` |
| `retest_run_id` | `f638fd4f-1c4f-4ab6-8d42-4d03a4f3afd5` |
| `unknown_run_id` | `6ce19813-6cb5-4aae-a3a0-aa59386a82dd` |

---

## BASELINE RESULT

**Class:** OBSERVED (Playwright pass-1 + pass-2 on indexed Phase 4C A).

| Field | Value |
|-------|-------|
| profile | `defended` |
| mode | `BASELINE` |
| tool | `lookup_policy` |
| requested_scope | `policy:read` |
| allowed_scope | `policy:read` |
| decision | ALLOW |
| reason | `tool_granted` |
| scope_relation | `granted` |
| mcp.started | yes (seq 4 after control seq 3) |
| terminal | `mcp.completed` |

ALLOW is the control decision. Execution is a later `mcp.started` / `mcp.completed` pair.

---

## ATTACK RESULT

**Class:** OBSERVED.

| Field | Value |
|-------|-------|
| profile | `vulnerable` |
| mode | `ATTACK` |
| tool | `lookup_policy` |
| requested_scope | `policy:restricted:read` |
| allowed_scope | `policy:read` |
| decision | ALLOW |
| reason | `vulnerable_profile_fail_open:scope_not_granted` |
| scope_relation | `mismatch` |
| handler | ran (runtime 1; Splunk `mcp.completed`) |

The grant did **not** change. `allowed_scope` stayed `policy:read`.

---

## RETEST RESULT

**Class:** OBSERVED (Splunk) + MEASURED (runtime handler count from Phase 4C).

| Field | Value |
|-------|-------|
| profile | `defended` |
| mode | `RETEST` |
| decision | DENY |
| reason | `scope_not_granted` |
| attempted / executed | false |
| outcome | `prevented` |
| Q-MCP-TOOL | empty (`no_mcp_execution_event`) |

Runtime handler count **0** remains authoritative. Empty Splunk execution is corroboration, not the proof of non-execution.

---

## UNKNOWN_SCOPE RESULT

**Class:** OBSERVED on DEFEND unknown tables (token D).

| Field | Value |
|-------|-------|
| requested_scope | `policy:write` |
| decision | ERROR |
| reason | `unknown_scope` |
| scope_relation | `not_a_grant` |
| handler | 0 |

This is **not** RETEST. ERROR ≠ DENY.

---

## Q-MCP-SCOPE RESULT

Unchanged SPL from `learning/level_1/LAB-MCP-001/searches/Q-MCP-SCOPE.spl`. Dashboard binds `__RUN_ID__` to the tab token only.

`case()` order: ERROR → `not_a_grant` before mismatch. BASELINE `granted`. ATTACK `mismatch`. RETEST `mismatch`. UNKNOWN `not_a_grant`.

No duplicate MCP-003 scope search was added.

---

## DET-MCP-001 REUSE RESULT

Live DETECT left table: **0 rows** for Hunt BASELINE (and Phase 4C A/B/C/D/E/F REST). Right table is **SIMULATED** `DET-MCP-001-SCOPE-POSITIVE-CONTROL` (`makeresults`). Original LAB-MCP-001 tool-grant PC is unused here so the teaching row is scope-specific.

DET-MCP-001 `.spl` was not modified. No DET-MCP-003 exists.

---

## WHAT HAPPENED RESULT

Identity table + decision table. Indexed fields only. No LLM narrative. Empty tables keep `noDataMessage`; captions are not used as empty-state teaching.

---

## COMPARE RESULT

Three columns (BASELINE / ATTACK / RETEST) × AUTHZ, SCOPE, EXECUTED.

Lesson: same tool, same arguments, different requested authority.

---

## EMPTY-STATE RESULT

Q-MCP-TOOL / Q-MCP-EXECUTED `noDataMessage`: "No indexed MCP execution event was found for this run."

Q-MCP-AFTER-DENY: "No indexed DENY followed later by mcp.started was found for this Hunt run_id."

Does **not** say "Scope escalation was blocked."

---

## ACCESSIBILITY RESULT

Full UUID tokens in inputs. Status is text + color, not color-only. Nested backticks that smashed `GRANT_UNCHANGED` on pass-1 were removed (HIGH). HUNT EXECUTED is full width so `execution_state` is on-canvas (HIGH). Residual MEDIUM: DETECT orange empty chrome, token ellipsis, COMPARE third-width clip.

---

## PASS-1 UI REVIEW

`docs/reviews/ui-review-ws-lab-mcp-003-2026-09-12.md`

BLOCKER: none. HIGH: two (smashed grant sentence; clipped HUNT EXECUTED).

---

## FIXES

1. ATTACK / DEFEND / RETEST markdown: no extra backticks around `allowed_scope=policy:read`.
2. HUNT: Q-MCP-EXECUTED full width; Q-MCP-TOOL full width below.

---

## PASS-2 UI REVIEW

Same file, pass-2 section. Screenshots: `docs/screenshots/lab-mcp-003/pass2_*.png`.

HIGH grant sentence **FIXED** (readable `policy:read`). HIGH HUNT EXECUTED **FIXED** (`execution_state=mcp.completed` on canvas). No remaining HIGH. Residual MEDIUM/LOW accepted.

---

## SECURITY SEMANTICS REVIEW

UI does not claim: tool granted = scope granted; known-but-ungranted = unknown; unknown = DENY; ALLOW = execution; mcp.started = success; mcp.failed = prevention; no Splunk event = blocked; allowed_scope rewritten on fail-open; Splunk authorized the tool; SIMULATED = OBSERVED.

---

## TEST RESULTS

This session (after HIGH rebuild, pass-2 capture, and these docs):

```text
.venv/bin/python -m pytest tests -q --tb=line -m "not live_ollama and not live_splunk"
194 passed, 2 deselected in 0.76s
```

Pytest does **not** execute SPL against Splunk and does **not** prove the dashboard loaded. Splunk Web load is OBSERVED via Playwright (`pass2_validation.json`). Runtime authorization tests were not changed this phase.

---

## FILES CHANGED

Primary this phase:

- `scripts/build_lab_mcp_003_dashboard.py` — single builder (JSON + XML)
- `learning/level_1/LAB-MCP-003/` — README, workshop, dashboard, evidence, knowledge-check, definition JSON
- `splunk_app/agentsec/default/data/ui/views/ws_lab_mcp_003.xml`
- `splunk_app/agentsec/default/data/ui/nav/default.xml`
- `scripts/capture_lab_mcp_003_screenshots.py`
- `tests/splunk/test_lab_mcp_003_dashboard.py`, `tests/workshops/test_lab_mcp_003_workshop.py`
- `scripts/lab-ready.sh`, `scripts/lab-up.sh`, `scripts/splunk_app_init.sh`
- `docs/PHASE4D_MCP003_WORKSHOP.md`, `docs/learning-notes/mcp-scope-workshop.md`
- `docs/reviews/ui-review-ws-lab-mcp-003-2026-09-12.md`
- `docs/screenshots/lab-mcp-003/pass1_*.png`, `pass2_*.png`

Not changed: `src/agentsec/mcp/authorize.py`, schema 1.1.0, `DET-MCP-001.spl`, Q-MCP SPL logic (bind-only).

---

## LIMITATIONS

- Playwright is canvas-level, not cell-level OCR of every table row.
- COMPARE third-width still clips some columns (MEDIUM accepted).
- DETECT orange empty chrome is Splunk Studio default (MEDIUM accepted).
- Handler count is runtime, not a Splunk field.
- No MCP-004. No DET-MCP-003. No Cisco. No MLTK. No attack chains.

---

## PHASE 4D VERDICT

**VALIDATED.** Workshop UI loaded in Splunk Web (10/10 tabs OBSERVED). Indexed BASELINE / ATTACK / RETEST / UNKNOWN tables OBSERVED. HIGH UI findings fixed and recaptured. Pytest **194 passed**, 2 deselected. Splunk still does not authorize MCP tools. No DET-MCP-003. No MCP-004. Runtime authorization unchanged.
