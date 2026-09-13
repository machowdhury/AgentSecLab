# Phase 5D — LAB-MCP-004 workshop and Dashboard Studio

**Date:** 2026-09-13  
**View:** `ws_lab_mcp_004` (`/en-US/app/agentsec/ws_lab_mcp_004`)  
**Builder:** `scripts/build_lab_mcp_004_dashboard.py`  
**Schema:** `agentsec.security_event` **1.2.0** (unchanged)  
**Evidence class:** OBSERVED (Splunk Web + Playwright) unless marked MEASURED / SIMULATED / DOCUMENTED.

Phase 5C is VALIDATED. This phase does **not** change runtime authorization, schema 1.2.0, DET-MCP-001, or Q-MCP SPL logic. No DET-MCP-004. No MCP-005.

---

## WORKSHOP FLOW

Ten GRID tabs, same lifecycle as LAB-MCP-001 / LAB-MCP-003:

LEARN → BASELINE → ATTACK → OBSERVE → HUNT → DETECT → DEFEND → RETEST → COMPARE → PROVE

Learning story:

- LAB-MCP-001: may the agent call this **tool**?
- LAB-MCP-003: may the agent call this tool at this **scope**?
- LAB-MCP-004: may the agent call this tool at this scope for **this resource**?

The tool (`lookup_policy`) is granted. The scope (`policy:read`) is granted. The excessive resource (`executive-restricted`) is not.

---

## DASHBOARD STRUCTURE

| Tab | Teaching | Bound searches |
|-----|----------|----------------|
| LEARN | Authorization ladder; three resource states; valid args ≠ authorized | Markdown + three-state cards + parameter panel |
| BASELINE | Granted `lending-basics` ALLOW | AUTHZ, RESOURCE-AUTHZ, TOOL, EXECUTED + What Happened |
| ATTACK | Vulnerable fail-open; grant unchanged; resource not granted | AUTHZ, RESOURCE-AUTHZ, TOOL, EXECUTED + What Happened |
| OBSERVE | Sequence: control before `mcp.started`; resource fields | Sequence table, AUTHZ, RESOURCE-AUTHZ |
| HUNT | Primary `Q-MCP-RESOURCE-AUTHZ`; SCOPE contrast | AUTHZ, SCOPE, RESOURCE-AUTHZ, TOOL, EXECUTED |
| DETECT | DET-MCP-001 reuse; LIVE 0; SIMULATED PC | Q-MCP-AFTER-DENY + `makeresults` SIMULATED |
| DEFEND | Defended DENY; unknown ERROR; malformed; duplicate-key | AUTHZ, RESOURCE-AUTHZ on UNKNOWN token |
| RETEST | DENY `resource_not_granted`; handler 0 | AUTHZ, RESOURCE-AUTHZ, TOOL, EXECUTED + What Happened |
| COMPARE | Three-way BASELINE / ATTACK / RETEST | AUTHZ / RESOURCE-AUTHZ / EXECUTED × 3 |
| PROVE | Evidence hierarchy; correlation limitation | What Happened on Hunt token |

Tokens (Phase 5C fresh LIVE specimens):

| Token | Default run.id |
|-------|----------------|
| `run_id` (Hunt) | `fb50dcaf-8e84-4a3f-a55b-997c72edbd04` (BASELINE A) |
| `baseline_run_id` | same A |
| `attack_run_id` | `5ab59fc7-303e-4eea-84e7-ae0b2f405146` |
| `retest_run_id` | `0726a0ff-a551-41a8-bfbb-ab2ceca4c0dd` |
| `unknown_run_id` | `0e4e0051-528d-4bf3-8773-d1fb55a5864f` |

---

## BASELINE RESULT

**Class:** OBSERVED (Playwright + live CLI).

| Field | Value |
|-------|-------|
| profile | `defended` |
| mode | `BASELINE` |
| tool | `lookup_policy` |
| scope | `policy:read` (granted) |
| resource.id | `lending-basics` |
| allowed_resource.ids | `lending-basics` |
| decision | ALLOW |
| reason | `tool_granted` |
| resource_relation | `granted` |
| mcp.started | yes (seq 4 after control seq 3) |
| terminal | `mcp.completed` |
| handler count | **1** (runtime, Phase 5C) |

ALLOW is the control decision. Execution is a later `mcp.started` / `mcp.completed` pair.

---

## ATTACK RESULT

**Class:** OBSERVED.

| Field | Value |
|-------|-------|
| profile | `vulnerable` |
| mode | `ATTACK` |
| tool | `lookup_policy` (granted) |
| scope | `policy:read` (granted) |
| resource.id | `executive-restricted` |
| allowed_resource.ids | `lending-basics` (unchanged) |
| decision | ALLOW |
| reason | `vulnerable_profile_fail_open:resource_not_granted` |
| resource_relation | `known_but_ungranted` |
| mcp.started | yes |
| terminal | `mcp.completed` |
| handler count | **1** (runtime, Phase 5C) |

The resource was **not** granted. The vulnerable control failed open. Q-MCP-SCOPE on this run is still `granted` (MEASURED). That is why the resource hunt exists.

Do not label: resource authorized, resource granted, grant widened.

---

## RETEST RESULT

**Class:** OBSERVED.

| Field | Value |
|-------|-------|
| profile | `defended` |
| mode | `RETEST` |
| resource.id | `executive-restricted` |
| allowed_resource.ids | `lending-basics` |
| decision | DENY |
| reason | `resource_not_granted` |
| attempted / executed | false / false |
| outcome | `prevented` |
| mcp.started | no indexed row |
| handler count | **0** (runtime, Phase 5C; authoritative) |

Splunk absence of `mcp.started` is corroboration on a complete copy. Splunk did not prevent the action.

---

## UNKNOWN RESOURCE RESULT

**Class:** OBSERVED. Not ATTACK. Not RETEST.

| Field | Value |
|-------|-------|
| resource.id | `does-not-exist` |
| decision | ERROR |
| reason | `unknown_resource` |
| resource_relation | `not_a_grant` |
| handler count | **0** (Phase 5C) |

unknown resource ≠ known-but-ungranted. ERROR ≠ DENY.

---

## MALFORMED ARGUMENT TEACHING

LEARN/DEFEND markdown. Phase 5C `{ }` specimen `9ea63448-bf6a-4619-b313-b152f4d94bb6`: ERROR `malformed_arguments`, **no** `resource.id`. Integer `policy_id` is the same class. `{"policy_id": "executive-restricted"}` is valid shape, known, not granted.

---

## DUPLICATE-KEY TEACHING

HTTP boundary. Phase 5C `ffafb62e-a6c6-42c0-837d-094cbfb3f795`: `run.failed` `duplicate_json_keys`, **no** CTRL-MCP-001 event. Do not fabricate a control.decision hunt.

---

## Q-MCP-RESOURCE-AUTHZ RESULT

**Class:** MEASURED (live Splunk CLI this session). Files unchanged.

| Specimen | resource_relation | decision / reason |
|----------|-------------------|-------------------|
| BASELINE | `granted` | ALLOW `tool_granted` |
| ATTACK | `known_but_ungranted` | ALLOW `vulnerable_profile_fail_open:resource_not_granted` |
| RETEST | `known_but_ungranted` | DENY `resource_not_granted` |
| UNKNOWN | `not_a_grant` | ERROR `unknown_resource` |

---

## DET-MCP-001 REUSE RESULT

LIVE MCP-004 RETEST `Q-MCP-AFTER-DENY`: **0** rows (MEASURED). DETECT right table: **SIMULATED** `DET-MCP-001-RESOURCE-POSITIVE-CONTROL` fires one fixture row (OBSERVED in Studio). DET-MCP-001.spl unmodified. No DET-MCP-004.

0 detector hits means no indexed DENY→execution violation was found. Not: system is secure.

---

## CHECK/USE TEACHING

LEARN parameter panel: request resource → authorize exact id → AllowTicket.resource_id → handler uses ticket resource. Resource authorized means resource used. Practical: the body must not be changeable after the check so a different policy is executed.

---

## WHAT HAPPENED RESULT

Two indexed-field tables (identity + decision). No LLM narrative. Decision table includes `resource_id`, `allowed_resource_ids`, `execution_state`. Empty is not DENY.

---

## COMPARE RESULT

Markdown three-way: same tool, same scope; ATTACK and RETEST same resource; profile changes whether fail-open is permitted. Tables: AUTHZ / RESOURCE-AUTHZ / EXECUTED × 3. Handler counts are runtime facts from Phase 5C.

---

## PROVE RESULT

Six layers: RUNTIME → LOCAL → EXPORT → SPLUNK INDEXED → SEARCH → DETECTION. Runtime invoke count is strongest proof of handler non-execution. Splunk is observational. Correlation note: DET-MCP-001 is `run_id` + tool; one invoke per run is valid now; future multi-resource same-tool flows may need per-invocation identity. Not solved here.

---

## EMPTY-STATE RESULT

Tables stay visible (`hideWhenNoData=false`). Neutral copy, e.g. “No indexed MCP execution event was found for this run.” DETECT live empty uses Studio orange chrome (MEDIUM). Captions do not say “Resource attack blocked.”

---

## ACCESSIBILITY RESULT

Studio `large` markdown. Severity in text (ALLOW / DENY / ERROR / SIMULATED), not color alone. Full UUIDs in LEARN bullets; token inputs ellipsis (Playwright reads complete values). Not a WCAG certification.

---

## PASS-1 UI REVIEW

`docs/reviews/ui-review-ws-lab-mcp-004-2026-09-13.md`. No BLOCKER. One HIGH: LEARN three-state cards below first canvas.

---

## FIXES

Shortened LEARN intro. Moved AllowTicket / malformed / duplicate-key into the parameter panel. Three relation cards now start at GRID y=440.

---

## PASS-2 UI REVIEW

10/10 tabs. HIGH fixed (`pass2_learn.png` shows GRANTED / KNOWN BUT UNGRANTED / UNKNOWN RESOURCE). Residual MEDIUM/LOW accepted.

---

## SECURITY SEMANTICS REVIEW

UI does not claim: valid argument = authorized resource; tool/scope granted = resource granted; known-but-ungranted = unknown; unknown_resource = DENY; ALLOW = execution; fail-open = grant changed; mcp.started = success; mcp.failed = prevention; no Splunk event = blocked; Splunk authorized the resource; SIMULATED = OBSERVED.

---

## TEST RESULTS

`.venv/bin/python -m pytest -q --tb=line -m "not live_ollama and not live_splunk"`  
**245 passed, 2 deselected** (2026-09-13, this session).

XML/JSON parse and match. Ten tabs. Tokens resolve. Search references exist. `Q-MCP-RESOURCE-AUTHZ` bound. Existing Q-MCP SPL files unchanged. DET-MCP-001 unchanged. No DET-MCP-004. Schema remains 1.2.0.

Playwright: 10/10 tabs, five token values MEASURED (`docs/screenshots/lab-mcp-004/pass2_validation.json`).

---

## FILES CHANGED

- `learning/level_1/LAB-MCP-004/README.md`
- `learning/level_1/LAB-MCP-004/workshop.md`
- `learning/level_1/LAB-MCP-004/evidence.md`
- `learning/level_1/LAB-MCP-004/knowledge-check.md`
- `learning/level_1/LAB-MCP-004/dashboard.md`
- `learning/level_1/LAB-MCP-004/dashboard.definition.json`
- `splunk_app/agentsec/default/data/ui/views/ws_lab_mcp_004.xml`
- `splunk_app/agentsec/default/data/ui/nav/default.xml`
- `scripts/build_lab_mcp_004_dashboard.py`
- `scripts/capture_lab_mcp_004_screenshots.py`
- `scripts/lab-up.sh`, `scripts/lab-ready.sh`, `scripts/splunk_app_init.sh`
- `tests/splunk/test_lab_mcp_004_dashboard.py`
- `tests/workshops/test_lab_mcp_004_workshop.py`
- `tests/splunk/test_lab_mcp_004_splunk.py` (allow Studio; still forbid DET-MCP-004)
- `tests/unit/test_splunk_app_init.py`
- `docs/PHASE5D_MCP004_WORKSHOP.md`
- `docs/learning-notes/mcp-resource-workshop.md`
- `docs/reviews/ui-review-ws-lab-mcp-004-2026-09-13.md`
- `docs/screenshots/lab-mcp-004/`
- `docs/IMPLEMENTATION_STATUS.md`

Not changed: runtime authorize, schema 1.2.0, DET-MCP-001.spl, Q-MCP-*.spl logic.

---

## LIMITATIONS

- CTRL-MCP-001 is a lab allow-list, not production IAM.
- JSON-RPC is in-process.
- Runtime handler count remains authoritative for non-execution.
- DETECT live 0 rows ≠ independent non-execution.
- Resource positive control is **SIMULATED** (`makeresults`).
- DET-MCP-001 correlates `run_id` + tool (one invoke per canonical run).
- Duplicate-key rejection has no control.decision event.
- After `--refresh-app`, Splunk Web served the view and indexed 5C data remained searchable; **HEC health did not return HTTP 200** (empty reply). Do not claim the local lab was READY for new ingest during pass-2. No new LIVE specimens were generated in 5D.
- Playwright captures the first Studio canvas (1440×1100), not inner GRID scroll.

---

## PHASE 5D VERDICT

**VALIDATED** for the workshop/Dashboard Studio teaching surface on Phase 5C LIVE indexed copies.

STOP. Do not start MCP-005. Do not create DET-MCP-004. Do not modify runtime authorization. Do not modify schema 1.2.0.
