# Phase 3D — LAB-MCP-001 workshop and Dashboard Studio

**Date:** 2026-09-11 (workshop build); screenshots 2026-09-12 local lab  
**Status:** **VALIDATED** for the learner-facing workshop UI (not a detection pack; not MCP-003+)  
**Schema:** `agentsec.security_event` **1.1.0** — field meanings unchanged  
**View:** `ws_lab_mcp_001`  
**Layout:** Dashboard Studio GRID (tabs = workshop steps)  
**SPL:** Phase 3C validated Q-MCP searches. Token bind only (`__RUN_ID__` → `"$token$"`). Dashboard-only display searches reuse the same index, `event.name` filters, and `mvindex(mvdedup(...),0)` collapse. Q-MCP logic was not rewritten.

Evidence class: dashboard JSON/XML is **DOCUMENTED**. Binding equality vs `.spl` files is **MEASURED** by pytest. Splunk Web load, ten tabs, and four token values are **OBSERVED / MEASURED** in `docs/screenshots/lab-mcp-001/pass2_validation.json`. Indexed BASELINE / ATTACK / RETEST rows on this volume are **OBSERVED** in pass-2 screenshots. Runtime handler counts remain Phase 3B/3C **MEASURED** facts. DETECT positive control is **SIMULATED**.

Runtime remains authoritative. Splunk is corroboration.

Do **not** treat this document as a detection, Cisco integration, MLTK, or MCP-003+ delivery.

---

## What was built

One workshop dashboard for LAB-MCP-001. Ten GRID tabs: LEARN, BASELINE, ATTACK, OBSERVE, HUNT, DETECT, DEFEND, RETEST, COMPARE, PROVE.

Single builder: `scripts/build_lab_mcp_001_dashboard.py` writes both `learning/level_1/LAB-MCP-001/dashboard.definition.json` and `splunk_app/agentsec/default/data/ui/views/ws_lab_mcp_001.xml`. Do not hand-maintain two definitions.

Visual sibling of LAB-PI-001. Palette from `docs/AGENTSEC_DESIGN_SYSTEM.md`. No neon, no extra charts, no MLTK purple.

---

## Workshop flow

| Tab | Teaching | Evidence on this volume |
|-----|----------|-------------------------|
| LEARN | Trust path; registered vs granted; ALLOW ≠ execution; `untrusted_data`; in-process JSON-RPC `tools/call` | Markdown + full specimen UUIDs |
| BASELINE | Granted `lookup_policy` / `policy:read` / defended | Indexed ALLOW, `mcp.completed`, handler count **1** (runtime) |
| ATTACK | Registered, not granted `lookup_customer_tier`; vulnerable labeled fail-open | Indexed ALLOW `vulnerable_profile_fail_open…`, `mcp.completed`, handler **1** |
| OBSERVE | Sequence: `control.decision` before `mcp.started` | Sequences 3 → 4 → 5 on Hunt=BASELINE |
| HUNT | Q-MCP-WHO / SCOPE / PARAMS / EXECUTED / RESULT / RESULT-TRUST | Indexed BASELINE rows |
| DETECT | Contract hunt, not DET-001 | Q-MCP-AFTER-DENY **0** rows; positive control **SIMULATED** |
| DEFEND | CTRL-MCP-001 lab allow-list, control before handler | Markdown only |
| RETEST | Same ungranted tool, defended | Indexed DENY `tool_not_granted`, `no_mcp_execution_event`, handler **0** |
| COMPARE | Same known-ungranted request: fail-open executes; defended does not | Markdown + AUTHZ ALLOW / ALLOW / DENY |
| PROVE | Five evidence layers; knowledge-check prompts | Hunt What Happened on BASELINE default |

Story: **unauthorized invocation**, not a malicious tool.

---

## Dashboard structure

Tokens:

| Token | Default | Used on |
|-------|---------|---------|
| `run_id` (Hunt) | `163d11e2-e751-4282-9406-19b490542ed4` | OBSERVE, HUNT, DETECT, PROVE What Happened |
| `baseline_run_id` | same BASELINE UUID | BASELINE tab, COMPARE |
| `attack_run_id` | `5e8f55f3-eb46-47ee-b979-b72d9c9b1f49` | ATTACK tab, COMPARE |
| `retest_run_id` | `7a1d37b5-d589-4dfd-8322-25ebd0152dbc` | RETEST tab, COMPARE |

Hunt defaults to BASELINE so the dashboard does not open on an empty-token error.

Q-MCP datasources bind the validated files. Extra display searches: ordered OBSERVE sequence; split What Happened (identity + decision).

---

## BASELINE result (OBSERVED in Studio)

Run `163d11e2-e751-4282-9406-19b490542ed4`. Profile `defended`. Mode `BASELINE`. Tool `lookup_policy`. Decision **ALLOW** `tool_granted`. Scopes both `policy:read`. `execution_state=mcp.completed`. `result_trust=untrusted_data`. Runtime handler count **1** (Phase 3C). ALLOW is not treated as execution; `mcp.started` is.

---

## ATTACK result (OBSERVED in Studio)

Run `5e8f55f3-eb46-47ee-b979-b72d9c9b1f49`. Profile `vulnerable`. Mode `ATTACK`. Tool `lookup_customer_tier` (registered, not granted). Decision **ALLOW** with labeled fail-open reason. Requested `customer:read`, allowed still `policy:read`. `execution_state=mcp.completed`. `result_trust=untrusted_data`. Runtime handler count **1**. Controlled lab authorization failure, not a production exploit.

---

## RETEST result (OBSERVED in Studio)

Run `7a1d37b5-d589-4dfd-8322-25ebd0152dbc`. Profile `defended`. Mode `RETEST`. Same tool. Decision **DENY** `tool_not_granted`. `execution_state=no_mcp_execution_event`. Outcome `prevented`. `result_trust=no_completed_result`. Runtime handler count **0** is authoritative non-execution. Splunk absence of `mcp.started` is corroboration on a complete copy.

---

## What Happened result

Two indexed-field tables (not LLM prose): identity (`run_id`, profile, mode, agent, tool) and decision (`decision`, reason, scopes, `execution_state`, outcome, `result_trust`). Pass-2 screenshots show BASELINE ALLOW/`mcp.completed`, ATTACK fail-open ALLOW/`mcp.completed`, RETEST DENY/`no_mcp_execution_event`. The UI does not invent DENY or executed from an empty table.

---

## COMPARE result

Markdown states registered/granted/decision/reason/`mcp.started`/terminal event/runtime handler count/`operation.executed`/outcome for all three specimens. AUTHZ tables: ALLOW `tool_granted` · ALLOW fail-open · DENY `tool_not_granted`. Core lesson: same known-ungranted request; vulnerable labeled fail-open ALLOW executes; defended DENY does not. Status is text, not color alone.

---

## DETECT / positive control result

Left: Q-MCP-AFTER-DENY on Hunt=BASELINE → Studio empty graphic + caption “Indexed invariant hunt. Validated specimens: 0 rows.” That is **no indexed violation found**, not independent proof of non-execution.

Right: Q-MCP-AFTER-DENY-POSITIVE-CONTROL title includes **SIMULATED**. One `makeresults` fixture row labeled SIMULATED. Not indexed. Not OBSERVED runtime.

---

## Empty-state result

Tables use `hideWhenNoData=false`. Populated captions no longer claim “No indexed … was found” (pass-1 BLOCKER). Empty teaching is `options.noDataMessage` plus tab markdown. DETECT left empty copy is not “Tool was blocked.” Incomplete Hunt ids stay a neutral instructional state (`EMPTY_HUNT`).

---

## Accessibility result

- Tab labels exist; Playwright clicked all 10.
- Inputs labeled Hunt / BASELINE / ATTACK / RETEST.
- ALLOW / DENY / SIMULATED / modes are words, not color-only.
- Full UUIDs are in LEARN (and PROVE) markdown; token fields still ellipsis at 1440px; Playwright reads complete values.
- Markdown `fontSize: large`.
- Do **not** claim WCAG certification. Splunk chrome (Submit green, focus rings, tab order) is not restyled.

---

## Pass-1 UI review

`docs/reviews/ui-review-ws-lab-mcp-001-2026-09-11.md`

- **BLOCKER:** empty-state copy used as always-visible table caption on populated tables.
- **HIGH:** What Happened columns clipped `execution_state` / result trust; Q-MCP-EXECUTED visible `executed=false` read as non-execution; specimen UUIDs below LEARN fold.

---

## BLOCKER/HIGH fixes

1. `description` = populated caption; `noDataMessage` = empty teaching.
2. Split What Happened into identity + decision tables.
3. Caption Q-MCP-EXECUTED: control `executed` is not handler execution; read `has_started` / `execution_state`. Q-MCP SPL unchanged.
4. Move Phase 3C UUIDs to the top of LEARN.

---

## Pass-2 UI review

10/10 tabs OBSERVED. Four token values MEASURED. BLOCKER/HIGH addressed. Residual MEDIUM/LOW: Studio orange empty chrome on DETECT; SIMULATED header clip; token ellipsis; COMPARE EXECUTED tables below first viewport.

---

## Security semantics review

Verified against pass-2 UI copy and JSON (not a new runtime experiment):

| Forbidden claim | UI behavior |
|-----------------|-------------|
| ALLOW = executed | LEARN / BASELINE / HUNT / COMPARE state ALLOW is the control decision; execution begins at `mcp.started` |
| `mcp.started` = success | Copy: `mcp.completed` is success of a begun call |
| `mcp.failed` = prevented | Copy: `mcp.failed` is execution then error, not prevention |
| no Splunk row = DENY | Empty copy and HUNT markdown forbid this |
| unknown tool = DENY | LEARN / DEFEND: not registered → ERROR |
| known-ungranted tool = ERROR | LEARN / ATTACK / RETEST: registered + not granted → DENY |
| Splunk authorized the action | Dashboard description: Splunk does not ALLOW or DENY a tool |
| SIMULATED = OBSERVED runtime | DETECT right title and caption: SIMULATED `makeresults`, not indexed |

CTRL-MCP-001, known-ungranted=DENY, unknown=ERROR, ALLOW≠execution, `mcp.failed`≠prevention: unchanged.

---

## Files changed (Phase 3D)

- `scripts/build_lab_mcp_001_dashboard.py`
- `scripts/capture_lab_mcp_001_screenshots.py`
- `learning/level_1/LAB-MCP-001/` workshop docs + `dashboard.definition.json`
- `splunk_app/agentsec/default/data/ui/views/ws_lab_mcp_001.xml` + nav entry
- `tests/splunk/test_lab_mcp_001_dashboard.py`
- `tests/workshops/test_lab_mcp_001_workshop.py`
- `docs/reviews/ui-review-ws-lab-mcp-001-2026-09-11.md`
- `docs/screenshots/lab-mcp-001/`
- `docs/learning-notes/mcp-workshop.md`
- this file; `docs/IMPLEMENTATION_STATUS.md`

Q-MCP `.spl` files, schema 1.1.0 meanings, MCP authorize semantics, CTRL-MCP-001: **not** changed in this phase.

---

## Tests

`tests/splunk/test_lab_mcp_001_dashboard.py` — JSON parses; XML CDATA matches; GRID; tabs; tokens; datasource queries equal bound `.spl`; display searches do not join/transaction; empty copy not used as populated caption; What Happened split.

`tests/workshops/test_lab_mcp_001_workshop.py` — ten `##` steps; knowledge-check Questions before Answers; evidence hierarchy; SIMULATED not OBSERVED.

Pytest does not prove the dashboard loaded in Splunk Web. That is Playwright `pass2_validation.json`.

Full suite (this session): **131 passed**, 2 deselected (`not live_ollama and not live_splunk`).

---

## Limitations

- Transport is in-process JSON-RPC `tools/call`, not stdio/HTTP MCP.
- CTRL-MCP-001 is a lab allow-list, not production IAM.
- Q-MCP-AFTER-DENY zero rows ≠ independent non-execution.
- Positive control is SIMULATED.
- Token fields visually clip UUIDs at 1440px (same Studio limit as LAB-PI-001).
- `--refresh-app` restarts Splunk; HEC can lag behind Splunk Web. Screenshots do not prove HEC health.
- No detections, no MCP-003 / MCP-004 / MCP-005 / MCP-006, no Cisco, no MLTK, no attack chains.

---

## Phase 3D verdict

**VALIDATED** for LAB-MCP-001 workshop + Dashboard Studio `ws_lab_mcp_001`: contracts inspected, ten-step GRID workshop shipped, Q-MCP bind-only, three Phase 3C specimens render, SIMULATED labeled, BLOCKER/HIGH UI findings fixed, security-semantics copy holds, pytest MEASURED for JSON/XML/workshop contracts, Splunk Web OBSERVED.

Not COMPLETE as a detection product. Not automatically tagged COMPLETE. Stop. Do not implement detections. Do not start MCP-003.
