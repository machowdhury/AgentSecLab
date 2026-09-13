# Phase 2C.3 LAB-PI-001 Dashboard Studio

**Date:** 2026-09-11  
**Status:** COMPLETE for Dashboard Studio workshop UI (screenshot + token/tab validation)  
**Schema:** `agentsec.security_event` 1.0.0 — unchanged  
**View:** `ws_lab_pi_001`  
**Layout:** Dashboard Studio GRID (tabs = workshop steps)  
**SPL:** existing LAB-PI-001 searches only. No new investigation queries. No detections. No attacks.

Evidence class: dashboard JSON/XML is **DOCUMENTED**. Binding equality vs `.spl` files is **MEASURED** by pytest. Splunk Web load, ten tabs, and four token values are **OBSERVED / MEASURED** in `docs/screenshots/lab-pi-001/pass2_validation.json`. Indexed Q-* rows on this volume were empty in pass-2 screenshots; that is not a new MEASURED experiment.

## What was built

One workshop dashboard for LAB-PI-001. Ten GRID tabs: LEARN, BASELINE, ATTACK, OBSERVE, HUNT, DETECT, DEFEND, RETEST, COMPARE, PROVE.

Tabs are the twelve-row workshop contract split for readability. A single unscrolled 12-row canvas would violate the design-system rule against crowded pages. Absolute layout was not used.

## SPL binding

| Datasource | Source file | Token |
|------------|-------------|-------|
| `ds_q_run_events` | `Q-RUN-EVENTS.spl` | `$run_id$` |
| `ds_q_control` / RETEST reuse | `Q-CONTROL-DECISION.spl` | `$run_id$` |
| `ds_q_llm` / RETEST reuse | `Q-LLM-EXECUTED.spl` | `$run_id$` |
| `ds_q_after_deny` | `Q-LLM-AFTER-DENY.spl` | `$run_id$` |
| `ds_q_after_deny_sim` | `Q-LLM-AFTER-DENY-POSITIVE-CONTROL.spl` | none (`makeresults`) |
| COMPARE ×3 control | `Q-CONTROL-DECISION.spl` | `$baseline_run_id$` / `$attack_run_id$` / `$retest_run_id$` |
| COMPARE ×3 llm | `Q-LLM-EXECUTED.spl` | same three tokens |

Only change from validated files: `__RUN_ID__` → `"$token$"` so an empty Hunt Submit is a zero-row search, not a parse error.

## Security assumptions

- Splunk still does not authorize Ollama.
- DETECT is a contract hunt. The SIMULATED panel is labeled SIMULATED.
- COMPARE defaults to previously MEASURED specimen ids; they are examples, not new runs.
- `78f05d1b-…` remains DENY/`ATTACK` and is not a RETEST token default.

## Tests

`tests/splunk/test_lab_pi_001_dashboard.py` — JSON parses; XML CDATA matches; GRID; tabs; tokens; datasource queries equal bound `.spl`; every viz is laid out; every datasource is used; no notable/alert/MLTK/MCP/RAG.

Pytest does not prove the dashboard loaded in Splunk Web.

## Live Splunk UI

Install is **LOCAL compose**, not a manual copy. `./scripts/lab-up.sh` stages `ws_lab_pi_001.xml` into named volume `splunk_app_agentsec` before Splunk is healthy. After XML edits: `./scripts/lab-up.sh --refresh-app`. See `docs/LOCAL_DOCKER_LAB.md`.

**Screenshot review (2026-09-11):** Playwright opened `http://127.0.0.1:8000/en-US/app/agentsec/ws_lab_pi_001`. Pass 1 review: `docs/reviews/ui-review-ws-lab-pi-001-2026-09-11.md`. Pass 2 after BLOCKER/HIGH fixes:

- 10/10 tabs OBSERVED
- Four tokens MEASURED at specimen UUIDs (`pass2_validation.json`)
- SIMULATED positive-control table OBSERVED
- Indexed hunt tables empty on this volume (not claimed as missing history without a live count)

Parent visual contract: `docs/AGENTSEC_DESIGN_SYSTEM.md`. Provisioning design unchanged.

## Limitations

- Token fields still visually clip 36-character UUIDs at 1440px; values are complete (Playwright). Copy from LEARN.
- Placeholder `savedsearches.conf` Q-RUN / Q-DENY remain disabled and unvalidated; they are not this dashboard.
- No time picker: validated SPL uses `earliest=0`.
- `--refresh-app` restarts Splunk; HEC can lag behind Splunk Web. Dashboard screenshots do not prove HEC health.
