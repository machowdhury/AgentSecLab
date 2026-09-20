# LAB-PI-001 Dashboard Studio (WS-001)

**View:** `ws_lab_pi_001` in the `agentsec` app  
**Layout:** Dashboard Studio GRID, one dashboard, ten tabs  
**SPL:** Phase 2C.1 validated searches only  
**Not:** a detection pack, Attack Service, AcmeBank, MCP, A2A, RAG, or MLTK

Definition: `dashboard.definition.json` (source) and `splunk_app/agentsec/default/data/ui/views/ws_lab_pi_001.xml` (what Splunk loads). Rebuild both with `python scripts/build_lab_pi_001_dashboard.py`.

## WHAT IS IT?

A tabbed GRID workshop that walks LEARN → PROVE using tables bound to the four validated investigation queries. Markdown teaches. Tables show telemetry.

## Tokens

- `run_id` — global Investigate specimen (canonical REPLAY). Default BASELINE id.

HUNT is a stacked notebook (Path A question, Hint 1, Hint 2, Path B solution, bound table × six investigations). Studio 10.2 hide/show overlapped Path B onto the question origin, so this lab does **not** use `gi_id` / `reveal` visibility tokens. No custom JavaScript.

Fresh LIVE `run.id` is **not** written into Studio tokens. Use Attack Service Search handoff.

The only SPL edit is replacing `__RUN_ID__` with `"$token$"` or a canonical literal. `earliest=0` stays. No time picker (it would fight the validated window).

## How to use it

1. Open Splunk → AgentSec → **LAB-PI-001 Direct Prompt Injection**.
2. Submit. COMPARE tables should fill from the default specimen ids if those events are still in `index=agentsec_telemetry`.
3. Paste a Hunt `run.id` to walk BASELINE / OBSERVE / HUNT / DETECT / RETEST.
4. DETECT right table is **SIMULATED** `makeresults`. Left table is indexed.

Splunk does not fire ATK-002 and does not switch `AGENTSEC_SECURITY_PROFILE`.

## Empty states

An empty Hunt table means no matching events for that token, not that the bank is safe. Check AcmeBank, `artifacts/<run-id>/`, then `export.json`.

## What this dashboard is not allowed to claim

- INV-008 is proven because the dashboard exists
- Zero `Q-LLM-AFTER-DENY` rows independently prove non-execution
- ALLOW means Ollama ran
- The SIMULATED fixture is OBSERVED runtime
- `78f05d1b-…` is RETEST
