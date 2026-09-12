# LAB-PI-001 Dashboard Studio (Phase 2C.3)

## WHAT IS IT?

One Splunk Dashboard Studio workshop (`ws_lab_pi_001`) for Direct Prompt Injection. Ten GRID tabs follow the existing lab flow. Tables run the four already-validated investigation searches. Markdown teaches. It is not a detection.

## WHY DOES IT EXIST?

Phase 2C.1 proved the questions. Phase 2C.2 proved when to ask them. Analysts still need a page that puts query + explanation in the lifecycle order without inventing a fifth search.

## HOW DOES IT WORK?

Hunt `run.id` drives OBSERVE / HUNT / DETECT / RETEST and defaults to the validated BASELINE specimen so Studio tables run (empty token is an error graphic, not a teaching empty). COMPARE has three specimen tokens (BASELINE / ATTACK / RETEST). DETECT also shows the SIMULATED `makeresults` fixture, labeled SIMULATED.

The only SPL change is `__RUN_ID__` → `"$token$"`.

## WHERE DOES IT SIT IN AGENTSEC?

After workshop logic (2C.2). Inside the `agentsec` Splunk app. AcmeBank remains the enforcement point. Splunk remains observe-only.

## WHAT IS THE TRUST BOUNDARY?

Unchanged: `acmebank.http_api` / `acmebank.llm_call`. The dashboard cannot ALLOW a loan.

## WHAT COULD AN ATTACKER CONTROL?

Still `input` / `user_id`. Not dashboard JSON, not tokens, not profile.

## WHAT CAN GO WRONG?

Treating an empty Hunt table as DENY. Treating COMPARE defaults as new live experiments. Treating the SIMULATED table as OBSERVED. Calling the dashboard proof of INV-008. Relabeling `78f05d1b-…` as RETEST.

## WHAT TELEMETRY SHOULD EXIST?

Schema 1.0.0. No new event types. Same Q-* fields as Phase 2C.1.

## HOW WILL SPLUNK SHOW IT?

GRID tables and markdown. No charts. No color-only severity. Empty tables stay visible.

## WHAT CONTROL COULD CHANGE THE RESULT?

CTRL-INPUT-001 / security profile on AcmeBank. Not this view.

## WHAT TEST PROVES THE LOGIC?

`tests/splunk/test_lab_pi_001_dashboard.py` proves the definition binds the validated files. It does not prove Splunk Web rendered the page.

## What I should now be able to explain

1. Why this dashboard uses tabs instead of one 12-row canvas.
2. Why Hunt `run.id` defaults to the BASELINE specimen (Studio empty-token state).
3. Why COMPARE tokens have defaults.
4. Why DETECT has two tables.
5. Why `__RUN_ID__` is wrapped as `"$token$"`.
6. Why there is no time picker.
7. Why Splunk still cannot DENY the loan.
8. Why ALLOW tables and LLM tables are both required on COMPARE.
9. Why `78f05d1b-…` is mentioned but not a COMPARE default.
10. What would have justified a new `.spl` file — and why none was added.
