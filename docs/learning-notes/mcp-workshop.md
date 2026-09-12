# MCP workshop 101

**Status:** Phase 3D Dashboard Studio workshop `ws_lab_mcp_001`.  
**Parents:** `docs/PHASE3D_MCP_WORKSHOP.md`, `learning/level_1/LAB-MCP-001/`.

---

## WHAT IS IT?

A ten-tab Splunk Dashboard Studio class for LAB-MCP-001. Markdown teaches. Tables run the Phase 3C Q-MCP searches. What Happened is a table of indexed fields, not a generated story.

## WHY DOES IT EXIST?

Runtime and SPL were already proven. Learners still need a path they can click: granted tool, unauthorized tool in `vulnerable`, same request in `defended`.

## HOW DOES IT WORK?

Tokens: Hunt defaults to BASELINE `163d11e2-e751-4282-9406-19b490542ed4`. BASELINE / ATTACK / RETEST tokens bind the three Phase 3C specimens so those tabs show real data. Q-MCP files are unchanged except `__RUN_ID__` → `"$token$"`. DETECT right table is **SIMULATED** `makeresults`. What Happened is split so `execution_state` and `result_trust` stay readable. Table captions describe populated data; empty teaching is `noDataMessage`.

## WHERE DOES IT SIT IN AGENTSEC?

After 3B runtime and 3C hunts. Visual sibling of LAB-PI-001. Splunk still does not authorize.

## WHAT IS THE TRUST BOUNDARY?

`acmebank.mcp.authorize` then `mcp.tool.execute`. The dashboard is observe-only.

## WHAT COULD AN ATTACKER CONTROL?

Still only the MCP HTTP body fields. Not tokens, not profile, not the control verdict.

## WHAT CAN GO WRONG?

- Reading ALLOW as execution
- Calling unknown-tool ERROR a DENY
- Treating empty Q-MCP-TOOL as blocked
- Treating SIMULATED as OBSERVED
- Inferring prevention from missing Splunk rows

## WHAT TELEMETRY SHOULD EXIST?

Same as Phase 3C. Handler count is runtime. Splunk is a copy.

## HOW WILL SPLUNK SHOW IT?

`ws_lab_mcp_001` ten GRID tabs. Empty tables stay visible and explain themselves.

## WHAT CONTROL COULD CHANGE THE RESULT?

`AGENTSEC_SECURITY_PROFILE` on CTRL-MCP-001. The dashboard cannot switch it.

## WHAT TEST PROVES THE LOGIC?

Pytest: JSON/XML match, tabs, tokens, SPL bind-only, hideWhenNoData false. Playwright: ten tabs and token values. Runtime spy still proves RETEST non-execution.

---

## What I should now be able to explain

1. Why Hunt defaults to the BASELINE specimen.
2. Why BASELINE / ATTACK / RETEST tabs use their own tokens.
3. Why ALLOW ≠ `mcp.started`.
4. Why RETEST empty Q-MCP-TOOL is corroboration, not spy proof.
5. Why DETECT right is SIMULATED.
6. Why What Happened must not say DENIED unless `decision` is DENY.
7. Why handler count is not a Splunk field.
8. Why this page is not a detection.
9. Why `lookup_customer_tier` is unauthorized invocation, not “malware.”
10. Why tool results stay `untrusted_data`.
