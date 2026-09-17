# MCP confused-deputy workshop 101

**Status:** Phase 7D Dashboard Studio workshop `ws_lab_mcp_006`.  
**Parents:** `docs/PHASE7D_MCP006_WORKSHOP.md`, `learning/level_1/LAB-MCP-006/`.

---

## WHAT IS IT?

A ten-tab Splunk Dashboard Studio class for LAB-MCP-006. It teaches **DEPUTY AUTHORITY ≠ CALLER AUTHORITY** and **DEPUTY AUTHORITY ≠ DELEGATED AUTHORITY**. Markdown teaches. Tables run Phase 7C-validated Q-MCP searches plus `Q-MCP-DELEGATION`. What Happened is that hunt (one indexed row per run), not a generated story.

---

## WHY DOES IT EXIST?

LAB-MCP-001–005 authorized the acting agent more and more contextually (tool, scope, resource, result data). Learners still need a clickable path for INV-001 when one agent acts as deputy for another: did the **caller** actually delegate this operation, or did the deputy spend **ambient** authority? Runtime and Splunk reuse were already proven in 7B/7C. The workshop is the teaching surface, not a new control and not a new detector.

---

## HOW DOES IT WORK?

Tokens: Hunt defaults to BASELINE `1cf98c4d-1bd8-4df5-be70-b82419e2c2b2`. BASELINE / ATTACK / RETEST tokens bind the Phase 7C LIVE specimens. Q-MCP files are unchanged except `__RUN_ID__` → `"$token$"`. `Q-MCP-DELEGATION` is the primary hunt. DETECT right table is **SIMULATED** `makeresults` (`DET-MCP-001-POSITIVE-CONTROL`). Live DETECT left table is `Q-MCP-AFTER-DENY` (0 rows on MCP-006 LIVE runs). Empty teaching is `noDataMessage`.

BASELINE is granted `lookup_policy`. ATTACK/RETEST request `lookup_customer_tier` with the same hash. Not every delegated-agent workflow is a confused-deputy attack.

---

## WHERE DOES IT SIT IN AGENTSEC?

After 7B runtime and 7C hunts. Visual sibling of `ws_lab_mcp_005`. Splunk still does not authorize. No DET-MCP-006. No MCP-007.

---

## WHAT IS THE TRUST BOUNDARY?

CALLER REQUEST → CTRL-DELEGATION-001 → (only if ALLOW) CTRL-MCP-001 → (only if ALLOW) TOOL HANDLER. The dashboard is observe-only.

---

## WHAT COULD AN ATTACKER CONTROL?

The **requested operation** a caller asks a deputy to perform (here, Credit asking Compliance for `lookup_customer_tier`). Not the deputy’s coded ambient grant. Not `allowed_tools` (that field is not even indexed). Not Splunk.

---

## WHAT CAN GO WRONG?

- Treating deputy possession as caller authorization
- Collapsing ambient authority with delegated authority
- Reading ATTACK MCP ALLOW as a caller grant of `lookup_customer_tier`
- Treating missing `mcp.started` as proof the handler never ran
- Treating DET-MCP-001 silence as “no confused-deputy attack”
- Creating DET-MCP-006 to make the workshop look complete
- Inventing `allowed_tools` or a hop-1 deputy on RETEST
- Teaching every delegated-agent workflow as an attack

---

## WHAT TELEMETRY SHOULD EXIST?

Same as Phase 7C. Handler count is runtime. Splunk is a copy. `Q-MCP-DELEGATION` labels `authority.source`, caller/deputy observation, CTRL-DELEGATION-001, downstream MCP, and execution observation. DET-MCP-001 still hunts DENY then later `mcp.started`.

---

## HOW WILL SPLUNK SHOW IT?

`ws_lab_mcp_006` ten GRID tabs. Empty tables stay visible and explain themselves. DETECT labels SIMULATED on the right-hand table and teaches **DETECTION ANALYZED — NO NEW DETECTOR**. COMPARE is three aligned cards.

---

## WHAT CONTROL COULD CHANGE THE RESULT?

`AGENTSEC_SECURITY_PROFILE`. Vulnerable CTRL-DELEGATION-001 may ALLOW with `authority.source=ambient_deputy`. Defended DENY `delegated_authority_not_granted`. The dashboard cannot switch the profile. Splunk cannot deny the deputy call.

---

## WHAT TEST PROVES THE LOGIC?

Pytest: JSON/XML match, tabs, tokens, SPL bind-only, no DET-MCP-006, rejected hunts absent as datasources, hideWhenNoData false, forbidden semantic claims. Playwright: ten tabs and four token values. Runtime spy still proves RETEST handler count 0 (Phase 7B/7C).

---

## What I should now be able to explain

1. Why the deputy can possess more authority than the caller.
2. Why ambient authority is not delegated authority.
3. Why MCP-006 tests INV-001 at the caller/deputy boundary.
4. Why ATTACK CTRL-DELEGATION-001 ALLOW is fail-open, not caller grant.
5. Why RETEST DENYs the same request against the same hash.
6. Why DET-MCP-001 stays silent, and why no DET-MCP-006 was created.
7. Why runtime handler count is authoritative and Splunk absence is corroboration.
8. Why downstream MCP ALLOW is not caller authorization.
9. Why execution is not proof of valid delegation.
10. What a SOC would hunt next when DET-MCP-001 is silent.
