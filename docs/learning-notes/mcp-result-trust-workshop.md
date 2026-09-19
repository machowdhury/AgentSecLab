# MCP result-trust workshop 101

**Status:** Phase 6D Dashboard Studio workshop `ws_lab_mcp_005`.  
**Parents:** `docs/PHASE6D_MCP005_WORKSHOP.md`, `learning/level_1/LAB-MCP-005/`.

---

## WHAT IS IT?

A ten-tab Splunk Dashboard Studio class for LAB-MCP-005. It teaches **AUTHORIZED TOOL ≠ AUTHORITATIVE RESULT** and **DATA ≠ AUTHORITY**. Markdown teaches. Tables run Phase 6C-validated Q-MCP searches plus `Q-MCP-RESULT-AUTHORITY`. What Happened is that hunt (one indexed row per run), not a generated story.

---

## WHY DOES IT EXIST?

LAB-MCP-001–004 authorized the invoke (tool, then scope, then resource). Learners still need a clickable path for INV-002 **after** a legitimate `mcp.completed`: can returned bytes change future authority? Runtime and Splunk reuse were already proven in 6B/6C. The workshop is the teaching surface, not a new control and not a new detector.

---

## HOW DOES IT WORK?

Tokens: Hunt defaults to BASELINE `3013aa39-fe08-4b58-9898-f3abb092ac06`. BASELINE / ATTACK / RETEST tokens bind the Phase 6C LIVE specimens. Q-MCP files are unchanged except `__RUN_ID__` → `"$token$"`. `Q-MCP-RESULT-AUTHORITY` is the primary hunt. DETECT right table is **SIMULATED** `makeresults` (`DET-MCP-001-POSITIVE-CONTROL`). Live DETECT left table is `Q-MCP-AFTER-DENY` (0 rows on MCP-005 LIVE runs). Empty teaching is `noDataMessage`.

The first hop is always granted `lookup_policy` at `policy:read` on `lending-basics`. MCP-005 begins after that execution.

---

## WHERE DOES IT SIT IN AGENTSEC?

After 6B runtime and 6C hunts. Visual sibling of `ws_lab_mcp_004`. Splunk still does not authorize. No DET-MCP-005. No MCP-006.

---

## WHAT IS THE TRUST BOUNDARY?

TOOL RESULT = DATA. FOLLOW-ON OPERATION = REQUIRES AUTHORIZATION. CTRL-MCP-RESULT-001 classifies; it does not grant. Hop-1 CTRL-MCP-001 is the real follow-on gate. The dashboard is observe-only.

---

## WHAT COULD AN ATTACKER CONTROL?

Tool-result **content** after a legitimate invoke (here, a MALICIOUS fixture). Not the coded server grant. Not `allowed_tools` (that field is not even indexed). Not Splunk.

---

## WHAT CAN GO WRONG?

- Treating an authorized tool as an authoritative result
- Collapsing provenance with authority
- Reading ATTACK follow-on ALLOW as a server grant of `lookup_customer_tier`
- Treating a matching hash as trust
- Treating missing `mcp.started` as proof the handler never ran
- Treating DET-MCP-001 silence as “no security violation”
- Creating DET-MCP-005 to make the workshop look complete
- Inventing `allowed_tools` or `gen_ai.tool.call.id`
- Reconstructing bounded preview (`lookup_customer_tie`)
- Teaching prompt-injection resistance instead of an authorization boundary

---

## WHAT TELEMETRY SHOULD EXIST?

Same as Phase 6C. Handler count is runtime. Splunk is a copy. `Q-MCP-RESULT-AUTHORITY` labels derived_authority present/absent and follow-on observation. DET-MCP-001 still hunts DENY then later `mcp.started`.

---

## HOW WILL SPLUNK SHOW IT?

`ws_lab_mcp_005` ten GRID tabs. Empty tables stay visible and explain themselves. DETECT labels SIMULATED on the right-hand table and teaches **DETECTION ANALYZED — NO NEW DETECTOR**. COMPARE is three aligned cards.

---

## WHAT CONTROL COULD CHANGE THE RESULT?

`AGENTSEC_SECURITY_PROFILE`. Vulnerable overlay may ALLOW result-derived follow-on. Defended leaves RESULT-001 as OBSERVE and hop-1 DENY `tool_not_granted`. The dashboard cannot switch the profile. Splunk cannot deny the follow-on.

---

## WHAT TEST PROVES THE LOGIC?

Pytest: JSON/XML match, tabs, tokens, SPL bind-only, no DET-MCP-005, rejected FOLLOWON absent as a datasource, hideWhenNoData false, forbidden semantic claims. Playwright: ten tabs and four token values. Runtime spy still proves RETEST follow-on handler count 0 (Phase 6B/6C).

---

## What I should now be able to explain

1. Why an authorized tool does not make its result authoritative.
2. The difference between provenance, content, and authority.
3. Why MCP-005 tests INV-002 and begins after a legitimate execution.
4. Why ATTACK follow-on ALLOW is overlay, not server policy.
5. Why RETEST DENYs the same follow-on against the same malicious hash.
6. Why DET-MCP-001 stays silent, and why no DET-MCP-005 was created.
7. Why a matching result hash is identity evidence, not trust.
8. Why runtime handler count is authoritative and Splunk absence is corroboration.
9. Why this lab is an authorization boundary, not prompt-injection resistance.
10. Why repeated same-tool invocations would need stronger correlation than `run.id` + tool name.
