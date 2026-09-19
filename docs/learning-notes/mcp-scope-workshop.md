# MCP scope workshop 101

**Status:** Phase 4D Dashboard Studio workshop `ws_lab_mcp_003`.  
**Parents:** `docs/PHASE4D_MCP003_WORKSHOP.md`, `learning/level_1/LAB-MCP-003/`.

---

## WHAT IS IT?

A ten-tab Splunk Dashboard Studio class for LAB-MCP-003. It teaches **scope escalation on a granted MCP tool**. Markdown teaches. Tables run the same Phase 4C-validated Q-MCP searches as LAB-MCP-001. What Happened is indexed fields, not a generated story.

## WHY DOES IT EXIST?

LAB-MCP-001 already answered “may this agent call this **tool**?” Learners still need a clickable path for the next question: “may this agent call this tool **at this requested_scope**?” Runtime and Splunk reuse were already proven in 4B/4C. The workshop is the teaching surface, not a new control.

## HOW DOES IT WORK?

Tokens: Hunt defaults to BASELINE `5b089682-1d5a-49a7-ac43-967265fd6bc6`. BASELINE / ATTACK / RETEST / UNKNOWN tokens bind the Phase 4C LIVE specimens. Q-MCP files are unchanged except `__RUN_ID__` → `"$token$"`. DETECT right table is **SIMULATED** `makeresults` (`DET-MCP-001-SCOPE-POSITIVE-CONTROL`). Live DETECT left table is `Q-MCP-AFTER-DENY` (0 rows on MCP-003 LIVE runs). What Happened is split so identity and decision stay readable. Empty teaching is `noDataMessage`.

The core example is `lookup_policy`:

- catalog: `policy:read`, `policy:restricted:read`
- grant: `policy:read`
- `policy:read` → known + granted
- `policy:restricted:read` → known, not granted
- `policy:write` → unknown to the catalog

Colons are opaque labels. No hierarchy, wildcard, or prefix matching.

## WHERE DOES IT SIT IN AGENTSEC?

After 4B runtime and 4C hunts. Visual sibling of `ws_lab_mcp_001`. Splunk still does not authorize. No DET-MCP-003. No MCP-004.

## WHAT IS THE TRUST BOUNDARY?

`acmebank.mcp.authorize` (CTRL-MCP-001) then, only on ALLOW, `mcp.tool.execute`. Scope checks happen before the handler. The dashboard is observe-only.

## WHAT COULD AN ATTACKER CONTROL?

Still only the MCP HTTP body: `tool`, `arguments`, `requested_scope`, `user_id`. Not the profile, not the grant, not `allowed_scope`, not tokens, not the control verdict.

## WHAT CAN GO WRONG?

- Treating tool granted as every catalog scope granted
- Collapsing known-but-ungranted with unknown
- Calling unknown-scope ERROR a DENY
- Reading ALLOW as execution
- Treating empty Q-MCP-TOOL as blocked
- Treating SIMULATED as OBSERVED
- Inferring prevention from missing Splunk rows
- Thinking fail-open rewrote `allowed_scope`

## WHAT TELEMETRY SHOULD EXIST?

Same as Phase 4C. Handler count is runtime. Splunk is a copy. Q-MCP-SCOPE labels `granted` / `mismatch` / `not_a_grant`. DET-MCP-001 still hunts DENY then later `mcp.started`.

## HOW WILL SPLUNK SHOW IT?

`ws_lab_mcp_003` ten GRID tabs. Empty tables stay visible and explain themselves. DETECT labels SIMULATED on the right-hand table.

## WHAT CONTROL COULD CHANGE THE RESULT?

`AGENTSEC_SECURITY_PROFILE` on CTRL-MCP-001. Defended DENYs known-but-ungranted scope. Vulnerable labels fail-open for that case only. Unknown catalog tokens stay ERROR. The dashboard cannot switch the profile.

## WHAT TEST PROVES THE LOGIC?

Pytest: JSON/XML match, tabs, tokens, SPL bind-only, no DET-MCP-003, hideWhenNoData false, forbidden semantic claims. Playwright: ten tabs and five token values. Runtime spy still proves RETEST handler count 0.

---

## What I should now be able to explain

1. Why LAB-MCP-003 is a different question from LAB-MCP-001 even when the tool is the same.
2. Why `policy:restricted:read` is DENY (known-but-ungranted) and `policy:write` is ERROR (unknown).
3. Why colons are opaque and there is no prefix matching.
4. Why Hunt defaults to the BASELINE specimen.
5. Why ALLOW ≠ `mcp.started` and why ALLOW ≠ success.
6. Why `allowed_scope` stays `policy:read` during vulnerable fail-open.
7. Why arguments cannot grant a broader scope.
8. Why DET-MCP-001 can be reused and why 0 detector rows is not non-execution proof.
9. Why runtime handler count is authoritative and Splunk absence is corroboration.
10. Why the DETECT right-hand table is SIMULATED, not OBSERVED.
