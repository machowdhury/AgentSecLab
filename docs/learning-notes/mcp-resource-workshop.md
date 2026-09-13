# MCP resource workshop 101

**Status:** Phase 5D Dashboard Studio workshop `ws_lab_mcp_004`.  
**Parents:** `docs/PHASE5D_MCP004_WORKSHOP.md`, `learning/level_1/LAB-MCP-004/`.

---

## WHAT IS IT?

A ten-tab Splunk Dashboard Studio class for LAB-MCP-004. It teaches **parameter and resource authorization on a granted MCP tool at a granted scope**. Markdown teaches. Tables run Phase 5C-validated Q-MCP searches plus `Q-MCP-RESOURCE-AUTHZ`. What Happened is indexed fields, not a generated story.

---

## WHY DOES IT EXIST?

LAB-MCP-001 answered “may this agent call this **tool**?” LAB-MCP-003 answered “at this **scope**?” Learners still need a clickable path for the next question: “at this scope, for **this resource**?” Runtime and Splunk reuse were already proven in 5B/5C. The workshop is the teaching surface, not a new control.

---

## HOW DOES IT WORK?

Tokens: Hunt defaults to BASELINE `fb50dcaf-8e84-4a3f-a55b-997c72edbd04`. BASELINE / ATTACK / RETEST / UNKNOWN tokens bind the Phase 5C LIVE specimens. Q-MCP files are unchanged except `__RUN_ID__` → `"$token$"`. `Q-MCP-RESOURCE-AUTHZ` is the primary hunt. DETECT right table is **SIMULATED** `makeresults` (`DET-MCP-001-RESOURCE-POSITIVE-CONTROL`). Live DETECT left table is `Q-MCP-AFTER-DENY` (0 rows on MCP-004 LIVE runs). What Happened is split so identity and decision stay readable. Empty teaching is `noDataMessage`.

The core example is `lookup_policy` at `policy:read`:

- catalog resources: `lending-basics`, `executive-restricted`
- grant: `lending-basics`
- `lending-basics` → known + granted
- `executive-restricted` → known, not granted
- `does-not-exist` → unknown to the catalog

Use the control reason. Do not infer known vs unknown from grant-set membership alone.

---

## WHERE DOES IT SIT IN AGENTSEC?

After 5B runtime and 5C hunts. Visual sibling of `ws_lab_mcp_003`. Splunk still does not authorize. No DET-MCP-004. No MCP-005.

---

## WHAT IS THE TRUST BOUNDARY?

`acmebank.mcp.authorize` (CTRL-MCP-001) then, only on ALLOW, `mcp.tool.execute` using AllowTicket.resource_id. Resource checks happen before the handler. The dashboard is observe-only.

---

## WHAT COULD AN ATTACKER CONTROL?

Still only the MCP HTTP body: `tool`, `arguments`, `requested_scope`, `user_id`. Not the profile, not the grant, not `allowed_resource.ids`, not tokens, not the control verdict. Duplicate JSON keys are rejected before authorize.

---

## WHAT CAN GO WRONG?

- Treating tool granted or scope granted as resource granted
- Collapsing known-but-ungranted with unknown
- Calling unknown-resource ERROR a DENY
- Calling a valid `policy_id` string authorized
- Reading ALLOW as execution or as a rewritten grant
- Treating empty Q-MCP-TOOL as blocked
- Treating SIMULATED as OBSERVED
- Inferring prevention from missing Splunk rows
- Fabricating a control.decision for duplicate-key HTTP rejection

---

## WHAT TELEMETRY SHOULD EXIST?

Same as Phase 5C. Handler count is runtime. Splunk is a copy. `Q-MCP-RESOURCE-AUTHZ` labels `granted` / `known_but_ungranted` / `not_a_grant`. DET-MCP-001 still hunts DENY then later `mcp.started` (any DENY reason).

---

## HOW WILL SPLUNK SHOW IT?

`ws_lab_mcp_004` ten GRID tabs. Empty tables stay visible and explain themselves. DETECT labels SIMULATED on the right-hand table. HUNT shows Q-MCP-SCOPE as contrast (ATTACK scope can still be `granted`).

---

## WHAT CONTROL COULD CHANGE THE RESULT?

`AGENTSEC_SECURITY_PROFILE` on CTRL-MCP-001. Defended DENYs known-but-ungranted resource. Vulnerable labels fail-open for that case only. Unknown catalog tokens stay ERROR. The dashboard cannot switch the profile.

---

## WHAT TEST PROVES THE LOGIC?

Pytest: JSON/XML match, tabs, tokens, SPL bind-only, no DET-MCP-004, hideWhenNoData false, forbidden semantic claims. Playwright: ten tabs and five token values. Runtime spy still proves RETEST handler count 0 (Phase 5B/5C). Live CLI this session: `Q-MCP-RESOURCE-AUTHZ` relations match 5C.

---

## What I should now be able to explain

1. Why LAB-MCP-004 is a different question from LAB-MCP-001 and LAB-MCP-003 even when the tool and scope are the same.
2. Why `executive-restricted` is not malformed, and why it is DENY while `does-not-exist` is ERROR.
3. Why ALLOW does not mean the resource was granted, especially on vulnerable fail-open.
4. Why `allowed_resource.ids` stays `lending-basics` during fail-open.
5. Why arguments identify a resource and cannot widen the grant.
6. Why AllowTicket.resource_id binds check to use.
7. Why runtime handler count is authoritative and Splunk absence is corroboration.
8. Why DET-MCP-001 can be reused and why 0 detector rows is not “system is secure.”
9. Why DET-MCP-001’s `run_id` + tool correlation is enough for one invoke per run and may be insufficient later.
10. Why duplicate-key rejection has no Q-MCP-AUTHZ row.
