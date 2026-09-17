# MCP catalog / tool-description workshop 101

**Status:** Phase 8E Dashboard Studio workshop `ws_lab_mcp_catalog`.  
**Parents:** `docs/PHASE8E_MCP_CATALOG_WORKSHOP.md`, `learning/level_1/LAB-MCP-CATALOG/`.

---

## WHAT IS IT?

A ten-tab Splunk Dashboard Studio class for LAB-MCP-CATALOG. It teaches that a tool can be legitimate, its first call can be properly authorized, and its catalog **description** can still contain manipulative content. Metadata is DATA. Metadata may influence a REQUEST. Metadata must not determine the GRANT. Markdown teaches. Tables run Phase 8D-validated Q-MCP searches plus `Q-MCP-CATALOG-AUTHORITY`. What Happened is that hunt (one indexed row per run), not a generated story.

---

## WHY DOES IT EXIST?

LAB-MCP-001–006 authorized the acting agent more and more contextually (tool, scope, resource, result data, deputy vs caller). Learners still need a clickable path for INV-002 when the untrusted bytes are **catalog metadata**, not a tool result. Runtime and Splunk reuse were already proven in 8C/8D. The workshop is the teaching surface, not a new control, not a new detector, and not a scanner product.

---

## HOW DOES IT WORK?

Tokens: Hunt defaults to BASELINE `d95717ed-ffd2-46c0-a130-9a5d7d539a5d`. BASELINE / ATTACK / RETEST tokens bind the Phase 8D LIVE specimens. Q-MCP files are unchanged except `__RUN_ID__` → `"$token$"`. `Q-MCP-CATALOG-AUTHORITY` is the primary hunt. DETECT right table is **SIMULATED** `makeresults` (`DET-MCP-001-POSITIVE-CONTROL`). Live DETECT left table is `Q-MCP-AFTER-DENY` (0 rows on catalog LIVE runs). Empty teaching is `noDataMessage`.

BASELINE uses NORMAL catalog. ATTACK and RETEST use the same MALICIOUS description hash. Compare by hash, not preview.

---

## WHERE DOES IT SIT IN AGENTSEC?

After 8C runtime and 8D hunts. Visual sibling of `ws_lab_mcp_005` / `ws_lab_mcp_006`. Splunk still does not authorize. No DET-MCP-CATALOG. No scanner wiring. No rug-pull. No A2A.

---

## WHAT IS THE TRUST BOUNDARY?

```text
MCP catalog
 → Tool metadata
 → Agent observes metadata
 → Agent may form a request
 → CTRL-MCP-001
 → Handler only after ALLOW
```

CTRL-MCP-METADATA-001 classifies (`OBSERVE metadata_is_data`). CTRL-MCP-001 grants. The dashboard is observe-only.

---

## WHAT COULD AN ATTACKER CONTROL?

The **description bytes** advertised for a granted tool (here, `lookup_policy`). Not the first hop’s coded grant. Not `allowed_tools` (that field is not even indexed). Not Splunk. Not a scanner verdict.

---

## WHAT CAN GO WRONG?

- Treating OBSERVE as ALLOW or DENY
- Treating an authorized tool as a trusted description
- Treating malicious metadata as a malicious tool
- Treating provenance as content trust
- Treating a follow-on REQUEST as a GRANT
- Treating Q-MCP-EXECUTED extra OBSERVE row as “metadata executed”
- Treating DET-MCP-001 silence as “no catalog attack”
- Creating DET-MCP-CATALOG to make the workshop look complete
- Treating scanner PASS as trusted or scanner FAIL as runtime DENY
- Correlating ATTACK and RETEST by preview instead of hash

---

## WHAT TELEMETRY SHOULD EXIST?

Same as Phase 8D. Handler count is runtime. Splunk is a copy. `Q-MCP-CATALOG-AUTHORITY` labels metadata trust/provenance, description hash, METADATA-001 OBSERVE, first grant, follow-on decision, and execution observation. DET-MCP-001 still hunts DENY then later `mcp.started`.

---

## HOW WILL SPLUNK SHOW IT?

`ws_lab_mcp_catalog` ten GRID tabs. Empty tables stay visible and explain themselves. DETECT labels SIMULATED on the right-hand table and teaches **DETECTION GAP** plus **DETECTION ANALYZED — DETECTION CANDIDATE JUSTIFIED FOR LATER DESIGN**. COMPARE is three aligned cards with the same MALICIOUS hash on ATTACK and RETEST.

---

## WHAT CONTROL COULD CHANGE THE RESULT?

`AGENTSEC_SECURITY_PROFILE`. Vulnerable CTRL-MCP-001 may ALLOW the follow-on with `vulnerable_profile_fail_open:metadata_derived_authority`. Defended DENY `tool_not_granted`. The dashboard cannot switch the profile. Splunk cannot deny the follow-on. A scanner cannot deny the follow-on in this lab.

---

## WHAT TEST PROVES THE LOGIC?

Pytest: JSON/XML match, tabs, tokens, SPL bind-only, no DET-MCP-CATALOG, rejected hunts absent as datasources, hideWhenNoData false, hash equality teaching, schema 1.5.0. Playwright: ten tabs and four token values. Runtime spy still proves RETEST handler count 0 (Phase 8C/8D).

---

## What I should now be able to explain

1. Why a legitimate first tool can still carry untrusted catalog metadata.
2. Why METADATA-001 OBSERVE is classification, not authorization.
3. Why REQUEST ≠ GRANT on the follow-on `lookup_customer_tier`.
4. Why ATTACK and RETEST must be compared by description hash, not preview.
5. Why the vulnerable hop-1 ALLOW is overlay fail-open, not description grant.
6. Why DET-MCP-001 stays silent, and why no DET-MCP-CATALOG was created.
7. Why runtime handler count is authoritative and Splunk absence is corroboration.
8. Why Q-MCP-EXECUTED may show an extra OBSERVE row.
9. Why scanner output would still not be authorization.
10. How MCP-CATALOG sits on the MCP-001 → MCP-006 ladder without claiming to be the last MCP problem.
