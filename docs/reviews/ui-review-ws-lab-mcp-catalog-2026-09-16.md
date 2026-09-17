# UI review — `ws_lab_mcp_catalog` (LAB-MCP-CATALOG)

**Date:** 2026-09-16  
**Surface:** Dashboard Studio `ws_lab_mcp_catalog` (learner-facing). Splunk login/chrome not restyled.  
**Pass:** 1 written first; HIGH fixes then pass-2.  
**Screenshots:** `docs/screenshots/lab-mcp-catalog/pass1_*.png` (pass-1)  
**Validation:** `docs/screenshots/lab-mcp-catalog/pass1_validation.json`  
**Tokens checked:** `run_id`, `baseline_run_id`, `attack_run_id`, `retest_run_id` (all four MEASURED in DOM)  
**Tabs checked:** LEARN, BASELINE, ATTACK, OBSERVE, HUNT, DETECT, DEFEND, RETEST, COMPARE, PROVE (10/10 clicked)  
**Viewports OBSERVED:** 1440 (all tabs), 1024 (LEARN/RETEST/COMPARE), 768 (LEARN/RETEST/COMPARE)  
**Evidence class:** screenshot findings are **OBSERVED**. JSON/XML contracts remain **DOCUMENTED**. Indexed table rows on BASELINE / ATTACK / OBSERVE / HUNT / RETEST What Happened are **OBSERVED** for Phase 8D specimen tokens. DETECT live hunt is empty (0 DENY-then-start). DETECT right table is **SIMULATED**. This review does not re-MEASURE `dc(_raw)`.

Canonical tokens: `docs/AGENTSEC_DESIGN_SYSTEM.md`. Reference implementation: LAB-MCP-006.

Playwright viewport is 1440×1100. Studio content scrolls inside the view, so `full_page` still captures the first canvas, not the GRID below the fold.

`--refresh-app` restaged `ws_lab_mcp_catalog.xml`. Splunk Web HTTP 200. Catalog XML present inside the container. HEC health returned empty reply during lab-up wait (same class as Phase 7D). Indexed Phase 8D copies remained searchable. Do not claim the local lab was READY for new ingest during pass-1 capture.

---

## Roles

### Splunk architect

GRID tabs load. Four tokens exist and Submit-on-load ran. Hunt defaults to BASELINE (no empty-token red `!`). Q-MCP and `Q-MCP-CATALOG-AUTHORITY` returned indexed rows for BASELINE / ATTACK / RETEST What Happened. DETECT left table is empty (0 violations) with Studio’s default empty graphic. DETECT right table rendered one **SIMULATED** `makeresults` row labeled SIMULATED. Table `description` is populated-caption. Q-MCP bind-only; no DET-MCP-CATALOG; rejected extra Q-MCP-CATALOG-* hunts are named only as not published. Schema copy says 1.5.0.

### SOC analyst

Can hunt: Hunt token is prefilled; specimen tabs bind Phase 8D ids. Cannot read a full 36-character UUID from the global inputs (ellipsis). LEARN heading “Phase 8D LIVE ids” and the three complete UUIDs **are** on the first canvas. ATTACK / RETEST / COMPARE print the full MALICIOUS hash. HUNT primary `Q-MCP-CATALOG-AUTHORITY` is on canvas; many columns wrap. BASELINE AUTHZ first visible row is CTRL-MCP-001, not METADATA-001. ATTACK AUTHZ first visible row is hop-1 `lookup_customer_tier` ALLOW. RETEST AUTHZ headers sit at the fold with no data row on the first canvas.

### UX designer

Reading order of tabs is clear. White panels, navy headers, no neon, no extra charts, no MLTK purple. Markdown `fontSize: large`. LEARN three-column METADATA / REQUEST vs GRANT / Trust boundary is the right teaching layout. Trust-boundary ASCII clips rejected-hunt names at 1440 and clips TOOL HANDLER at 768. DETECT “DETECTION GAP” body is on the first canvas (better than MCP-006 pass-1). COMPARE three cards are the most readable reconstruction; 768 wraps the fail-open reason.

### Technical instructor

LEARN states REQUEST ≠ GRANT and OBSERVE ≠ ALLOW and the MCP-001…006 → MCP-CATALOG ladder. ATTACK states the DESCRIPTION was not authorized and uses the exact fail-open reason. RETEST states same hash, DENY `tool_not_granted`, runtime handler 0, Splunk corroboration wording. DETECT labels DETECTION GAP, LIVE 0/0/0, SIMULATED / NOT INDEXED, no DET-MCP-CATALOG. COMPARE three cards make ATTACK vs RETEST hash equality readable. What Happened is the hunt table, not generated prose. Q-MCP-EXECUTED extra OBSERVE row is taught on HUNT.

### Accessibility

Body markdown is Studio `large`. Severity is labeled in text (ALLOW / DENY / OBSERVE / SIMULATED / BASELINE / ATTACK / RETEST / NORMAL / MALICIOUS), not color alone. Token fields clip 36-character UUIDs visually; Playwright still reads the full value; LEARN prints complete UUIDs; ATTACK/RETEST/COMPARE print complete hashes. Keyboard tab bar is Splunk chrome (clicked in Playwright; not a WCAG certification). Wrapped hunt columns can be mistaken for truncated field values.

---

## Findings

### HIGH — LEARN Trust boundary clips handler / rejected hunts

**Where:** LEARN (`pass1_learn.png`, `pass1_w768_learn.png`)

At 1440 the rejected-hunt list is cut after `Q-MCP-CATALOG-TRUST, Q-`. At 768 the ASCII ends at `TOOL HANDL` / `only if ALLOW`. The required path is catalog snapshot → METADATA-001 OBSERVE → CTRL-MCP-001 → handler only after ALLOW.

### HIGH — ATTACK AUTHZ first visible row is the follow-on ALLOW

**Where:** ATTACK (`pass1_attack.png`)

Q-MCP-AUTHZ first canvas row is `lookup_customer_tier` CTRL-MCP-001 ALLOW `vulnerable_profile_fail_open:…`. METADATA-001 OBSERVE and hop-0 `lookup_policy` ALLOW are not on the first canvas. A learner can read the visible row as “the tool was the attack” or “the description was authorized.” What Happened still shows OBSERVE + first grant + follow-on. Do not rewrite Q-MCP-AUTHZ.

### HIGH — RETEST AUTHZ has no data row on the first canvas

**Where:** RETEST (`pass1_retest.png`)

Markdown and What Happened populated, including the MALICIOUS hash. AUTHZ is headers-only at the fold. Phase 8D indexed METADATA-001 OBSERVE, hop-0 ALLOW, and hop-1 DENY `tool_not_granted` for this run.id. An empty first-canvas AUTHZ teaches the wrong empty-state lesson on RETEST.

### MEDIUM — Q-MCP-CATALOG-AUTHORITY wraps hash, tool, and follow-on

**Where:** BASELINE / ATTACK / RETEST / HUNT What Happened tables

Column wrap can be mistaken for truncated telemetry (`lookup_cu` / `stomer_tie`, hash broken across lines). Markdown and COMPARE cards already spell the full strings. Do not rewrite Q-MCP SPL. Do not hide the hash.

### MEDIUM — BASELINE AUTHZ first visible row is CTRL-MCP-001

**Where:** BASELINE (`pass1_baseline.png`)

Table is already full-width. First visible AUTHZ row is hop-0 `lookup_policy` ALLOW because Q-MCP-AUTHZ is not rewritten (no extra `sort`). BASELINE markdown and What Happened still show METADATA-001 OBSERVE then CTRL-MCP-001.

### MEDIUM — DETECT empty left table uses Studio’s orange warning chrome

**Where:** DETECT (`pass1_detect.png`)

Indexed `Q-MCP-AFTER-DENY` is correctly empty (0 DENY-then-start). Caption teaching is right. Studio still shows a warning triangle and “No search results returned.” Same Studio limit as LAB-MCP-006. Custom `noDataMessage` is not the visible empty graphic.

### MEDIUM — COMPARE ATTACK reason wraps; 768 clips `metadata_derived_authority`

**Where:** COMPARE (`pass1_compare.png`, `pass1_w768_compare.png`)

At 1440 the reason wraps to `metadata_derived_author`. At 768 it becomes `vulnerable_profile_fail_open:met`. The COMPARE header already prints the full hash. The fail-open reason must remain readable without relying on the third-width card wrap.

### LOW — Global token inputs ellipsis 36-character UUIDs

Playwright `input_value` is complete. LEARN prints the full ids. Same Studio chrome limit as prior labs.

### LOW — Dashboard description truncates in Splunk chrome

The Studio description is cut after “Saved search DET-MCP-”. Teaching is in LEARN / DETECT, not in that chrome line. Do not restyle Splunk enterprise chrome.

### LOW — HUNT rejected-hunt names wrap across the heading paragraph

Readable enough. DETECT and LEARN already state no DET-MCP-CATALOG.

---

## Pass-1 counts

**0 BLOCKER / 3 HIGH / 4 MEDIUM / 3 LOW**

Do not fix until this review is written. Then fix only BLOCKER and HIGH unless the task already requires those fixes (this Phase 8E task does).

---

## Pass-2 (after HIGH fixes)

**Screenshots:** `docs/screenshots/lab-mcp-catalog/pass2_*.png`  
**Validation:** `docs/screenshots/lab-mcp-catalog/pass2_validation.json`  
**Tokens:** all four complete UUIDs MEASURED again. Tabs 10/10. Viewports 1440 / 1024 / 768 recaptured.

| Pass-1 HIGH | Pass-2 result |
|-------------|---------------|
| LEARN Trust boundary clips handler / rejected hunts | **Fixed.** One-line path `Catalog snapshot → METADATA-001 OBSERVE → CTRL-MCP-001 → Handler only after ALLOW` is on the first canvas at 1440 and 768 (`pass2_learn.png`, `pass2_w768_learn.png`). Rejected-hunt names are abbreviated on the same card. |
| ATTACK AUTHZ first visible row is the follow-on ALLOW | **Downgraded to MEDIUM.** Teaching on the first canvas states hop-1 may appear first and is not description authorization (`pass2_attack.png`). First AUTHZ data row remains hop-1 `lookup_customer_tier` ALLOW because Q-MCP-AUTHZ is not rewritten. What Happened still shows OBSERVE, first grant, and follow-on. |
| RETEST AUTHZ has no data row on the first canvas | **Fixed.** `pass2_retest.png` shows hop-1 DENY `tool_not_granted` and hop-0 `lookup_policy` ALLOW on the first canvas, plus the MALICIOUS hash in markdown. |

### Residual MEDIUM / LOW (accepted)

- MEDIUM: Q-MCP-CATALOG-AUTHORITY column wrap (`lookup_cu` / `stomer_tie`, hash broken across table cells). Markdown and COMPARE header keep the full hash.
- MEDIUM: BASELINE AUTHZ first visible row is CTRL-MCP-001 (METADATA-001 remains in What Happened / markdown)
- MEDIUM: ATTACK AUTHZ first visible row remains hop-1 ALLOW (taught, not rewritten)
- MEDIUM: DETECT left table Studio orange empty chrome
- MEDIUM: COMPARE third-width card still wraps `metadata_derived_authority`; full-width COMPARE header now prints the complete ATTACK and RETEST reasons (visible at 768)
- LOW: token ellipsis; chrome description truncation; HUNT rejected-hunt wrap

**Pass-2 counts: 0 BLOCKER / 0 HIGH.** Residual MEDIUM/LOW documented, not hidden.

Do not rewrite pass-1 history.
