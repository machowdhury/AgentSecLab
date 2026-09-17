# UI review — `ws_lab_mcp_006` (LAB-MCP-006)

**Date:** 2026-09-15  
**Surface:** Dashboard Studio `ws_lab_mcp_006` (learner-facing). Splunk login/chrome not restyled.  
**Pass:** 1 written first; HIGH fixes then pass-2.  
**Screenshots:** `docs/screenshots/lab-mcp-006/pass1_*.png` (pass-1)  
**Validation:** `docs/screenshots/lab-mcp-006/pass1_validation.json`  
**Tokens checked:** `run_id`, `baseline_run_id`, `attack_run_id`, `retest_run_id` (all four MEASURED in DOM)  
**Tabs checked:** LEARN, BASELINE, ATTACK, OBSERVE, HUNT, DETECT, DEFEND, RETEST, COMPARE, PROVE (10/10 clicked)  
**Evidence class:** screenshot findings are **OBSERVED**. JSON/XML contracts remain **DOCUMENTED**. Indexed table rows on BASELINE / ATTACK / OBSERVE / HUNT / RETEST / COMPARE teaching cards are **OBSERVED** for Phase 7C specimen tokens. DETECT live hunt is empty (0 DENY-then-start). DETECT right table is **SIMULATED**. This review does not re-MEASURE `dc(_raw)`.

Canonical tokens: `docs/AGENTSEC_DESIGN_SYSTEM.md`. Reference implementation: LAB-MCP-005.

Playwright viewport is 1440×1100. Studio content scrolls inside the view, so `full_page` still captures the first canvas, not the GRID below the fold.

`--refresh-app` restaged the view. Splunk Web HTTP 200. HEC health returned empty reply during lab-up wait (same class of observation as Phase 6D). Indexed Phase 7C copies remained searchable. Do not claim the local lab was READY for new ingest during pass-1 capture.

---

## Roles

### Splunk architect

GRID tabs load. Four tokens exist and Submit-on-load ran. Hunt defaults to BASELINE (no empty-token red `!`). Q-MCP and `Q-MCP-DELEGATION` returned indexed rows for BASELINE / ATTACK / RETEST What Happened. DETECT left table is empty (0 violations) with Studio’s default empty graphic. DETECT right table rendered one **SIMULATED** `makeresults` row labeled SIMULATED. Table `description` is populated-caption. Q-MCP bind-only; no DET-MCP-006; rejected `Q-MCP-AMBIENT-USE` / chain / executed / authority hunts are named only as not published. Schema copy says 1.4.0.

### SOC analyst

Can hunt: Hunt token is prefilled; specimen tabs bind Phase 7C ids. Cannot read a full 36-character UUID from the global inputs (ellipsis). LEARN heading “Phase 7C LIVE ids” and the three complete UUIDs **are** on the first canvas (better than MCP-005 pass-1). HUNT primary `Q-MCP-DELEGATION` is on canvas; many columns wrap. BASELINE AUTHZ first visible row is CTRL-MCP-001, not CTRL-DELEGATION-001. ATTACK AUTHZ/TOOL first canvas did not show populated rows. RETEST TOOL empty is the expected corroboration empty state.

### UX designer

Reading order of tabs is clear. White panels, navy headers, no neon, no extra charts, no MLTK purple. Markdown `fontSize: large`. LEARN three-column CALLER / DELEGATED vs AMBIENT / Trust boundary is the right teaching layout. CALLER ASCII clips before “Tool handler”. DELEGATED vs AMBIENT clips the end of the LIMITED grant sentence. DETECT “Why no DET-MCP-006” body is below the fold. COMPARE three cards are the most readable reconstruction.

### Technical instructor

LEARN states DEPUTY AUTHORITY ≠ CALLER AUTHORITY and the core question. ATTACK states the deputy could perform the operation without caller authorization and uses the exact fail-open reason. RETEST states same request, DENY `delegated_authority_not_granted`, runtime handler 0, Splunk corroboration wording, `deputy_not_on_indexed_hop1`. DETECT labels NO NEW DETECTOR, LIVE 0/0/0, SIMULATED / NOT INDEXED. COMPARE three cards make ATTACK vs RETEST readable. What Happened is the hunt table, not generated prose.

### Accessibility

Body markdown is Studio `large`. Severity is labeled in text (ALLOW / DENY / OBSERVED / SIMULATED / BASELINE / ATTACK / RETEST / delegated / ambient_deputy), not color alone. Token fields clip 36-character UUIDs visually; Playwright still reads the full value; LEARN prints complete UUIDs. Keyboard tab bar is Splunk chrome (clicked in Playwright; not a WCAG certification). Wrapped hunt columns can be mistaken for truncated field values.

---

## Findings

### HIGH — LEARN CALLER vs DEPUTY ASCII clips the tool handler

**Where:** LEARN (`pass1_learn.png`)

The required path is Caller → Deputy → CTRL-DELEGATION-001 → MCP authorize → Tool handler. The first canvas ends at “MCP authorize (CTRL-MCP-001)”. “Tool handler” is not visible in that card.

### HIGH — BASELINE AUTHZ first visible row is CTRL-MCP-001

**Where:** BASELINE (`pass1_baseline.png`)

Q-MCP-AUTHZ is a 260px half-width table. The visible row is CTRL-MCP-001 ALLOW `tool_granted`. CTRL-DELEGATION-001 is the MCP-006 control. A learner can read “MCP ALLOW” as the whole story and miss the delegation decision. What Happened still shows both, but AUTHZ is the control card.

### HIGH — ATTACK AUTHZ and TOOL tables did not show populated rows on the first canvas

**Where:** ATTACK (`pass1_attack.png`)

Markdown and What Happened populated. The lower AUTHZ and TOOL panels rendered as empty/loading chrome. Phase 7C indexed two AUTHZ rows and one TOOL row for this run.id. An empty first canvas here teaches the wrong empty-state lesson on the ATTACK tab.

### HIGH — DETECT “Why no DET-MCP-006” explanation is below the fold

**Where:** DETECT (`pass1_detect.png`)

The heading is visible. The required SOC lesson (huntable evidence ≠ detection predicate; no `allowed_tools`; possession must not alert) is not on the first canvas. DETECT otherwise labels NO NEW DETECTOR and SIMULATED correctly.

### MEDIUM — Q-MCP-DELEGATION wraps `lookup_customer_tier` and `deputy_not_on_indexed_hop1`

**Where:** ATTACK / RETEST / HUNT What Happened tables

Column wrap can be mistaken for truncated telemetry (`lookup_cu` / `stomer_tie`, `deput… t_on_inde xed_hop1`). Markdown and COMPARE cards already spell the full strings. Do not rewrite Q-MCP SPL.

### MEDIUM — DETECT empty left table uses Studio’s orange warning chrome

**Where:** DETECT (`pass1_detect.png`)

Indexed `Q-MCP-AFTER-DENY` is correctly empty (0 DENY-then-start). Caption teaching is right. Studio still shows a warning triangle and an unlabeled empty grid. Same Studio limit as LAB-MCP-005.

### MEDIUM — RETEST Q-MCP-TOOL empty chrome can be read as “blocked”

**Where:** RETEST (`pass1_retest.png`)

Caption says Splunk corroboration and runtime handler count 0 is authoritative. Studio empty graphic still looks like an error. Markdown on the same tab is the correct teaching.

### MEDIUM — OBSERVE IDENTITY first visible WHO row is the deputy

**Where:** OBSERVE (`pass1_observe.png`)

Caption says hop 0 is the caller. The visible WHO row is `acme-agent-compliance-004`. Sequence table above it does show hop 0 credit then hop 1 compliance.

### MEDIUM — COMPARE ATTACK reason wraps inside the third-width card

**Where:** COMPARE (`pass1_compare.png`)

`vulnerable_profile_fail_open:ambient_deputy_authority` wraps. The field is still present. Cards otherwise keep caller/deputy/source/decision readable.

### LOW — Global token inputs ellipsis 36-character UUIDs

Playwright `input_value` is complete. LEARN prints the full ids. Same Studio chrome limit as prior labs.

### LOW — Dashboard description truncates in Splunk chrome

The Studio description is cut after “packaged”. Teaching is in LEARN, not in that chrome line. Do not restyle Splunk enterprise chrome.

### LOW — PROVE knowledge-check path is a repo path, not a Splunk link

Expected. Answers live in `learning/level_1/LAB-MCP-006/knowledge-check.md`.

---

## Pass-1 counts

**0 BLOCKER / 4 HIGH / 5 MEDIUM / 3 LOW**

Do not fix until this review is written. Then fix only BLOCKER and HIGH unless the task already requires those fixes (this Phase 7D task does).

---

## Pass-2 (after HIGH fixes)

**Screenshots:** `docs/screenshots/lab-mcp-006/pass2_*.png`  
**Validation:** `docs/screenshots/lab-mcp-006/pass2_validation.json`  
**Tokens:** all four complete UUIDs MEASURED again. Tabs 10/10.

| Pass-1 HIGH | Pass-2 result |
|-------------|---------------|
| LEARN CALLER ASCII clips Tool handler | **Fixed.** One-line path `Caller → Deputy → CTRL-DELEGATION-001 → MCP authorize → Tool handler` is on the first canvas (`pass2_learn.png`). |
| BASELINE AUTHZ first visible row is CTRL-MCP-001 | **Downgraded to MEDIUM.** Table is full-width. First visible AUTHZ row remains CTRL-MCP-001 because Q-MCP-AUTHZ is not rewritten (no extra `sort`). BASELINE markdown and What Happened still show CTRL-DELEGATION-001 ALLOW `delegation_granted` then CTRL-MCP-001. Do not rewrite the hunt to fix presentation. |
| ATTACK AUTHZ/TOOL empty on first canvas | **Fixed as empty-chrome.** `pass2_attack.png` shows populated What Happened plus AUTHZ column headers (not a loading empty grid). AUTHZ data rows remain below the 1100px first canvas. Reconstruction is the What Happened row. |
| DETECT why-no-detector below the fold | **Fixed.** `pass2_detect.png` shows “Why no DET-MCP-006” and the huntable-vs-predicate lesson on the first canvas. SIMULATED right table still labeled. |

### Residual MEDIUM / LOW (accepted)

- MEDIUM: Q-MCP-DELEGATION column wrap (`lookup_cu` / `stomer_tie`, `deputy_no t_on_inde xed_hop1`)
- MEDIUM: DETECT left table Studio orange empty chrome
- MEDIUM: RETEST Q-MCP-TOOL empty chrome (caption still corroboration-only)
- MEDIUM: OBSERVE IDENTITY first WHO row can be the deputy
- MEDIUM: COMPARE ATTACK reason wraps; BASELINE AUTHZ shows MCP row first
- LOW: token ellipsis; chrome description truncation; PROVE repo path

**Pass-2 counts: 0 BLOCKER / 0 HIGH.** Residual MEDIUM/LOW documented, not hidden.
