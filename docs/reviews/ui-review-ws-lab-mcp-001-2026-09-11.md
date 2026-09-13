# UI review — `ws_lab_mcp_001` (LAB-MCP-001)

**Date:** 2026-09-11  
**Surface:** Dashboard Studio `ws_lab_mcp_001` (learner-facing). Splunk login/chrome not restyled.  
**Pass:** 1 (no UI changes yet)  
**Screenshots:** `docs/screenshots/lab-mcp-001/pass1_*.png`  
**Validation:** `docs/screenshots/lab-mcp-001/pass1_validation.json`  
**Tokens checked:** `run_id`, `baseline_run_id`, `attack_run_id`, `retest_run_id` (all present in DOM)  
**Tabs checked:** LEARN, BASELINE, ATTACK, OBSERVE, HUNT, DETECT, DEFEND, RETEST, COMPARE, PROVE (10/10 clicked)  
**Evidence class:** screenshot findings are **OBSERVED**. JSON/XML contracts remain **DOCUMENTED**. Indexed table rows on BASELINE / ATTACK / RETEST / OBSERVE / HUNT / COMPARE / PROVE are **OBSERVED** in pass-1 screenshots for the Phase 3C specimen tokens. This review does not re-MEASURE `dc(_raw)`.

Canonical tokens: `docs/AGENTSEC_DESIGN_SYSTEM.md`. Reference implementation: LAB-PI-001.

---

## Roles

### Splunk architect

GRID tabs load. Four tokens exist and Submit-on-load ran. Hunt defaults to the BASELINE specimen (no empty-token red `!`). Q-MCP datasources returned indexed rows for the three Phase 3C run.ids. DETECT left table is empty (0 violations) with Studio’s default empty graphic. DETECT right table rendered one **SIMULATED** `makeresults` row. Table `description` is always visible and currently concatenates empty-state copy onto populated tables.

### SOC analyst

Can hunt: Hunt token is prefilled; BASELINE / ATTACK / RETEST tabs bind specimen tokens so those pages show data without pasting. Cannot read a full 36-character UUID from the global inputs (ellipsis). LEARN specimen list is below the first-screen fold. What Happened packs twelve columns; `execution_state` and `result_trust` headers clip. Q-MCP-EXECUTED shows control `executed=false` while `has_started` is off-canvas in half- and third-width tables.

### UX designer

Reading order of tabs is clear. White panels, navy headers, no neon, no extra charts, no MLTK purple. Markdown `fontSize: large`. DETECT two-column split is the right teaching layout. Global token row still clips. COMPARE third-width tables overflow horizontally. Empty-state sentences appear as captions on tables that already have rows.

### Technical instructor

LEARN correctly separates authorization from execution, registered vs granted, and `untrusted_data`. ATTACK does not call `lookup_customer_tier` malware. RETEST markdown states runtime handler count is authoritative. DETECT labels SIMULATED and says zero rows are not independent proof. **Contradiction:** populated What Happened / Q-MCP tables are captioned “No indexed control.decision was found for this run.” COMPARE markdown says handler executed; the visible Q-MCP-EXECUTED column is `executed=false`.

### Accessibility

Body markdown is Studio `large` (~16px unformatted). Severity is labeled in text (ALLOW / DENY / SIMULATED / BASELINE / ATTACK / RETEST), not color alone. Token fields clip 36-character UUIDs visually; Playwright still reads the full value. Keyboard tab bar is Splunk chrome (clicked in Playwright; not a WCAG certification). Flask pages were not recaptured this pass.

---

## Findings

### BLOCKER — Empty-state copy is the always-visible table caption

**Where:** BASELINE, ATTACK, OBSERVE, HUNT, RETEST, PROVE (`pass1_baseline.png`, `pass1_attack.png`, `pass1_observe.png`, `pass1_hunt.png`, `pass1_retest.png`, `pass1_prove.png`)

Studio `description` renders even when the search has rows. Captions say “No indexed control.decision was found for this run” (and the MCP-execution variant) **above tables that show ALLOW / DENY, tools, and `mcp.completed`**. Learners are taught absence while looking at presence. Empty-state teaching belongs in `noDataMessage` (and markdown), not in the populated caption.

### HIGH — What Happened columns clip the execution and trust fields

**Where:** BASELINE, ATTACK, RETEST, PROVE What Happened tables

Required panel fields `execution_state` and `result_trust_display` render as `execution...` / `result_tru...`. Values wrap (`untrusted_dat a`). The panel exists and is telemetry-driven (good), but a learner cannot read the two fields that distinguish ALLOW from execution and result trust without horizontal decoding.

### HIGH — Q-MCP-EXECUTED visible `executed=false` reads as “did not run”

**Where:** ATTACK, HUNT, COMPARE (`pass1_attack.png`, `pass1_hunt.png`, `pass1_compare.png`)

Validated Q-MCP-EXECUTED keeps the **control-event** `executed` field (false on ALLOW). `has_started` / `execution_state` prove the handler began, but those columns are clipped in half- and third-width tables. COMPARE markdown says runtime handler count 1 / mcp executed true while the first numeric column the eye hits is `executed false`. Do not change Q-MCP SPL. Teach the column and make `execution_state` visible.

### HIGH — Full specimen UUIDs are not on the first LEARN screen

**Where:** global inputs (every tab) + LEARN (`pass1_learn.png`)

Input titles are already short (Hunt / BASELINE / ATTACK / RETEST). Values still ellipsis. LEARN copy includes the three full ids, but they sit below the trust-path fold. Design system: long identifiers must remain accessible. Copy-from-LEARN only works if LEARN shows them without hunting through the panel.

### MEDIUM — DETECT empty left table uses Studio’s orange warning chrome

**Where:** DETECT (`pass1_detect.png`)

Indexed Q-MCP-AFTER-DENY is correctly empty (0 violations). Caption teaching is right. Studio still shows a warning triangle + “No search results returned”. Not a security misclaim (markdown already explains zero rows), but it looks like a broken panel.

### MEDIUM — DETECT SIMULATED column headers clip

**Where:** DETECT right table

Title includes **SIMULATED**. Fixture row is visible and labeled SIMULATED. Headers truncate (`sequen…`, `event.…`, `eviden…`). Words still exist; not color-only.

### LOW — Submit button is Splunk default green

Out of scope to restyle. Not an AgentSec token.

### LOW — COMPARE third-width Q-MCP-TOOL tables are below the fold

COMPARE markdown already states the core lesson. Lower tables are corroboration. Not a teaching failure if AUTHZ / EXECUTED row is fixed.

---

## What is already good

- Ten tabs match the workshop contract. Hunt defaults to BASELINE (PI-001 HIGH empty-token is not repeated).
- Description line: Splunk does not ALLOW or DENY a tool.
- LEARN trust path, registered vs granted, ALLOW ≠ execution, `mcp.failed` is not prevention, results are `untrusted_data`.
- ATTACK is a controlled lab authorization failure, not a production exploit.
- RETEST copy: runtime handler count is authoritative; Splunk absence of `mcp.started` is corroboration only.
- DETECT right table title includes SIMULATED; fixture row is not indexed telemetry.
- Indexed BASELINE / ATTACK / RETEST rows actually appeared (Phase 3C specimens present on this volume).
- No neon, no extra charts, no MLTK purple. Tables do not use `hideWhenNoData`.
- Markdown lists, not GFM tables. `fontSize: large`.

---

## Fix scope (BLOCKER + HIGH only)

1. Stop putting empty-state sentences in always-visible `description`. Use populated captions + `noDataMessage`.
2. Split What Happened into identity + decision/execution tables so `execution_state` and result trust are readable.
3. Caption Q-MCP-EXECUTED: control `executed` is not handler execution; show / point at `has_started` and `execution_state`.
4. Move the three full specimen UUIDs to the top of LEARN (after the learning objectives).

---

## Pass 2 (after BLOCKER/HIGH fixes)

**Screenshots:** `docs/screenshots/lab-mcp-001/pass2_*.png`  
**Validation:** `docs/screenshots/lab-mcp-001/pass2_validation.json`

| Check | Result | Class |
|-------|--------|-------|
| 10 tabs clicked | LEARN … PROVE all present | OBSERVED |
| Token values | Hunt/BASELINE/ATTACK/RETEST equal the three specimen UUIDs (Hunt = BASELINE) | MEASURED (Playwright `input_value`) |
| LEARN specimen list | Full UUIDs on the first LEARN screen, above Trust path | OBSERVED |
| Empty-token red `!` | Still absent | OBSERVED |
| Empty caption on populated tables | Gone. Captions describe the populated table. Empty teaching is `noDataMessage` | OBSERVED |
| What Happened split | Identity + decision tables. `execution_state` and `result_trust` headers fully readable. BASELINE `mcp.completed` / `untrusted_data`. ATTACK fail-open ALLOW / `mcp.completed`. RETEST `DENY` / `no_mcp_execution_event` / `prevented` | OBSERVED |
| Q-MCP-EXECUTED caption | States control `executed` stays false on ALLOW; read `has_started` and `execution_state` | OBSERVED |
| SIMULATED table | Fixture row, title includes SIMULATED | OBSERVED |
| DETECT indexed empty | “No search results returned” plus teaching caption (not “Tool was blocked”) | OBSERVED |

BLOCKER/HIGH from pass 1 are addressed.

Residual **MEDIUM:** DETECT left table still uses Studio’s orange warning chrome for a correct zero-row hunt. SIMULATED column headers still truncate. RETEST `execution_state` value wraps (`no_mcp_execution_eve` / `nt`) but the full token is readable. Token input fields still ellipsis at 1440px; Playwright reads the full 36-character values; copy from LEARN.

Residual **LOW:** Splunk default green Submit. COMPARE Q-MCP-EXECUTED tables sit below the first viewport (AUTHZ ALLOW / ALLOW / DENY is visible; markdown states handler counts).

Do **not** claim WCAG certification. Keyboard tab bar is Splunk chrome. Severity is labeled in text.

---
