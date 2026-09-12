# UI review — `ws_lab_pi_001` (LAB-PI-001)

**Date:** 2026-09-11  
**Surface:** Dashboard Studio `ws_lab_pi_001` (learner-facing). Splunk login/chrome not restyled.  
**Pass:** 1 (no UI changes yet)  
**Screenshots:** `docs/screenshots/lab-pi-001/pass1_*.png`  
**Tokens checked:** `run_id`, `baseline_run_id`, `attack_run_id`, `retest_run_id` (all present in DOM)  
**Tabs checked:** LEARN, BASELINE, ATTACK, OBSERVE, HUNT, DETECT, DEFEND, RETEST, COMPARE, PROVE (10/10 clicked)  
**Evidence class:** screenshot findings are **OBSERVED**. JSON/XML contracts remain **DOCUMENTED**. This review does not MEASURE index counts on this Splunk volume.

Canonical tokens: `docs/AGENTSEC_DESIGN_SYSTEM.md`.

---

## Roles

### Splunk architect

GRID tabs load. Four tokens exist. SIMULATED `makeresults` table rendered one fixture row labeled SIMULATED. Hunt tables bound to empty `run_id` did not run (Studio empty-token state). COMPARE searches ran against specimen defaults and returned no rows on this volume — do not treat that as a new experiment.

### SOC analyst

Cannot copy a full specimen `run.id` from the token fields (values clip). LEARN specimen table is unreadable pipe text. Empty Hunt looks like a dashboard error, not a hunt waiting for an id.

### UX designer

Reading order of tabs is clear. Token row is overcrowded. LEARN table overflow. Markdown headings are readable. DETECT two-column layout is the right teaching split.

### Technical instructor

Copy still says Splunk does not ALLOW/DENY. ALLOW ≠ execution is on BASELINE/HUNT/COMPARE. SIMULATED is labeled in the DETECT panel title. Empty Hunt is *not* explained by the Studio empty-token graphic.

### Accessibility

Body markdown is Studio default (~14px). Token fields clip 36-character UUIDs (content not fully visible). Severity is not color-only in our markdown. Flask pages were reviewed in source (not screenshotted): `lang`, labels, 44px buttons, focus-visible teal.

---

## Findings

### BLOCKER — LEARN specimen table is unreadable

**Where:** LEARN (`pass1_learn.png`)  
Studio rendered the markdown table as one wrapping pipe string. Learners cannot copy BASELINE / ATTACK / RETEST ids from the page. Cause: markdown strings in the generator are indented inside `build()`, and GFM tables do not survive that indent.

### HIGH — Hunt `run.id` empty token looks like an error

**Where:** BASELINE, OBSERVE, HUNT, DETECT (left), RETEST  
Studio shows a red `!` and “Set token value to render visualization.” Design-system empty copy (“Zero rows is not all-clear and is not DENY”) never appears. Six workshop steps look broken on first open.

### HIGH — Specimen token fields clip UUIDs

**Where:** global inputs on every tab  
BASELINE / ATTACK / RETEST fields show a truncated id (ellipsis). SOC cannot verify which specimen is selected without expanding the field. Four long titles compete with four 36-character values on one row.

### HIGH — COMPARE empty state is a warning, not a teaching empty

**Where:** COMPARE (`pass1_compare.png`)  
Six tables: “No search results returned” plus orange warnings. Tokens have defaults; searches ran. This volume may not contain those prior MEASURED run.ids. The tab does not say that empty COMPARE is not DENY and is not proof the specimens are missing from history.

### MEDIUM — Studio markdown default size vs body ≥16px

Markdown `fontSize` is unset (Studio default 14px unformatted). Design system asks for body ≥16px equivalent on learner copy.

### MEDIUM — DETECT SIMULATED columns clip

SIMULATED table is labeled correctly; several column headers truncate (`hop_in…`, `event.…`). Words still exist; not color-only.

### LOW — Submit button is Splunk default green

Out of scope to restyle. Not an AgentSec token.

### LOW — Flask Attack Service (source-only)

Primary action is labeled “Fire ATK-002” with critical color. No screenshot this pass.

---

## What is already good

- Ten tabs match the workshop contract.
- Description line: Splunk does not ALLOW or DENY.
- DETECT right table title includes SIMULATED and showed the fixture row.
- No neon, no extra charts, no MLTK purple.
- Tables do not use `hideWhenNoData`.
- ATTACK tab does not fire the payload from Splunk.

---

## Fix scope (BLOCKER + HIGH only)

1. Dedent markdown; replace the LEARN table with a readable list of full UUIDs.
2. Default Hunt `run_id` to the validated BASELINE specimen so tables run; keep COMPARE defaults.
3. Shorten input titles so UUIDs remain visible.
4. State on COMPARE (and Hunt empty copy) that zero rows on this volume is not DENY.
5. Set markdown `fontSize` to `large` (16px unformatted) while touching those panels.

---

## Pass 2 (after BLOCKER/HIGH fixes)

**Screenshots:** `docs/screenshots/lab-pi-001/pass2_*.png`  
**Validation:** `docs/screenshots/lab-pi-001/pass2_validation.json`

| Check | Result | Class |
|-------|--------|-------|
| 10 tabs clicked | LEARN … PROVE all present | OBSERVED |
| Token values | Hunt/BASELINE/ATTACK/RETEST equal the three specimen UUIDs (Hunt = BASELINE) | MEASURED (Playwright `input_value`) |
| LEARN specimen list | Full UUIDs readable as bullets | OBSERVED |
| Empty-token red `!` | Gone; tables show “No search results returned” | OBSERVED |
| COMPARE empty teaching | Copy states empty on this volume is not DENY | OBSERVED |
| SIMULATED table | Fixture row, title includes SIMULATED | OBSERVED |

Residual **MEDIUM:** token fields still visually clip at 1440px (ellipsis). Playwright read the full 36-character values. Copy the ids from LEARN if the field looks truncated.

Residual **not a UI defect:** indexed Q-* tables are empty on this Splunk volume. Do not treat that as a new MEASURED absence of the Phase 2C.2 runs without a live `tstats` on this volume.

BLOCKER/HIGH from pass 1 are addressed. Flask pages were not recaptured (source already matched tokens).

