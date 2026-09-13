# UI review — `ws_lab_mcp_003` (LAB-MCP-003)

**Date:** 2026-09-12  
**Surface:** Dashboard Studio `ws_lab_mcp_003` (learner-facing). Splunk login/chrome not restyled.  
**Pass:** 1 written first; HIGH fixes then pass-2.  
**Screenshots:** `docs/screenshots/lab-mcp-003/pass1_*.png` (pass-1) and `pass2_*.png` (pass-2)  
**Validation:** `docs/screenshots/lab-mcp-003/pass1_validation.json` and `pass2_validation.json`  
**Tokens checked:** `run_id`, `baseline_run_id`, `attack_run_id`, `retest_run_id`, `unknown_run_id` (all five MEASURED in DOM)  
**Tabs checked:** LEARN, BASELINE, ATTACK, OBSERVE, HUNT, DETECT, DEFEND, RETEST, COMPARE, PROVE (10/10 clicked)  
**Evidence class:** screenshot findings are **OBSERVED**. JSON/XML contracts remain **DOCUMENTED**. Indexed table rows on BASELINE / ATTACK / OBSERVE / HUNT / RETEST / COMPARE are **OBSERVED** for Phase 4C specimen tokens. DETECT live hunt is empty (0 violations). DETECT right table is **SIMULATED**. This review does not re-MEASURE `dc(_raw)`.

Canonical tokens: `docs/AGENTSEC_DESIGN_SYSTEM.md`. Reference implementation: LAB-MCP-001 / LAB-PI-001.

---

## Roles

### Splunk architect

GRID tabs load. Five tokens exist and Submit-on-load ran. Hunt defaults to BASELINE (no empty-token red `!`). Q-MCP datasources returned indexed rows for BASELINE / ATTACK / RETEST. UNKNOWN teaching tables exist on DEFEND (below first fold). DETECT left table is empty (0 violations) with Studio’s default empty graphic. DETECT right table rendered one **SIMULATED** `makeresults` row. Table `description` is populated-caption (not empty-state copy on rows). Q-MCP bind-only; no DET-MCP-003.

### SOC analyst

Can hunt: Hunt token is prefilled; specimen tabs bind Phase 4C ids. Cannot read a full 36-character UUID from the global inputs (ellipsis). LEARN specimen list is on the first screen (good). HUNT Q-MCP-EXECUTED shows control `executed=false` while `has_started` / `execution_state` clip. COMPARE third-width AUTHZ tables clip `reason`.

### UX designer

Reading order of tabs is clear. White panels, navy headers, no neon, no extra charts, no MLTK purple. Markdown `fontSize: large`. LEARN three-column GRANTED / KNOWN BUT UNGRANTED / UNKNOWN is the right teaching layout. Nested backticks smashed `allowed_scope` copy on ATTACK / DEFEND / RETEST. Global token row still clips. DETECT orange empty chrome on a true 0-row hunt.

### Technical instructor

LEARN correctly separates LAB-MCP-001 (tool) from LAB-MCP-003 (scope), and the three catalog states. ATTACK states the tool is granted, the scope is not, and the grant did not change — except the interpolated grant sentence is unreadable (`grantpolicy:read`). RETEST shows DENY `scope_not_granted`, `no_mcp_execution_event`, `prevented`. DETECT labels SIMULATED and says zero rows are not independent proof. ALLOW ≠ execution is stated on BASELINE / HUNT / COMPARE.

### Accessibility

Body markdown is Studio `large`. Severity is labeled in text (ALLOW / DENY / ERROR / SIMULATED / BASELINE / ATTACK / RETEST), not color alone. Token fields clip 36-character UUIDs visually; Playwright still reads the full value. Keyboard tab bar is Splunk chrome (clicked in Playwright; not a WCAG certification).

---

## Findings

### HIGH — Nested backticks smash the grant-unchanged teaching sentence

**Where:** ATTACK, DEFEND, RETEST (`pass1_attack.png`, `pass1_defend.png`, `pass1_retest.png`)

`GRANT_UNCHANGED` was interpolated inside extra markdown backticks. Learners see `allowed_scope stays the coded grantpolicy:read` with no space. That is the core MCP-003 lesson (fail-open does not rewrite the grant). Fix: plain prose, no nested code spans.

### HIGH — HUNT Q-MCP-EXECUTED visible `executed=false` reads as “did not run”

**Where:** HUNT (`pass1_hunt.png`)

Validated Q-MCP-EXECUTED keeps the **control-event** `executed` field (false on ALLOW). `has_started=1` is barely visible as a clipped `has_st…` column. Caption already teaches the distinction but truncates. Do not change Q-MCP SPL. Make the EXECUTED table full width so `execution_state` is on canvas.

### MEDIUM — DETECT empty left table uses Studio’s orange warning chrome

**Where:** DETECT (`pass1_detect.png`)

Indexed Q-MCP-AFTER-DENY is correctly empty (0 violations). Caption teaching is right. Studio still shows a warning triangle + “No search results returned”. Not a security misclaim.

### MEDIUM — COMPARE / OBSERVE / HUNT AUTHZ column headers clip

Third-width and half-width tables truncate `reason`, `requested_scope`, `control_id`. Markdown on COMPARE already states the three-way story in full. Same Studio limit as LAB-MCP-001.

### MEDIUM — LEARN authorization-path last line sits on the card fold

**Where:** LEARN (`pass1_learn.png`)

Path is visible through “requested scope granted?”; “ALLOW → handler” is tight against the three-state cards. Increase intro panel height slightly.

### MEDIUM — DEFEND unknown live tables are below the first fold

UNKNOWN SCOPE markdown (ERROR `unknown_scope`, not RETEST) is on the first screen. Q-MCP-AUTHZ / Q-MCP-SCOPE for `policy:write` require scroll. Acceptable if markdown stays; prefer tables higher.

### LOW — Submit button is Splunk default green

Out of scope to restyle. Not an AgentSec token.

### LOW — Token inputs ellipsis 36-character UUIDs

Playwright reads complete values. LEARN bullets show full ids.

---

## What is working (do not regress)

- Ten GRID tabs; Hunt defaults to BASELINE.
- Three scope states visually distinct on LEARN.
- BASELINE ALLOW `tool_granted`, scopes both `policy:read`, `execution_state=mcp.completed`.
- ATTACK fail-open ALLOW, requested `policy:restricted:read`, allowed still `policy:read`, `mcp.completed`.
- OBSERVE sequence: control.decision seq 3 before mcp.started seq 4.
- Q-MCP-SCOPE BASELINE `granted`.
- DETECT: 0 live AFTER-DENY rows; SIMULATED title and row.
- RETEST DENY `scope_not_granted`, `no_mcp_execution_event`, `prevented`.
- Empty-state copy is `noDataMessage`, not populated captions.
- No neon, no extra charts, no MLTK purple.
- Splunk does not ALLOW or DENY (dashboard description).

---

## Pass-1 verdict

No BLOCKER. Two HIGH findings (garbled grant sentence; EXECUTED column clip). Fix those, then recapture pass-2.

---

## Pass-2 (after HIGH fixes)

**Date:** 2026-09-12  
**App reload:** `./scripts/lab-up.sh --refresh-app` READY, then Playwright `--label pass2`.  
**Screenshots:** `docs/screenshots/lab-mcp-003/pass2_*.png`  
**Validation:** `docs/screenshots/lab-mcp-003/pass2_validation.json` — 10/10 tabs, five tokens MEASURED to Phase 4C LIVE ids.

### HIGH re-check

**Nested backticks / grant sentence — FIXED.** ATTACK / DEFEND / RETEST now read `allowed_scope stays the coded grant policy:read` with a space. No `grantpolicy:read`. OBSERVED on `pass2_attack.png`, `pass2_defend.png`, `pass2_retest.png`.

**HUNT EXECUTED clip — FIXED.** Q-MCP-EXECUTED is full width. Visible columns include `executed=false`, `has_started=1`, `has_completed=1`, `execution_state=mcp.completed`. OBSERVED on `pass2_hunt.png`. Q-MCP SPL unchanged.

### Residual (not HIGH)

- **MEDIUM** DETECT left table still uses Studio orange empty chrome. Caption still says 0 rows ≠ non-execution. SIMULATED right table still labeled. (`pass2_detect.png`)
- **MEDIUM** COMPARE third-width AUTHZ still clips `reason`. Markdown above the tables still states the three-way story in full. (`pass2_compare.png`)
- **MEDIUM** LEARN “Colons are opaque labels…” still sits on the fold over the three-state card headers. (`pass2_learn.png`) Same class as pass-1; not a security misclaim.
- **LOW** Token inputs still ellipsis 36-character UUIDs. LEARN bullets still show full ids. Playwright still reads complete values.
- **LOW** Submit remains Splunk default green.

Bonus vs pass-1: DEFEND unknown AUTHZ/SCOPE tables are on the first fold (`pass2_defend.png`). ERROR `unknown_scope` / `not_a_grant` visible without scrolling.

### Pass-2 roles (delta)

Instructor can now read the grant-unchanged sentence and the HUNT execution_state on canvas. Architect: Q-MCP still bind-only; SIMULATED still distinct from LIVE 0-row AFTER-DENY. SOC: Hunt still defaults to BASELINE A.

### Pass-2 verdict

No BLOCKER. No remaining HIGH. Residual MEDIUM/LOW accepted (Studio chrome, third-width clip, LEARN fold overlap, token ellipsis). Do not restyle Splunk login. Do not invent DET-MCP-003.
