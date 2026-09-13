# UI review — `ws_lab_mcp_004` (LAB-MCP-004)

**Date:** 2026-09-13  
**Surface:** Dashboard Studio `ws_lab_mcp_004` (learner-facing). Splunk login/chrome not restyled.  
**Pass:** 1 written first; HIGH fixes then pass-2.  
**Screenshots:** `docs/screenshots/lab-mcp-004/pass1_*.png` (pass-1) and `pass2_*.png` (pass-2)  
**Validation:** `docs/screenshots/lab-mcp-004/pass1_validation.json` and `pass2_validation.json`  
**Tokens checked:** `run_id`, `baseline_run_id`, `attack_run_id`, `retest_run_id`, `unknown_run_id` (all five MEASURED in DOM)  
**Tabs checked:** LEARN, BASELINE, ATTACK, OBSERVE, HUNT, DETECT, DEFEND, RETEST, COMPARE, PROVE (10/10 clicked)  
**Evidence class:** screenshot findings are **OBSERVED**. JSON/XML contracts remain **DOCUMENTED**. Indexed table rows on BASELINE / ATTACK / OBSERVE / HUNT / RETEST / COMPARE are **OBSERVED** for Phase 5C specimen tokens. DETECT live hunt is empty (0 violations). DETECT right table is **SIMULATED**. Live CLI `Q-MCP-RESOURCE-AUTHZ` on the four tokens is **MEASURED**. This review does not re-MEASURE `dc(_raw)`.

Canonical tokens: `docs/AGENTSEC_DESIGN_SYSTEM.md`. Reference implementation: LAB-MCP-003 / LAB-MCP-001.

Playwright viewport is 1440×1100. Studio content scrolls inside the view, so `full_page` still captures the first canvas, not the GRID below the fold.

---

## Roles

### Splunk architect

GRID tabs load. Five tokens exist and Submit-on-load ran. Hunt defaults to BASELINE (no empty-token red `!`). Q-MCP and `Q-MCP-RESOURCE-AUTHZ` datasources returned indexed rows for BASELINE / ATTACK / RETEST / UNKNOWN. DETECT left table is empty (0 violations) with Studio’s default empty graphic. DETECT right table rendered one **SIMULATED** `makeresults` row labeled SIMULATED. Table `description` is populated-caption. Q-MCP bind-only; no DET-MCP-004. Schema copy says 1.2.0.

### SOC analyst

Can hunt: Hunt token is prefilled; specimen tabs bind Phase 5C ids. Cannot read a full 36-character UUID from the global inputs (ellipsis). LEARN specimen list is on the first screen (good). HUNT primary `Q-MCP-RESOURCE-AUTHZ` is on canvas; many columns wrap. COMPARE third-width AUTHZ tables clip `reason` (`vulnerable_profile_fail_open:resource_not_granted` wraps). OBSERVE shows control sequence 3 before `mcp.started` sequence 4.

### UX designer

Reading order of tabs is clear. White panels, navy headers, no neon, no extra charts, no MLTK purple. Markdown `fontSize: large`. LEARN three-column GRANTED / KNOWN BUT UNGRANTED / UNKNOWN RESOURCE is the right teaching layout but sits below the first 1100px canvas. Grant-unchanged prose is readable (no nested-backtick smash). DETECT orange empty chrome on a true 0-row hunt.

### Technical instructor

LEARN correctly separates LAB-MCP-001 (tool), LAB-MCP-003 (scope), and LAB-MCP-004 (resource). ATTACK states the tool is granted, the scope is granted, the resource is not, and fail-open is not a grant. RETEST shows DENY `resource_not_granted`, `no_mcp_execution_event`, `prevented`. DETECT labels SIMULATED and says zero rows are not independent proof. ALLOW ≠ execution is stated on BASELINE / HUNT / COMPARE. AllowTicket / duplicate-key / malformed teaching is in the LEARN markdown below the first fold.

### Accessibility

Body markdown is Studio `large`. Severity is labeled in text (ALLOW / DENY / ERROR / SIMULATED / BASELINE / ATTACK / RETEST / known_but_ungranted), not color alone. Token fields clip 36-character UUIDs visually; Playwright still reads the full value. Keyboard tab bar is Splunk chrome (clicked in Playwright; not a WCAG certification).

---

## Findings

### HIGH — LEARN first canvas hides the three resource-relation cards

**Where:** LEARN (`pass1_learn.png`)

The core visual lesson is GRANTED / KNOWN BUT UNGRANTED / UNKNOWN RESOURCE. Those cards start at GRID y=780. The captured canvas is 1100px including Splunk chrome, so the first screen ends at the authorization path. Specimen UUIDs are visible (good). The three states are not. Fix: shorten the LEARN intro so the three cards land on the first canvas. Move AllowTicket, duplicate-key, and malformed teaching into the existing parameter panel under the cards.

### MEDIUM — DETECT empty left table uses Studio’s orange warning chrome

**Where:** DETECT (`pass1_detect.png`)

Indexed `Q-MCP-AFTER-DENY` is correctly empty (0 violations). Caption teaching is right (`LIVE MCP-004 specimens: 0 rows`). Studio still shows a warning triangle and an unlabeled empty grid. Not a security misclaim. Same Studio limit as LAB-MCP-003.

### MEDIUM — COMPARE / HUNT / OBSERVE column headers clip

Third-width and wide resource tables truncate `reason`, `resource_id`, `allowed_resource.ids`. COMPARE markdown already states the three-way story in full. Do not rewrite Q-MCP SPL.

### MEDIUM — DEFEND unknown live tables are below the first fold

UNKNOWN RESOURCE markdown (ERROR `unknown_resource`, not RETEST) is on the first screen. Q-MCP-AUTHZ / Q-MCP-RESOURCE-AUTHZ for `does-not-exist` require scroll. Acceptable if markdown stays.

### MEDIUM — BASELINE / ATTACK / RETEST hunt tables sit below What Happened

Identity + decision tables are on the first canvas (good). Q-MCP-RESOURCE-AUTHZ and full-width EXECUTED require scroll. Captions already teach ALLOW ≠ execution.

### LOW — Submit button is Splunk default green

Out of scope to restyle. Not an AgentSec token.

### LOW — Token inputs ellipsis 36-character UUIDs

Playwright reads complete values. LEARN bullets show full ids.

### LOW — Dashboard description truncates in Splunk chrome

Title area clips after “Not DET-MCP-004. Splunk does not ALLOW or DENY a resource.” Teaching markdown repeats the claim.

---

## Pass-1 security semantics (no BLOCKER)

| Claim we must not make | Pass-1 observation |
|------------------------|--------------------|
| valid argument = authorized resource | LEARN/DEFEND distinguish malformed vs `executive-restricted` |
| tool granted = resource granted | ATTACK lists tool granted, resource not granted |
| scope granted = resource granted | HUNT says Q-MCP-SCOPE can be granted on MCP-004 ATTACK |
| known-but-ungranted = unknown | Separate cards / UNKNOWN panel |
| unknown_resource = DENY | DEFEND: ERROR ≠ DENY |
| ALLOW = execution | BASELINE/HUNT/COMPARE state the opposite |
| ALLOW fail-open = grant changed | ATTACK: grant stays lending-basics; resource was not granted |
| mcp.started = success | ALLOW_NOT_EXEC copy |
| mcp.failed = prevention | ALLOW_NOT_EXEC copy |
| no Splunk event = blocked | Empty copy is no-data, not DENY |
| Splunk authorized the resource | “Splunk does not ALLOW or DENY a resource” |
| SIMULATED = OBSERVED | DETECT right table title includes SIMULATED |

---

## Pass-1 verdict

No BLOCKER. One HIGH (LEARN three-state cards off the first canvas). Fix HIGH only, recapture, re-review.

---

## What is working (do not regress)

- Ten GRID tabs; Hunt defaults to BASELINE.
- BASELINE ALLOW `tool_granted`, `resource.id=lending-basics`, `execution_state=mcp.completed`.
- ATTACK fail-open ALLOW, resource `executive-restricted`, allowed still `lending-basics`, `known_but_ungranted`, `mcp.completed`.
- OBSERVE sequence: control.decision seq 3 before mcp.started seq 4; resource fields on the control row.
- HUNT primary `Q-MCP-RESOURCE-AUTHZ`; Q-MCP-SCOPE still `granted` on MCP-004 ATTACK.
- DETECT: 0 live AFTER-DENY rows; SIMULATED title and row.
- RETEST DENY `resource_not_granted`, `no_mcp_execution_event`, `prevented`.
- DEFEND: ERROR `unknown_resource` ≠ DENY; duplicate-key has no control.decision.
- Empty-state copy is `noDataMessage`, not populated captions.
- No neon, no extra charts, no MLTK purple.
- Splunk does not ALLOW or DENY a resource (dashboard description).

---

## Pass-2 (after HIGH fix)

**Date:** 2026-09-13  
**App reload:** `./scripts/lab-up.sh --refresh-app` restaged `ws_lab_mcp_004.xml`. Splunk Web HTTP 200. HEC health stayed empty-reply after the Splunk restart (lab-ready NOT READY). Indexed Phase 5C copies remained searchable. Playwright `--label pass2`.  
**Screenshots:** `docs/screenshots/lab-mcp-004/pass2_*.png`  
**Validation:** `docs/screenshots/lab-mcp-004/pass2_validation.json` — 10/10 tabs, five tokens MEASURED to Phase 5C LIVE ids.

### HIGH re-check

**LEARN three-state cards — FIXED.** First canvas now shows GRANTED / KNOWN BUT UNGRANTED / UNKNOWN RESOURCE plus the start of the parameter panel. Specimen UUIDs remain above the cards. OBSERVED on `pass2_learn.png`. AllowTicket / malformed / duplicate-key teaching moved into the parameter panel under the cards.

### Residual (not HIGH)

- **MEDIUM** UNKNOWN specimen bullet sits tight against the GRANTED card header (`pass2_learn.png`). Not a security misclaim.
- **MEDIUM** DETECT left table still uses Studio orange empty chrome. Caption still says 0 rows ≠ non-execution. SIMULATED right table still labeled. (`pass2_detect.png`)
- **MEDIUM** COMPARE third-width AUTHZ still clips `reason`. Markdown above the tables still states the three-way story in full. (`pass2_compare.png`)
- **MEDIUM** DEFEND unknown hunt tables remain below the first fold. UNKNOWN RESOURCE markdown (ERROR, not RETEST) is on the first screen.
- **LOW** Token inputs still ellipsis 36-character UUIDs. LEARN bullets still show full ids. Playwright still reads complete values.
- **LOW** Submit remains Splunk default green.

### Pass-2 roles (delta)

Instructor can now see the three resource relations without scrolling. Architect: Q-MCP still bind-only; SIMULATED still distinct from LIVE 0-row AFTER-DENY. SOC: Hunt still defaults to BASELINE A.

### Pass-2 verdict

No BLOCKER. No remaining HIGH. Residual MEDIUM/LOW accepted (Studio chrome, third-width clip, LEARN tight fold, token ellipsis). Do not restyle Splunk login. Do not invent DET-MCP-004.
