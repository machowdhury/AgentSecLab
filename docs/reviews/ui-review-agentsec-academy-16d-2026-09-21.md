# UI review — AgentSec Academy packaging (2026-09-21)

**Surface:** Home `ws_agentsec_home`, grouped nav, Attack Service `/`, beginner LIVE `ws_lab_pi_001`, context `ws_lab_rag_context`, authority `ws_lab_agent_goal_integrity`, capstone `ws_lab_agentsec_capstone`  
**Pass:** pass16d Playwright 1440 / 1280 / 1024  
**Screenshots:** `docs/screenshots/agentsec-academy-16d/pass16d_*.png`  
**Validation JSON:** `docs/screenshots/agentsec-academy-16d/pass16d_validation.json`

Home tabs found: START, ORIENT, PATH, SPLUNK. Nav collections: Foundations, Context Security, Agent Intent, Capstone. Attack Service “Where you are” OBSERVED.

## Roles

- SPLUNK ARCHITECT — Home has no dataSources. Labs keep bind-only Q-*. No new detector. Schema 1.9.0 labeled.
- SOC ANALYST — Path A first on PI HUNT; Search link; quoted `run.id`; bootcamp on Home SPLUNK.
- UX DESIGNER — Start here + Direct Prompt Injection is the primary action. Menus are human titles. PATH is curriculum, not build order.
- TECHNICAL INSTRUCTOR — Splunk does not grant. LIVE vs REPLAY labeled. Path B is an answer key. Capstone is graduation.

## Findings after pass16d restage

### BLOCKER

None.

### HIGH

None unresolved. Fixed during 16D: Home identity “not published” / missing capstone (16C P0); capstone-before-Goal/Identity nav (16C P0); PATH effort line glued to the last REPLAY lab (Studio list eating a following paragraph). Recapture after restage shows effort on the level heading.

### MEDIUM

- Home START hero has leftover Studio block height (whitespace under the loop sentence). Readable; not a journey block.
- Attack Service page is long. At 1024 the lab-switch wraps and `.facts` stays two-column until 768. Labels remain textual.
- Path B remains on the same HUNT/INVESTIGATE tab after hints. Disclosure is present. Studio 10.2 cannot hide it without unsupported JS.
- Capstone PROVE tab label may clip at 1024 (`PR`). Pre-existing Studio chrome. Tab still selectable.
- Investigate-specimen dropdown labels truncate. Values remain selectable.

### LOW

- REPLAY workshops still name the tab HUNT.
- Splunk Enterprise login/chrome is not AgentSec-designed.
- Home ORIENT inequalities use `!=` ASCII (Studio markdown). Meaning is textual.

## Accessibility

Status words (LIVE, REPLAY, ALLOW, DENY, OBSERVE) are visible. Color is not the only SAME/DIFFERENT signal on COMPARE (pre-existing). Flask skip-link preserved. WCAG certification is **not** claimed.

## Verdict

**PASS** for Phase 16D UI gate. No unresolved BLOCKER/HIGH on changed critical surfaces.
