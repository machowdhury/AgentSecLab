# UI review — AgentSec Mastery Check (2026-09-21)

**Surface:** Home `ws_agentsec_home`, Mastery Check `ws_agentsec_mastery`, nav Mastery Check, `ws_lab_pi_001`, Attack Service `/`  
**Pass:** pass17a Playwright 1440 / 1280 / 1024  
**Screenshots:** `docs/screenshots/agentsec-academy-17a/pass17a_*.png`  
**Validation JSON:** `docs/screenshots/agentsec-academy-17a/pass17a_validation.json`

Home tabs OBSERVED: START, ORIENT, PATH, SPLUNK. Mastery tabs OBSERVED: INTRO, FOUNDATIONAL, PRACTITIONER, INVESTIGATOR, ADVANCED, PURPLE TEAM, RUBRIC. Nav: Foundations, Context Security, Agent Intent, Capstone, Mastery Check, Search. Attack Service “Where you are” OBSERVED. Defects array empty.

## Roles

- SPLUNK ARCHITECT — Mastery has no dataSources. Path B is copyable existing Q-* text. No new detector. Schema 1.9.0 on Home.
- SOC ANALYST — Path A, Search link, quoted specimen run.id, evidence classes on each card.
- UX DESIGNER — Same 16D language. Challenge cards. Home primary action remains Direct Prompt Injection; Mastery Check is secondary.
- TECHNICAL INSTRUCTOR — INTRO instructor prompt. Not a certificate. Path B disclosed as unhideable.

## Findings after pass17a restage

### BLOCKER

None.

### HIGH

None unresolved. Fixed during 17A: next-challenge labels used internal `MA-*` ids (learner-facing). Restaged copy uses titles (OBSERVED: “Next challenge: Rewrite the indefensible sentence.”). Official capstone ids labeled “official REPLAY ATTACK/RETEST recall”.

### MEDIUM

- Path B remains visible on the same card as Path A. Disclosed on INTRO. Studio 10.2 cannot hide it without unsupported JS.
- FOUNDATIONAL / PURPLE TEAM cards are tall; ownership lines sit below the first screen at 1440. Dashboard scroll still reaches them.
- ADVANCED stacks four challenges; vertical scroll at 1024.
- Home START still has leftover Studio block height (pre-existing 16D).

### LOW

- Splunk Enterprise login/chrome is not AgentSec-designed.
- Investigate-specimen dropdown labels truncate on PI (pre-existing).
- Attack Service full-page capture is long; labels remain textual.

## Accessibility

LIVE / REPLAY / ALLOW / DENY / OBSERVE are visible words. WCAG certification is **not** claimed.

## Verdict

**PASS** for Phase 17A UI gate. No unresolved BLOCKER/HIGH on changed critical surfaces.
