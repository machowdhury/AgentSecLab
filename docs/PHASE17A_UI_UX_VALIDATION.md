# Phase 17A UI / UX validation

**Surface:** Home `ws_agentsec_home`, Mastery Check `ws_agentsec_mastery`, nav Mastery Check, beginner lab `ws_lab_pi_001`, Attack Service `/`  
**Pass label:** pass17a  
**Viewports:** 1440 / 1280 / 1024 (768 diagnostic only)  
**Screenshots:** `docs/screenshots/agentsec-academy-17a/`  
**Method:** repository XML/JSON review + Playwright after named-volume restage. Pytest does not prove rendering.

## Roles

- SPLUNK ARCHITECT — Mastery has no dataSources. No new detector. Schema 1.9.0 labeled on Home. Existing Q-* copied only as Path B text.
- SOC ANALYST — Path A + Search link + quoted run.id. Evidence classes on every challenge.
- UX DESIGNER — Same 16D visual language. Challenge cards. Competency tabs. Home is not a fifth giant dashboard.
- TECHNICAL INSTRUCTOR — Instructor prompt on INTRO. Path B optional. Not a certificate.

## Findings

### BLOCKER

None. Playwright pass17a `defects` is empty (`docs/screenshots/agentsec-academy-17a/pass17a_validation.json`).

### HIGH

None unresolved. Next-challenge copy uses human titles after restage (OBSERVED FOUNDATIONAL: “Next challenge: Rewrite the indefensible sentence.”).

### MEDIUM

- Path B remains visible on the same card as Path A. Disclosed. Studio 10.2 cannot hide it without unsupported JS.
- ADVANCED tab stacks four long cards; vertical scroll at 1024.
- FOUNDATIONAL / PURPLE TEAM ownership lines can sit below the first screen; dashboard scroll reaches them.
- REPLAY UUIDs are long; they are the Search key, not navigation.
- Home START leftover Studio block height (pre-existing 16D).

### LOW

- Splunk Enterprise login/chrome is not AgentSec-designed.

## Accessibility

Status words (LIVE, REPLAY, ALLOW, DENY, OBSERVE) are visible text. Color is not the only signal. WCAG certification is **not** claimed.

## Verdict

**PASS** for the Phase 17A UI gate. Playwright pass17a reports no BLOCKER/HIGH. Details in `docs/reviews/ui-review-agentsec-mastery-2026-09-21.md`.
