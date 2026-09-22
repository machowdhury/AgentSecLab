# UI review — Lending Assistant Investigation (2026-09-20)

**Surface:** `ws_lab_agentsec_capstone` + Attack Service `/labs/LAB-AGENTSEC-CAPSTONE-001`  
**Pass:** pass16b Playwright 1440 / 1280 / 1024  
**Screenshots:** `docs/screenshots/lab-agentsec-capstone/pass16b_*.png`, `docs/screenshots/attack-service-capstone/pass16b_*.png`  
**Validation JSON:** `docs/screenshots/lab-agentsec-capstone/pass16b_validation.json`

Studio tabs found: MISSION, ARCHITECTURE, ATTACK, INVESTIGATE, TRACE, AUTHORITY, DEFEND, RETEST, COMPARE, PROVE (10/10). Tokens: retrieve / write / recall dropdowns. Title is an investigation assignment, not “RAG Memory MCP Authorization Failure.”

## Roles

- SPLUNK ARCHITECT — GRID, bound existing Q-* hunts, no Q-CAPSTONE, DET-MCP-001 SIMULATED labeled, tokens exist.
- SOC ANALYST — Path A question first; starter index/sourcetype; copyable Path B SPL.
- UX DESIGNER — mission-first; numbered architecture; COMPARE in words not only color.
- TECHNICAL INSTRUCTOR — OBSERVE ≠ ALLOW; handler count authoritative; Splunk does not DENY; Goal/Identity 0 rows ≠ “did not happen.”

## Findings after pass16b restage

### BLOCKER

None.

### HIGH

None unresolved. Fixed before this pass: Splunk view 404 until `_reload`; dashboard description overflow; “REPLAY placeholder” copy after LIVE ids existed; Attack Service inline script syntax error (`Unexpected token ';'`) that blocked LIVE clicks.

### MEDIUM

- At 1024 the PROVE tab label clips to `PR`. COMPARE remains labeled. Studio still exposes the tab.
- Investigate-specimen dropdown labels truncate (`Baseline retrieve — d…`). Values remain selectable.
- Q-RAG / Q-MCP tables squeeze many columns. Expected Studio behavior; Path B SPL is the readable answer key.
- Attack Service page is long. Full-page screenshots look dense. Primary actions remain labeled.

### LOW

- Architecture is a numbered list, not a decorative diagram. It does not place Splunk on the enforcement path.

## Verdict

**PASS** for Phase 16B UI gate. No unresolved BLOCKER/HIGH.

Playwright UX launch ids are not the official Splunk pair. Official pair is in `docs/PHASE16B_CAPSTONE_LIVE_VALIDATION.md`.
