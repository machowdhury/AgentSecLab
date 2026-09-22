# UI review — AgentSec Academy fresh learner (2026-09-21)

**Surface:** Home, Direct Prompt Injection, Tool Authorization, RAG, Memory, Goal Integrity, Identity / Delegation, Capstone, Mastery Check, Attack Service  
**Pass:** pass17b Playwright 1440 / 1280 / 1024  
**Screenshots:** `docs/screenshots/agentsec-academy-17b/pass17b_*.png`  
**Validation JSON:** `docs/screenshots/agentsec-academy-17b/pass17b_validation.json`  
**Class:** OBSERVED (Playwright after named-volume restage + Attack Service image rebuild). Pytest does not prove rendering.

Home tabs OBSERVED: START, ORIENT, PATH, SPLUNK. Labs OBSERVED: PI, MCP-001, RAG, Memory, Goal, Identity, Capstone. Mastery FOUNDATIONAL OBSERVED. Attack Service “Where you are” OBSERVED. Defects array empty.

## Roles

- SPLUNK ARCHITECT — no new dataSources, no new Q-*, no new DET-*. Schema 1.9.0 on Home ORIENT.
- SOC ANALYST — Path A still lives in Search. Empty ≠ DENY on Attack Service handoff. REPLAY not labeled LIVE EVIDENCE.
- UX DESIGNER — 16D design system. WHY/PREDICT on Goal and Capstone ATTACK. Persona C skip on Home START. Human CONNECT titles.
- TECHNICAL INSTRUCTOR — why-before-click; overlay / fingerprint / source_run_id on ORIENT; Mastery NONE without Search.

## Findings after pass17b restage

### BLOCKER

None.

### HIGH

None. Capture assertions passed: Home skip; ORIENT fingerprint and source_run_id; Goal/Capstone WHY+PREDICT; Memory Launch ATTACK (LIVE); Capstone PROVE contains Mastery Check; Mastery FOUNDATIONAL “You do not need Splunk Search”; Attack Service EVIDENCE READY and Empty Search is not DENY.

### MEDIUM

- Path B remains visible beside Path A (Studio 10.2). Disclosed. Not a 17B architecture change.
- Capstone PROVE “NEXT Mastery Check” sits below the first screen at 1440 (after Debrief). Scroll reaches it. Same class as other tall PROVE cards.
- Investigate dropdown labels still truncate (“Baseline — defende…”) at 1440.
- Home START still has unused canvas under the hero before the two cards (16D density).
- Attack Service is a long single page; the educational strip is correct but dense.

### LOW

- Splunk Web Edit / Actions chrome is product chrome, not Academy copy.
- Goal ATTACK still shows the canonical REPLAY UUID in the specimen list. It is labeled REPLAY, not a fresh launch.

## Verdict

No unresolved BLOCKER or HIGH learner-facing defects on the captured surfaces. Phase 17B UI review **PASS**.
