# UI review — Capstone postbuild

**Date:** 2026-09-24  
**Surfaces:** Capstone Attack Service workbench and Splunk Studio workshop  
**Evidence:** OBSERVED Playwright captures and browser checks

## Result

The Capstone now presents an investigation rather than another teaching template.

Attack Service:

- initial mission identifies incident, attacker influence, sensitive outcome, boundaries, and first action without naming the final root cause
- ATTACK is the primary first action; RETEST remains available without an architectural rewrite
- an evidence map separates source, retrieval, persistence, recall, intent, authority, execution, and evidence
- RETRIEVE, WRITE, RECALL, and `source_run_id` explain what each ID identifies
- post-run facts separate INFLUENCE, INTENT, AUTHORITY, and EXECUTION
- comparison groups same bytes, changed server-owned profile, changed control result, changed execution, and changed outcome
- raw responses remain behind Evidence / Advanced
- ERROR remains distinct from DENY

Studio:

- four tabs: MISSION, INVESTIGATE, EVIDENCE, PATH B · ANSWERS
- Path A asks six causal questions with starting-search guidance and progressive hints
- EVIDENCE provides selected-packet tables without presenting them as enforcement
- Path B contains validated SPL, expected shape, interpretation, limitations, and the causal answer

## Learner test

Without opening Path B, a technically capable learner can derive:

1. what incident is under investigation
2. where the untrusted bytes entered
3. that exact bytes persisted into a later run
4. what privileged operation was requested
5. that context controls only OBSERVE
6. where tool authority was evaluated
7. what operation executed
8. what changed in RETEST
9. what Splunk corroborates
10. what authentication and universal effectiveness remain unproven

The initial ten-second view communicates a multi-stage investigation and the need to trace influence into action. It does not reveal the final decision or result.

## Automated browser checks

- Attack Service HTTP 200 at 1920, 1440, 1280, and 1024.
- No horizontal overflow at all four widths.
- No Attack Service console or page errors.
- Primary action focus outline: `solid 2px`.
- Advanced evidence opens and remains readable.
- SIMULATED ERROR STATE captured through browser request interception; it is not a measured backend failure.
- 200% zoom capture completed.
- Shared MCP, RAG, Memory, Goal, and Identity workbenches passed page-load, hierarchy, comparison, Advanced, focus, overflow, and console/page-error checks at 1440 and 1024.

## Findings

### BLOCKER

None.

### HIGH

None.

### MEDIUM

- Dashboard Studio fixed-grid evidence tables become dense at narrower widths. Path B SPL remains the readable detailed representation.
- Studio custom fresh run-ID binding remains unsupported; learners copy fresh IDs into Search.
- Studio emitted three generic resource-load console errors from local Splunk platform endpoints/static app chrome. No JavaScript page errors occurred and all four tabs loaded. This is not represented as a clean console.

### LOW

- Full-page completed screenshots are information-dense by design; the initial viewport remains compact.

## Accessibility

- semantic headings, ordered evidence chains, definition lists, tables, buttons, and live status are present
- state is labeled in words, not only color
- keyboard-focus visibility was measured on the primary action
- screen-reader validation remains **PARTIAL** because no assistive technology was used

## Evidence

- `docs/screenshots/attack-service-capstone/capstone-integration_*.png`
- `docs/screenshots/lab-agentsec-capstone/capstone-integration_*.png`
- `docs/screenshots/lab-agentsec-capstone/capstone-integration_validation.json`
- `docs/screenshots/lab-agentsec-capstone/capstone-integration_shared-regression.json`

## Verdict

**PASS** with documented local Dashboard Studio limitations. No unresolved BLOCKER/HIGH.
