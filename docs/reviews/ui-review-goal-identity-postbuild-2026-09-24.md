# UI review — Goal Integrity and Identity postbuild

**Date:** 2026-09-24
**Surfaces:** Goal and Identity Attack Service workbenches; corresponding Studio workshops
**Evidence:** OBSERVED browser captures at 1920, 1440, 1280, and 1024; MEASURED LIVE runtime results; SIMULATED intercepted error states
**Verdict:** PASS — no blocker/high finding

## Goal workbench

- The initial viewport states the security question, server-owned task, granted tool, proposed objective, Goal control, and MCP PDP.
- The evidence chain separates effective action, supporting operation, and prohibited objective.
- RETEST visibly reports `lookup_policy` supporting handler 1 and wrong-goal handler 0.
- The comparison explicitly warns that total handler count alone is insufficient.
- Ten-second test: PASS. A learner can explain that permitted supporting execution and prohibited-objective execution are different facts.

## Identity workbench

- CLAIMED, ESTABLISHED IN LAB, and NOT MODELED appear before launch controls.
- Principal/caller/callee remain labeled CLAIMED in the chain and comparison.
- `WHO AUTHENTICATED = NOT PROVEN / NOT MODELED` is in the initial viewport and measured result.
- CTRL-IDENTITY-001 OBSERVE and CTRL-MCP-001 authorization are separate nodes.
- Ten-second test: PASS. A learner can identify the claim, actual authority evaluation, and absent authentication model.

## Responsive and interaction checks

- Initial and completed states: no document-level horizontal overflow at 1920/1440/1280/1024.
- CSS 200% zoom emulation: no document-level horizontal overflow.
- Keyboard: launch controls are reachable; visible focus styling is present.
- Copy run.id: works.
- Color independence: decisions and execution use text labels, counts, and reasons.
- Browser console: no errors before the intercepted-error exercise.
- Error state: browser-intercepted HTTP 503 is visibly `ERROR`; classified SIMULATED, not backend DENY.
- Evidence / Advanced: raw responses remain progressively disclosed.
- Screen reader: PARTIAL; no assistive-technology session was performed.

## Existing-workbench regression

- MCP: PASS at 1920/1440/1280/1024 and 200% zoom; ATTACK/RETEST comparison and Advanced rendered; no browser/page errors.
- RAG: PASS with fresh completed pair, Advanced, controlled error, and responsive captures.
- Memory: PASS with fresh completed pair, correlated IDs, Advanced, controlled error, and responsive captures.

## Studio review

- MISSION, INVESTIGATE, EVIDENCE, and PATH B · ANSWERS are present for both labs.
- Path A exposes a minimal starting search before hints and solutions.
- Goal Evidence leads with operation-specific interpretation.
- Identity MISSION makes assurance gaps visible.
- Fixed-grid whitespace is restrained on the primary tabs; the long legacy learning material remains in optional Path B.
- Splunk Web requests three optional platform resources that return 404 (`tenantinfo`, `structured_data_service`, and `appLogo.png`). These are documented platform-level console messages; no workshop visualization or data source failed to load.

## Residual limitations

- Localhost educational environment only.
- Screen-reader coverage remains PARTIAL.
- Studio has a separate Path B tab rather than dynamic disclosure.
- Browser screenshots prove rendered states, not universal usability or security effectiveness.
