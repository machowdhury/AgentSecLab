# UI review — Capstone prebuild

**Date:** 2026-09-24  
**Surface:** Attack Service Capstone launcher and `ws_lab_agentsec_capstone`  
**Evidence:** DOCUMENTED inspection of templates, builder, generated dashboard, tests, and prior screenshots

## Purpose

The Capstone should evaluate whether a learner can reconstruct how untrusted influence became a privileged request, where authority was decided, what executed, and which server-owned change altered RETEST.

## Current strengths

- Canonical runtime semantics and three-run correlation are already exposed.
- Existing Studio searches reuse validated RAG, Memory, MCP, Goal, and Identity hunts.
- Runtime handler count is correctly distinguished from Splunk corroboration.
- No Capstone detector or schema extension exists.
- Existing content repeatedly preserves OBSERVE != ALLOW and Splunk != enforcement.

## Findings

### HIGH

1. **Attack Service remains the legacy all-lab page.** Capstone-specific content is embedded in a long generic launcher with duplicated prediction, specimen, execution, handoff, comparison, and raw response sections. The initial view exposes expected outcomes and control conclusions rather than establishing an investigation.
2. **Studio has ten tabs and reveals the answer early.** ARCHITECTURE, ATTACK, DEFEND, and RETEST copy name the exact PDP, expected decisions, and handler counts before the learner investigates.
3. **Influence, intent, authority, and execution are not presented as four distinct evidence questions.** The current pages are accurate but dense; a learner can read the answer rather than derive it.

### MEDIUM

1. Correlation IDs are presented as many UUID fields without a compact explanation of what each identifies.
2. The causal model is mostly linear prose and tables; the supported eight-stage chain is not a compact evidence map.
3. Studio Path A is split across INVESTIGATE, TRACE, and AUTHORITY while answer material occupies several other tabs.
4. ATTACK and RETEST are visually peers. Capstone should make ATTACK the first investigation action without changing the API.
5. Prior Studio validation recorded fixed-grid clipping at 1024 and truncated dropdown labels.

### LOW

1. Advanced evidence exists but the legacy raw response block is not tailored to Capstone correlation.
2. The initial mission names too many determinations at once.

## Design decision

Implement one Capstone-specific template using `agentsec-workbench.css`; do not fork shared workbench CSS. Preserve the four-field launch contract and runtime semantics.

Attack Service hierarchy:

1. Mission and security question without naming the root cause.
2. Compact evidence map and actual trust boundaries.
3. ATTACK-first action, with RETEST secondary but available.
4. Three-run correlation with RECALL labeled as primary.
5. Post-run causal graph and separate Influence / Intent / Authority / Execution facts.
6. Learner hypothesis prompts.
7. Grouped ATTACK↔RETEST proof.
8. Evidence / Advanced raw responses.

Studio hierarchy:

1. MISSION
2. INVESTIGATE
3. EVIDENCE
4. PATH B · ANSWERS

Path A will ask six questions and use progressive hints. Existing validated searches remain the answer key in Path B.

## Ten-second target

The initial view should communicate: this is a multi-stage incident; the learner must trace influence into action and find the control that changed the result. It must not disclose the final control result in that interval.

## Accessibility and validation plan

- Use semantic headings, lists, tables, buttons, status regions, and visible text labels.
- Preserve keyboard access and visible focus from the shared stylesheet.
- Ensure color is never the only state cue.
- Validate 1920, 1440, 1280, 1024, and 200% zoom.
- Validate initial, completed, comparison, Advanced, and SIMULATED ERROR states.
- Screen-reader coverage remains PARTIAL unless actual assistive technology is used.

## Prebuild verdict

**REVISE.** Runtime semantics are sound; the Capstone information architecture does not yet evaluate investigation reasoning.
