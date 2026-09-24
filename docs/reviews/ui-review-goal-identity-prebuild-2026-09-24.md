# UI review — Goal Integrity and Identity prebuild

**Date:** 2026-09-24
**Surfaces:** Goal and Identity Attack Service pages; `ws_lab_agent_goal_integrity`; `ws_lab_agent_delegation`
**Evidence:** DOCUMENTED current templates, generated Studio definitions, and existing screenshots
**Verdict:** REVISE — 0 BLOCKER / 5 HIGH

## Roles

### Splunk architect

Existing Q-GOAL, Q-AGENT-DELEGATION, and Q-MCP searches already encode the required evidence claims and should remain byte-identical. The defect is information architecture, not SPL.

### SOC analyst

Both ten-tab workshops contain correct evidence but fragment one investigation across many tabs. Goal execution is especially easy to misread because generic MCP execution tables do not make the purpose-specific wrong-goal versus in-task counts primary.

### UX designer

Both Attack Service pages use the legacy documentation-first template. The initial viewport competes with long teaching cards, predictions, raw-oriented results, and generic comparison rows. The shared stylesheet is named after MCP despite supporting three workbench domains.

### Technical instructor

Goal copy states the correct rule, but its structure does not make the critical RETEST result immediate: `lookup_policy` executes once while the prohibited objective remains at zero. Identity shows the authentication limitation, but CLAIMED, ESTABLISHED IN LAB, and NOT MODELED are not visually separated.

## HIGH findings

1. **Goal operation semantics are not visually primary.** Generic handler totals can make RETEST handler 1 look like defense failure.
2. **Goal objective and sub-action outcomes are conflated.** Effective goal, wrong-goal execution, and in-task execution need separate rows.
3. **Identity claims look too similar to established runtime facts.** Unverified strings need explicit CLAIMED styling and labels.
4. **Authentication limitations are buried among long explanation cards.** `NOT MODELED` must be visible in the default viewport.
5. **Studio Path A and Path B compete in the same long notebook.** Correct answer material should move to the optional answer tab.

## Required corrections

- Safely rename `mcp-workbench.css` to shared `agentsec-workbench.css` and regression-test MCP/RAG/Memory.
- Give Goal an operation-aware chain and comparison with separate wrong-goal and in-task counts.
- Give Identity a claim/delegation/authority chain and explicit assurance classification.
- Reduce Studio to MISSION, INVESTIGATE, EVIDENCE, and PATH B · ANSWERS while preserving all existing visualizations/data sources.
- Preserve all validated SPL bytes.
- Keep raw responses under Evidence / Advanced.

## Accessibility gate

Validate textual state labels, keyboard order, visible focus, wrapping, no horizontal overflow, and 200% zoom. Screen-reader behavior remains PARTIAL without an assistive-technology session.
