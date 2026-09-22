# UI review — MCP reference post-build

**Date:** 2026-09-22
**Verdict:** PASS — 0 BLOCKER / 0 HIGH
**Evidence:** OBSERVED rendered UI plus MEASURED browser checks.

## Surfaces

- Attack Service: `LAB-MCP-001`
- Dashboard Studio: `ws_lab_mcp_001`

## Attack Service

The purpose is visible immediately: Tool Authorization, LIVE, mode, lab id, runtime health, and the security question. ATTACK and RETEST are primary actions. The closed browser boundary is explicit.

The result is shown as:

```text
PRINCIPAL → AGENT → REQUEST → AUTHORIZATION → EXECUTION → EVIDENCE
```

run.id is prominent, copyable, and paired with an investigation action. ATTACK ↔ RETEST uses aligned rows and textual SAME/DIFFERENT labels. Raw request/response/SPL details are behind `Evidence / Advanced`.

## Dashboard Studio

The reference workshop now has four areas:

1. MISSION
2. INVESTIGATE (Path A)
3. EVIDENCE
4. PATH B · ANSWERS

Existing validated Q-MCP searches were not changed. Path B no longer competes with the primary investigation.

## Resolutions and screenshots

Attack Service:

- 1920: `docs/screenshots/mcp-reference-workbench/checkpoint_attack_initial_1920.png`
- 1440 pair: `docs/screenshots/mcp-reference-workbench/checkpoint_attack_pair_1440.png`
- Advanced evidence: `docs/screenshots/mcp-reference-workbench/checkpoint_attack_advanced_1440.png`
- 1280: `docs/screenshots/mcp-reference-workbench/checkpoint_attack_initial_1280.png`
- 1024: `docs/screenshots/mcp-reference-workbench/checkpoint_attack_initial_1024.png`
- 200% zoom: `docs/screenshots/mcp-reference-workbench/checkpoint_attack_zoom200.png`

Studio:

- Final tab captures and 1920/1280/1024 variants under `docs/screenshots/lab-mcp-001/final_*.png`
- Validation record: `docs/screenshots/lab-mcp-001/final_validation.json`

## Accessibility

- Keyboard order begins with Skip to experiment then primary navigation.
- Visible focus rule observed.
- Semantic headings and table headers present.
- Controls have visible names.
- Status is expressed in text, not color alone.
- 200% zoom produced no horizontal document overflow.
- No overlap or document-width overflow at 1920, 1440, 1280, or 1024.
- Copy Run ID feedback is announced through an `aria-live` region.

Formal screen-reader behavior is **PARTIAL / NOT PROVEN**; no assistive technology session was run.

## Browser findings

- Console errors: 0
- Page errors: 0
- Attack comparison rows: 12
- Copy feedback: `Run ID copied. Use it to correlate this experiment.`
- Advanced response contained the RETEST run.id and the displayed request remained the four-field closed contract.
- Intercepted runtime-unreachable response rendered `ERROR`, explicitly said it was not a control DENY, and did not display a run.id.

## Residual findings

### LOW — Studio fixed-grid whitespace

Dashboard Studio retains some fixed-grid whitespace, especially on the concise MISSION tab. No clipping or overlap was observed. This is a platform/layout tradeoff, not a security defect.

### LOW — Non-MCP surfaces retain earlier density

The pattern has intentionally not been propagated beyond MCP.
