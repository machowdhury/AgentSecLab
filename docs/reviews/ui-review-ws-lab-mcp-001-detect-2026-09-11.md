# UI review — `ws_lab_mcp_001` DETECT tab (Phase 3E)

**Date:** 2026-09-12  
**Surface:** Dashboard Studio `ws_lab_mcp_001` DETECT tab only. Other tabs not re-reviewed.  
**Pass:** 1 (DETECT copy/layout after DET-MCP-001). No UI changes after this review (no BLOCKER/HIGH).  
**Screenshot:** `docs/screenshots/lab-mcp-001/detect_3e_detect.png`  
**Validation:** `docs/screenshots/lab-mcp-001/detect_3e_validation.json`  
**Tokens checked:** Hunt / BASELINE / ATTACK / RETEST (Playwright full UUIDs MEASURED)  
**Evidence class:** screenshot findings **OBSERVED**. Live SPL validation is in `docs/PHASE3E_MCP_DETECTION.md` (**MEASURED** / **SIMULATED**).

Canonical tokens: `docs/AGENTSEC_DESIGN_SYSTEM.md`.

---

## Roles (DETECT only)

### Splunk architect

Hunt table bound to `Q-MCP-AFTER-DENY` (indexed). Right table bound to `DET-MCP-001-POSITIVE-CONTROL` (`makeresults`). No `ds.savedsearch`. No `action.notable`. Dashboard description states DET-MCP-001 is packaged disabled.

### SOC analyst

Can tell hunt (left, 0 indexed rows) from detection teaching (markdown) and sensitivity fixture (right, SIMULATED). Hunt token defaults to BASELINE. Cannot see `mcp_start_sequence` without scrolling the SIMULATED table.

### UX designer

HUNT vs DETECTION heading is the reading-order win. Two-column split matches LAB-PI-001 / Phase 3D DETECT. Markdown `fontSize: large`. Studio orange empty chrome remains on the left table.

### Technical instructor

Copy states: no notable; DENY alone is not an alert; fail-open ALLOW is not this detection; `mcp.failed` after ALLOW is not DENY-then-start; ERROR is not DENY; Splunk does not enforce; SIMULATED is not OBSERVED; DET-MCP-001 did not fire on validated LIVE runs. Left empty is not captioned “Tool was blocked.”

### Accessibility

Severity/HIGH is a word. SIMULATED is a word in the table title. Token fields still ellipsis (Phase 3D residual). No WCAG claim.

---

## Findings

### BLOCKER

None.

### HIGH

None.

### MEDIUM — DETECT empty left table uses Studio’s orange warning chrome

Same residual as Phase 3D DETECT. Teaching caption is correct (“no indexed violation found”). Studio still shows a warning triangle + “No search results returned.”

### MEDIUM — SIMULATED detection columns clip

Title includes **SIMULATED**. Fixture row is visible (`simulated-det-mcp-001-0001`, DENY, deny_sequence 3). `mcp_start_sequence` and later columns are off-canvas. Markdown already states DENY seq 3 / `mcp.started` seq 4.

### LOW — Dashboard description truncates in Splunk chrome

The new description mentions DET-MCP-001 disabled and Splunk does not ALLOW/DENY; the last words clip in the header. Splunk chrome, not an AgentSec token.

---

## What is already good

- Hunt vs detection is explicit.
- SIMULATED is labeled in title, caption, and `evidence_class`.
- LIVE hunt table is empty as expected; not claimed as a firing detection.
- No neon, no extra charts, no MLTK purple.
- Tables stay visible when empty.

No BLOCKER/HIGH fix cycle for this DETECT-only change.
