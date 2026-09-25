# UI review — External Security Toolbox

**Surface:** `ws_lab_external_evaluation_garak`
**Evidence:** rendered local Splunk Web screenshots and
`docs/screenshots/external-security-toolbox/final_validation.json`
**Tokens:** `#F6F8FB`, `#FFFFFF`, `#17202A`, `#0B1F33`; shared Studio helpers
**Tabs:** TOOLBOX, GUIDED, INVESTIGATE, CHALLENGE

## Splunk architect

PASS. The view is generated from
`scripts/build_lab_external_evaluation_garak_dashboard.py`, uses a 1440 GRID,
and binds repository search files. The two external sourcetypes remain
separate from `otel:agentic:json`. No saved search, detector, invented field,
or runtime schema field was added.

## SOC analyst

PASS. GUIDED identifies the canonical Cisco scan and garak evidence ID.
INVESTIGATE sends the learner to Search before showing the multi-plane answer
table. Native result, raw reference/hash, and correlation method are visible.
Empty tables remain visible and say `NO EVIDENCE FOUND`; they do not say safe,
blocked, or denied.

## UX designer

PASS at 1920, 1440, 1280, and 1024. No horizontal page overflow was observed
at those widths. The four-tab sequence reduces duplication while preserving
progressive depth. Reading order is top-to-bottom.

MEDIUM — 200% CSS zoom at a 1024 viewport produced document-level horizontal
overflow. The captured AgentSec content remained readable; the measured DOM
includes fixed Splunk Enterprise chrome that AgentSec does not own. Status is
`PARTIAL`, not compliant. Do not claim arbitrary Studio reflow or WCAG
certification.

MEDIUM — wide native evidence tables require table scrolling to inspect every
field. This is preferable to deleting provenance fields, but learners should
use Search for full-width analysis.

## Technical instructor

PASS. The purpose is visible immediately:

```text
RUNTIME EVENT != SCANNER FINDING != ADVERSARIAL EVALUATION
FINDING != AUTHORIZATION
EVALUATION != AUTHORIZATION
SPLUNK != PDP
CORRELATION != CAUSATION
```

The view distinguishes BUILT, INTEGRATED, and TAUGHT/REFERENCED by AgentSec.
GUIDED supplies why/what/where/predict before evidence. CHALLENGE asks what is
established, suggested, not established, and additionally required. Threat
model and framework content remain bounded and educational.

## Accessibility

- Keyboard: OBSERVED. Focus moved from TOOLBOX to GUIDED with ArrowRight.
- Visible state: OBSERVED. Selected/focused tab has text and visible blue
  treatment; status is not color-only.
- Widths: OBSERVED at 1920/1440/1280/1024 with no page overflow.
- 200% zoom: PARTIAL due document-level overflow described above.
- Copy controls: NOT APPLICABLE. This REPLAY view intentionally has no runtime
  run ID to copy.
- Error/no-data language: TESTED in generated JSON; dependency outage was not
  injected into Splunk Web, so browser behavior is PARTIAL.
- Screen reader: NOT PROVEN.

## Findings

- BLOCKER: none
- HIGH: none
- MEDIUM: 200% Studio/chrome overflow; wide evidence tables
- LOW: none

## Verdict

PUBLISH with accessibility classification `PARTIAL`. No BLOCKER/HIGH fix is
required. Preserve the residual findings as known limitations.
