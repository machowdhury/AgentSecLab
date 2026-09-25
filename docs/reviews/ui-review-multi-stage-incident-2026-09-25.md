# UI review: L9 multi-stage incident

Date: 2026-09-25

Evidence class: `OBSERVED` browser rendering from local Splunk Web.

## Journey

Home PATH displayed L9 and `AGENT-2026-009` while preserving Capstone as the
last LIVE launcher. All ten workbench tabs rendered:

INCIDENT → INVESTIGATE → TIMELINE → EVIDENCE → CONTROLS → DATA IMPACT →
RESPOND → THREAT MODEL → REPORT → PATH B.

The final reasoning was absent before Path B and visible on Path B. Progressive
hints, textual evidence states, request-to-outcome timeline language,
`NO EVIDENCE FOUND`, `INSUFFICIENT EVIDENCE`, and never-SAFE language were
visible. Markdown and Splunk table cells use native selection; no custom copy
widget exists.

## Widths and zoom

No document-level horizontal overflow appeared at 1920, 1440, 1280, or 1024
CSS pixels. At the 512 CSS-pixel responsive equivalent of 1024 at 200% zoom,
Splunk's native ten-tab strip overflowed horizontally. AgentSec content
reflowed; the native shell limitation is documented rather than hidden.

## Keyboard and focus

INCIDENT accepted focus, Arrow Right moved focus to INVESTIGATE, and Splunk
showed a visible inset blue focus ring.

## Accessibility

Keyboard/focus, semantic text, timeline presentation, evidence tables, hints,
and responsive behavior were checked. No screen reader was used, so status is
`PARTIAL / NOT TESTED`.

## Evidence

Structured observations and screenshots are stored under
`docs/screenshots/multi-stage-incident/`. They contain synthetic educational
content only.
