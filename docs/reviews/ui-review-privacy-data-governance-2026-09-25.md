# UI review: L8 privacy and data governance

Date: 2026-09-25

Evidence class: `OBSERVED` browser rendering from local Splunk Web.

## Journey

The Home PATH includes L8, `PRIV-2026-001`, and preserves the Capstone as the
last LIVE launcher. All eight tabs rendered:

FOUNDATIONS → DATA MAP → TRACE → INVESTIGATE → MINIMIZE → THREAT MODEL →
DESIGN → PATH B · REVIEW.

The bounded reference conclusion was absent from earlier tabs and present only
on Path B. Progressive hints, synthetic labeling, `NO EVIDENCE FOUND`, and
`not SAFE` language were visible. Text is natively selectable; there is no
custom copy widget.

## Widths and zoom

At 1920, 1440, 1280, and 1024 CSS pixels the document reported no horizontal
overflow. At the 512 CSS-pixel responsive equivalent of 1024 at 200% zoom,
Splunk's native tab strip produced horizontal overflow. This is documented as
a Splunk-native shell limitation; the AgentSec markdown blocks reflowed.

## Keyboard and focus

The FOUNDATIONS tab accepted focus. Arrow Right moved focus to DATA MAP.
Splunk rendered a visible inset blue focus ring (`box-shadow`). Tab labels and
content remained keyboard reachable.

## Accessibility

Keyboard/focus and responsive checks were performed. No screen reader was
used, so screen-reader and overall accessibility status remain `PARTIAL`.

## Evidence

Structured observations and screenshots are under
`docs/screenshots/privacy-data-governance/`. Screenshots contain only the
synthetic educational workbench.
