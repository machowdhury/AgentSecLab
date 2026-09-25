# UI review — ws_lab_advanced_capstone

**Date:** 2026-09-25
**Surface:** `ws_lab_advanced_capstone` after `./scripts/lab-up.sh --refresh-app`
**Evidence:** `docs/screenshots/advanced-capstone/final_validation.json`
**Rendering:** OBSERVED
**Accessibility:** PARTIAL
**Screen reader:** NOT TESTED

## What was exercised

All 11 tabs were opened: MISSION, ARCHITECTURE, INVESTIGATE, EVIDENCE, TIMELINE, DATA, CONTROLS, DETECT & HUNT, RESPOND, REPORT, PATH B.

Home shows L10, MASTER-2026-001, and that the LIVE capstone remains the last launcher.

Mission text contains the business context, architecture, window, Splunk sourcetypes, and deliverables. It does not contain a canonical run identifier or a hypothesis disposition. Path B contains `H2 disposition is REFUTED`. That sentence is absent from the earlier tabs' visible text.

Keyboard: focus moved from MISSION to ARCHITECTURE with Arrow Right. The focused tab used a visible blue inset outline (`rgb(0, 110, 170)`).

Widths 1920, 1440, 1280, and 1024 had no horizontal overflow on the mission viewport measurement. At a 512 CSS-pixel viewport (200% of 1024), horizontal overflow was true. The Splunk header clipped the dashboard description, and the tab strip wrapped. Screen reader was not tested.

Failure copy visible before Path B: NO EVIDENCE FOUND, INSUFFICIENT EVIDENCE, Never write SAFE.

Copy is native selectable markdown and table text. There is no custom copy widget.
