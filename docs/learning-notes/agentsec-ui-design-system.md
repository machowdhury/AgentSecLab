# AgentSec UI Design System

## WHAT IS IT?

A small shared visual contract for learner-facing pages: AcmeBank, the Attack Service, and LAB-PI-001 Dashboard Studio. Palette, type, empty states, and “severity is never color alone.” It is not a component library and it does not restyle Splunk’s own chrome.

## WHY DOES IT EXIST?

Workshops fail as teaching tools when the page looks like a game, when ALLOW/DENY/SIMULATED are color-only, or when empty tables look like “all clear.” One parent doc (`docs/AGENTSEC_DESIGN_SYSTEM.md`) stops Splunk docs and Flask templates from drifting into two palettes.

## HOW DOES IT WORK?

Tokens are hex in the parent doc. Flask pages use CSS variables. Studio sets markdown `fontColor`, table header navy/white, and page `#F6F8FB`. `/ui-review` (`.cursor/skills/ui-review/SKILL.md`) writes a review before fixing BLOCKER/HIGH.

Secondary text is `#3D4654`, not `#5B6573` (that pair fails WCAG AA on the page background).

## WHERE DOES IT SIT IN AGENTSEC?

Beside Splunk design rules (GRID, workshop skeleton). After provisioning. Before calling a dashboard “complete.”

## WHAT IS THE TRUST BOUNDARY?

Unchanged. Paint does not authorize. The Attack Service button is labeled **Fire ATK-002** so red is not the only signal.

## WHAT COULD AN ATTACKER CONTROL?

Still `input` / `user_id`. Not CSS tokens, not Studio markdown.

## WHAT CAN GO WRONG?

Treating Splunk’s green Submit as an AgentSec token. Shrinking type to fit more panels. Using MLTK purple on the first lab. Calling screenshot review a control test.

## WHAT TELEMETRY SHOULD EXIST?

None from the design system itself. Dashboards still emit nothing; AcmeBank still emits schema 1.0.0.

## HOW WILL SPLUNK SHOW IT?

Navy table headers, white panels, labeled SIMULATED, GRID tabs. Screenshot evidence lives under `docs/screenshots/lab-pi-001/`.

## WHAT CONTROL COULD CHANGE THE RESULT?

None. CTRL-INPUT-001 is independent of color.

## WHAT TEST PROVES THE LOGIC?

`tests/unit/test_design_system.py` proves tokens exist in the parent doc and Flask pages. `tests/splunk/test_lab_pi_001_dashboard.py` proves Studio binding. Playwright capture proves tabs/tokens in Splunk Web when it is actually run.

## What I should now be able to explain

1. Why AgentSec has a parent UI design system instead of “whatever Splunk defaults are.”
2. Why `#5B6573` is banned for captions on `#F6F8FB`.
3. Why SIMULATED must be a word, not a green tile.
4. Why Flask buttons are ≥44px and use `focus-visible`.
5. Why `/ui-review` forbids fixing before the report is written.
6. Why Hunt `run.id` now defaults to the BASELINE specimen (Studio empty-token state).
7. Why Splunk login is out of scope to restyle.
8. Why COMPARE empty on a fresh volume is not DENY.
9. What `/ui-review` four roles are.
10. What still does not prove INV-008.
