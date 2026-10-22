# Attack UI accessibility: the four serious colour-contrast defects (Batch 8)

## The defect
Four Attack UI lab pages (`/labs/LAB-RAG-CONTEXT`, `LAB-MEMORY-001`, `LAB-AGENT-GOAL-INTEGRITY-001`, `LAB-AGENT-DELEGATION-001`) each had one *serious* axe `color-contrast` violation, identical in the baseline and every later build: the helper line under the teal **Launch RETEST (LIVE)** button, `<small>Same closed specimen family. The decision is still not printed here.</small>`, measured **4.31:1** (white at 92% opacity on the brand teal `#007f86`, 12.5 px) against the WCAG AA minimum of 4.5:1.
Cause: `src/agentsec/static/agentsec-workbench.css`, rule `.mode-actions small { ... opacity: .92; }`.

## The fix (one declaration)
`opacity: .92` became `opacity: 1`. White on `#007f86` is **4.79:1**. Nothing else changed: same colour tokens, font size (.78rem), weight, spacing, layout, copy and controls. The red ATTACK button's hint also becomes fully opaque (it already passed; it now passes with more margin).
A test proves the scope: restoring the one declaration to `.92` reproduces the baseline file's SHA-256 exactly (`test_the_contrast_fix_changed_one_declaration_and_removed_nothing`).

## Results
| Check | Before | After |
|---|---|---|
| axe serious/critical on the 4 pages | 1 each (4 total) | **0** |
| axe serious/critical on all 9 Attack UI pages (`/`, `/acmebank`, 7 lab pages), in-process, Chromium | 4 | **0** |
| Same 9 pages plus Academy home, path and the Loan Desk mission, **on the deployed lab** | 4 | **0** (`axe_live_attack_ui.json`) |
| Remaining axe findings | `region` (moderate) on the 7 lab pages: the "Skip to the lesson" link sits outside any landmark | unchanged: pre-existing, moderate, not part of this request; fixing it would add a landmark to the shared header |
| Contrast with the RETEST button disabled/enabled and after a launch | failing | passing in both states and after a launch |
| Every visible, enabled, focusable control reachable by Tab (9 pages) | not tested | pass (controls that cannot take focus, such as inactive stepper steps and collapsed content, are excluded by trying to focus them) |
| ATTACK and RETEST launch controls operated from the keyboard alone (Enter, Space), visible focus indicator present (4 pages) | not tested | pass; launch results appear |
| Controls and headings removed against the baseline browser walk | n/a | **none**: button, input and link counts on every page are at least the baseline's, and every baseline h1/h2/h3 is present |
| Visual design | | unchanged: the only visual change is the hint text now fully white instead of 92% white |

Tests: `tests/ui/test_attack_ui_accessibility.py`, 36 cases, all passing (axe on 9 pages; contrast in both button states and after a launch on 4 pages; Tab reachability on 9; keyboard launch on 4; one-declaration proof; no control or heading lost on 9).

## Not covered
Screen-reader announcement quality (axe is not a screen reader); a keyboard-only or screen-reader participant (the pilot recruits one if available); the pre-existing moderate `region` finding above.
