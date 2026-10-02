# AGENTSEC v1.1 TARGETED FINAL UI REMEDIATION

Starting Commit: `4447ec586d972484e2e1bb96643f592893578e98`

Ending Commit: the review commit that adds this file, after `b10eb768356cc9ab4443388160e6ef2a12c70e4d`

Remote Sync: implementation `b10eb76` is on `origin/develop`. This report is pushed with it.

MEDIUM Findings Addressed: Academy Home mark size. The rendered mark is no longer about 1360×1360.

MEDIUM Findings Remaining: Dashboard Studio keyboard focus. The rendered page still does not load the app stylesheet. A focused native tab still has `outline-style: none`.

Dashboard Studio Focus: NOT FIXED. MEASURED on `ws_lab_a2a_auth_delegation` after the app refresh.

CSS Packaged: PACKAGED. `agentsec_studio_focus.css` is still in the app and the `stylesheet` attribute is still on the view XML. Splunk 10.2 Dashboard Studio's own bundle sets `stylesheet: false`. The Studio page template links only Splunk stylesheets. The view controller returns before the classic CSS loader runs.

CSS Loaded In Rendered Studio Page: NOT LOADED. The rendered document stylesheets were `bootstrap-enterprise.css` and `splunk-dashboard-studio/build/editor.main.css`. `agentsec_studio_focus.css` was absent.

Focused Element: `BUTTON` with `role="tab"`, text `CLAIMS`. `document.activeElement` was that tab after `focus({focusVisible: true})`.

Computed outline-style: `none`

Computed outline-width: `3px` with style `none`, so the outline is not painted. The color was Splunk's `rgb(0, 110, 170)`, not the AgentSec teal.

Computed outline-color: `rgb(0, 110, 170)`

Computed box-shadow: `none`

Visible Focus: NOT RENDERED. `:focus-visible` did not match. A mouse click on the same tab also left `outline-style: none` and `box-shadow: none`.

Physical Keyboard Tab: NOT MEASURED. The focus above was `HTMLElement.focus({focusVisible: true})` in headless Chrome, not a physical key.

Academy Home Branding: RENDERED. The START tab shows the mark through a `splunk.image` visualization, 64×64 in the definition, `preserveAspectRatio: true`. The unconstrained markdown image was removed.

Natural Mark Size: 150×150. MEASURED `naturalWidth` and `naturalHeight`. The SVG file has a 64×64 view box and no width or height attribute. The browser reports 150×150 as the intrinsic size.

Rendered Mark Size Before: about 1360×1360. That figure is from the independent review of `4447ec5`. This pass did not re-measure the old page.

Rendered Mark Size After: MEASURED. 56×56 at 1920, 55×55 at 1440, 47×47 at 1280, 36×36 at 1024. At CSS zoom 200% on a 1024 CSS-pixel width the mark was 66×66.

Aspect Ratio Preserved: yes. Every measured box was square.

Horizontal Overflow: none at 1920, 1440, 1280, and 1024 on Academy Home and on the A2A Studio workshop. `scrollWidth` equaled `clientWidth`. CSS zoom 200% on Home made `scrollWidth` 1920 against `clientWidth` 1024. That zoom was `documentElement.style.zoom`, not the browser zoom menu.

Session History Regression: TEST. The existing session-history assertions passed in the offline suite. This pass did not reload Attack Service in the browser.

Comparison Rehydration Regression: TEST. The pairing contract passed. Not re-measured live in this pass.

Remote Navigation Regression: TEST. The listener and learner-navigation assertions passed. Not re-measured live in this pass.

Answer Leakage Regression: TEST. The LAB-PI-001 page assertion that `input_pattern_matched` is absent before launch passed. Not re-measured live in this pass.

Schema: `1.9.0`

ExternalEvidence: `1.0.0`

DET-MCP-001: still disabled. Not edited.

CTRL-MCP-001: unchanged. Not edited.

Focused Tests: 22 passed (learner console, Home dashboard, session contract, web UI, remote listener).

Full Offline Tests: `1085 passed, 3 deselected` in 8.77s. Marker `not live_ollama and not live_splunk`.

1920: Home and the A2A workshop, no page-level horizontal overflow. OBSERVED.

1440: same.

1280: same.

1024: same. The mark rendered at 36×36.

200% Zoom: CSS zoom on Home. The mark stayed 66×66. The page `scrollWidth` exceeded `clientWidth`. Browser zoom menu: NOT MEASURED.

Keyboard: programmatic focus only. Physical Tab: NOT MEASURED. Visible focus on the Studio tab: not rendered.

Screen Reader: NOT TESTED

WCAG Claim: none

Secret Hygiene: `.env` was not committed. The diff has no private key, token, or certificate. No cryptographic implementation was added. Codeguard: this change does not add credentials, certificates, or crypto.

BLOCKER: 0

HIGH: 0

MEDIUM: 1. Dashboard Studio native tab focus is still not visible because the app stylesheet is not loaded.

LOW: 0 new. Screen reader and physical keyboard remain untested. Academy CSS-zoom overflow is a measurement of `style.zoom`, not a new layout defect at 100%.

Main Modified: no

v1.0.0 Modified: no

v1.1.0 Created: no

GitHub Release Created: no

Git Status: untracked `docs/plans/` and `docs/reviews/AGENTSEC_REMOTE_DEPLOYMENT_VALIDATION.md` stay untracked. They are not part of this change.

FINAL VERDICT:

CONDITIONAL — INDEPENDENT VALIDATION STILL REQUIRED

The Home mark is RENDERED at logo size. Studio focus was MEASURED and is not fixed. Splunk 10.2 does not apply an app stylesheet to Dashboard Studio, and this pass did not patch Splunk's JavaScript or installation files.
