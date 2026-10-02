# AGENTSEC DASHBOARD STUDIO FOCUS FINAL REVIEW

Starting Commit: `a381e5f020d89154c6b3e3889476dcc16582963a`

Ending Commit: the review commit that adds this file, after `545c3d93f1be55152fcb394b45e5637633714585`

Remote Sync: implementation `545c3d9` is on `origin/develop`. This report is pushed with it.

Observed Splunk Version: Splunk 10.2.6 (build `bcdcf0552e0c`). OBSERVED from `splunk version` inside the running container after the app refresh.

## ROOT-CAUSE ANALYSIS

Dashboard Studio CSS Loading: NOT LOADED. On `ws_lab_a2a_auth_delegation` the document stylesheets were only `bootstrap-enterprise.css` and `splunk-dashboard-studio/build/editor.main.css`. MEASURED after this change was deployed.

Classic App CSS Loading: SUPPORTED for classic Simple XML. `view.py` collects `stylesheet` and `dashboard.css` only on the simple-XML path. The Studio branch renders `/view/splunk-dashboard-studio:/templates/dashboard.html` and returns before that loader. That template links bootstrap only. OBSERVED in the installed Splunk 10.2.6 tree on the prior inspection of this same container, and consistent with the rendered stylesheet list MEASURED here.

Supported Studio Extension Point: none for tab focus. Studio's bundle sets `stylesheet: false` while `theme: true`. Splunk's conversion table marks Custom CSS and Custom JavaScript Unsupported. Supported Studio styling is limited to built-in options such as theme, background color, and font. Those do not set a tab focus ring.

Evidence: rendered stylesheet list, computed tab style, installed view controller and Studio template, Studio bundle flag, and the Splunk 10.2 conversion document.

## CANDIDATE MECHANISMS

Mechanism: `stylesheet` on `<dashboard version="2">`
Status: UNSUPPORTED
Evidence: the attribute was present and the file was served, and the rendered Studio document still omitted it. The Studio bundle sets `stylesheet: false`.

Mechanism: `appserver/static/dashboard.css` or `application.css` auto-load
Status: UNSUPPORTED
Evidence: that loader runs only for the classic path. Studio returns first. The rendered page did not gain an app stylesheet.

Mechanism: custom JavaScript in the app
Status: UNSUPPORTED
Evidence: Splunk documents Custom JavaScript as Unsupported for Dashboard Studio. Not added.

Mechanism: Dashboard Studio theme, background, and font options
Status: SUPPORTED
Evidence: Splunk documents those as the replacement for common CSS cases. They do not style `button[role="tab"]` focus.

Mechanism: a definition field that sets native tab focus
Status: NOT PROVEN
Evidence: no such field was found, and the rendered tab still uses Splunk's own `outline-style: none`.

Mechanism: edit the Studio page template or vendor bundle
Status: not an AgentSec extension point
Evidence: those files belong to Splunk. They were not modified.

## FINAL CLASSIFICATION

AgentSec-fixable: no

Splunk-platform limitation: yes

Unresolved: no for the classification. A physical keyboard was not used.

DASHBOARD STUDIO NATIVE TAB FOCUS:
PLATFORM LIMITATION — SPLUNK 10.2

Attack Service keeps its own `:focus-visible` rule in `src/agentsec/static/agentsec.css`. A unit test asserts that rule is still present. This pass did not refocus Attack Service in the browser. That live check is NOT MEASURED.

## IMPLEMENTATION

The false `stylesheet="agentsec_studio_focus.css"` attribute was removed from the Studio views and from the builders that emit them. The unused CSS file was deleted. Native Studio tabs were left as Splunk renders them.

Files Modified: Studio view XML, dashboard builders, `scripts/agentsec_studio.py`, and `tests/unit/test_learner_console.py`. Deleted `splunk_app/agentsec/appserver/static/agentsec_studio_focus.css`.

Splunk Core Modified: NO

Vendor JavaScript Modified: NO

Unsupported DOM Injection Added: NO

## LIVE VALIDATION

Studio View: `ws_lab_a2a_auth_delegation` on `http://3.17.29.24:8000`

Focused Element: `BUTTON` `role="tab"`, text `CLAIMS`

document.activeElement: that same tab (`same: true`)

:focus-visible: `false`. The call was `focus({focusVisible: true})` in headless Chrome, not a physical key.

outline-style: `none`

outline-width: `3px`

outline-color: `rgb(0, 110, 170)`

outline-offset: `0px`

box-shadow: `none`

Visible Focus: NOT RENDERED. A click on the tab also left `outline-style: none` and `box-shadow: none`.

Physical keyboard Tab: NOT MEASURED

## ACADEMY HOME REGRESSION

1920: mark 56×56. Page `scrollWidth` equals `clientWidth`. No horizontal overflow. MEASURED.

1440: mark 55×55. No horizontal overflow. MEASURED.

1280: mark 47×47. No horizontal overflow. MEASURED.

1024: mark 36×36. No horizontal overflow. MEASURED.

Mark Size: bounded. Natural size remains 150×150. Rendered size tracks the 64×64 image visualization as the canvas scales.

Aspect Ratio: preserved. Every measured box was square.

Horizontal Overflow: none at 1920, 1440, 1280, and 1024 on Home and on the A2A workshop.

## Tests

Focused Tests: 22 passed. Session history, comparison pairing, Home branding, web UI, and remote listener.

Full Offline Tests: `1085 passed, 3 deselected` in 8.76s. Marker `not live_ollama and not live_splunk`.

Schema: `1.9.0`

ExternalEvidence: `1.0.0`

DET-MCP-001: still disabled. Not edited.

CTRL-MCP-001: unchanged. Not edited.

Secret Hygiene: `.env` was not committed. The diff has no private key, token, or certificate. No cryptographic implementation was added. Codeguard: this change does not add credentials, certificates, or crypto.

BLOCKER: 0

HIGH: 0

MEDIUM: 0 AgentSec-remediable. Native Studio tab focus remains a Splunk 10.2 platform limitation. It is not an AgentSec stylesheet defect.

LOW: 0 new. Physical keyboard and screen reader remain NOT TESTED. No WCAG claim.

Main Modified: no

v1.0.0 Modified: no

v1.1.0 Created: no

GitHub Release Created: no

FINAL VERDICT:

READY FOR FINAL INDEPENDENT PILOT WITH DOCUMENTED SPLUNK PLATFORM LIMITATION
