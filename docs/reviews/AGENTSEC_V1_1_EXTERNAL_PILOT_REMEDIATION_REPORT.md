# AGENTSEC v1.1 EXTERNAL PILOT REMEDIATION REPORT

Evidence words below mean what they say. A served file is not a rendered Studio tab. A launcher terminal is not a Splunk search row. A control decision is not execution.

Starting Commit: `ee2b8dce817917e0152fcb7f43e7a48505b89cb0`

Ending Commit: the review commit that adds this file, on `develop` after `0eeae924c643eec9edffdc28b679a4f21073a8d6`

Branch: `develop`

Origin/Develop: `0eeae924c643eec9edffdc28b679a4f21073a8d6` at the implementation push. Updated when this report is pushed.

Main: `15f379e37773f250f70bc43270e64325590525e4`

v1.0.0 Peeled Commit: `537be71a13a5776c42a59ee9a25e2d4051d34ad0`

Schema: `1.9.0`

ExternalEvidence: `1.0.0`

DET-MCP-001: saved search `AgentSec - MCP Execution After Authorization Deny` remains `disabled = 1` and `enableSched = 0`. Not enabled.

CTRL-MCP-001: unchanged. It remains the tool PDP where the labs already define it. Splunk does not authorize.

## Scope

Two confirmed medium findings and four low findings from independent learner pilots, plus a bounded brand footprint. No schema change, no new authentication, no new control, no release tag.

Untracked and not committed: `docs/plans/` and `docs/reviews/AGENTSEC_REMOTE_DEPLOYMENT_VALIDATION.md`.

## Release Boundary Integrity

`v1.0.0` was not moved. `main` was not changed. No `v1.1.0` tag. No GitHub Release. No force push. No merge of `develop` into `main`.

## MEDIUM Findings

### MEDIUM-1 Session History

Finding: CONFIRMED in source before the change. `recordLaunch` stored the last painted client label. For a finished ATTACK whose evidence was still `WAITING_FOR_EVIDENCE`, that label is `RUN IN PROGRESS`. Reload printed only that label.

Root Cause: session history persisted `state` from `learnerRunState`. That function maps `completed_allowed` plus `WAITING_FOR_EVIDENCE` to `RUN IN PROGRESS`. Nothing refreshed the row, and the row did not keep the launcher terminal beside the client label.

Change: each stored row keeps the client label and, when the launch response has them, `terminal`, `evidence_state`, control decision, and `llm_call_count`. The visible line always says `LAST KNOWN CLIENT STATE` and `not a Splunk verdict`. On reload the page GETs the existing `/api/launches/<run.id>` record when it is still in launcher memory and updates the terminal and evidence fields. It does not replace the client label with an inferred verdict, and it does not read Splunk.

Tests: `tests/unit/test_learner_session_contract.py` executes the browser script. It requires the history line to contain `LAST KNOWN CLIENT STATE: RUN IN PROGRESS`, `launcher terminal=completed_allowed`, `evidence=WAITING_FOR_EVIDENCE`, and `not a Splunk verdict`.

Live Browser: OBSERVED on `http://3.17.29.24:5001/labs/LAB-PI-001` after commit `0eeae92` was rebuilt. Before reload and after reload the ATTACK row was `LAST KNOWN CLIENT STATE: RUN IN PROGRESS` and `launcher terminal=completed_allowed`. The run id did not change. `WAITING_FOR_EVIDENCE` stayed on the line and was not presented as the control decision.

Before: history text was `MODE · RUN IN PROGRESS · run.id · time`.

After: history text includes the client label, the launcher terminal, the evidence state, and the words `not a Splunk verdict`.

Evidence Status: VERIFIED in the browser for this lab session. The launcher GET is the runtime record, not indexed evidence.

Remaining Limitation: if the Attack Service process no longer has the record, the row stays at the last values stored in the tab. That is labeled as last known client state. Search is still required.

### MEDIUM-2 Dashboard Studio Focus

Finding: CONFIRMED by the pilots on Splunk's native tab chrome (`outline-style: none`, `box-shadow: none`). This pass did not re-open a logged-in Studio page, so that computed style was not re-measured before the change.

Root Cause: Dashboard Studio tab buttons are Splunk chrome. AgentSec had no app stylesheet aimed at `role="tab"`.

Change: `splunk_app/agentsec/appserver/static/agentsec_studio_focus.css` sets a 3px `#007F86` outline and a matching box-shadow on `[role="tab"]:focus-visible` only. Every `ws_*.xml` dashboard root now has `stylesheet="agentsec_studio_focus.css"`. The dashboard builders that emit that root tag were updated so a rebuild keeps the attribute. `open_attack.xml` stays a version 1.1 helper and does not get the Studio stylesheet.

Tests: the unit test checks the CSS contains `:focus-visible` and `role="tab"`, and that every `ws_*.xml` references the stylesheet. That proves packaging. It does not prove a rendered tab.

Live Browser: the stylesheet URL `http://3.17.29.24:8000/en-US/static/app/agentsec/agentsec_studio_focus.css` returned HTTP 200, `text/css`. OBSERVED.

Computed Style: NOT MEASURED. Academy Home redirected to Splunk login. No tab element was focused.

Keyboard Physical Tab: NOT MEASURED

Evidence Status: PARTIAL. The file is served. The Studio tab's computed style was not inspected.

Remaining Limitation: an independent reviewer with a Splunk session must focus a native Studio tab and read computed `outline` and `box-shadow`. Do not treat this finding as closed.

## LOW Findings

### LOW-1 Learning Localhost References

Classification before edit:

- Learner navigation examples: memory, RAG, and goal dashboard URLs; A2A README Attack Service URL. Kept the loopback example and added the remote-host caveat.
- Manifest scope lines for LAB-PI-001, LAB-MCP-001, LAB-MEMORY-001, LAB-AGENT-GOAL-INTEGRITY-001, LAB-AGENTSEC-CAPSTONE-001, LAB-AGENT-DELEGATION-001, and LAB-RAG-CONTEXT. Reworded so a remote learner is told to use the host in the address bar. No public IP was written.
- Garak workshop `http://127.0.0.1:11434`: internal runtime and a local health check. Left the address. Added that remote mode does not publish 11434 and that the curl is not a learner navigation URL.

CHANGE: those caveats. TEST: the memory dashboard text is asserted to mention the browser address bar, and the new docs are asserted not to contain a deployment IP. OBSERVATION: source only. The learning markdown was not rendered in a browser. NOT MEASURED: a remote learner reading those files on the EC2 host.

### LOW-2 Comparison Rehydration

CHANGE: the newest ATTACK and RETEST rows that share the current lab id are rebuilt after reload from fields already stored in the tab. A row without that lab id is ignored. Two rows with the same run id are not a pair. Missing decision or `llm_call_count` stays `NOT YET MEASURED`.

TEST: the Node contract rejects a different lab and a one-sided history.

OBSERVATION: after reload on the live page, the panel showed both new run ids, `ALLOW` and `DENY`, `llm_call_count` 4 and 0, both evidence states `WAITING_FOR_EVIDENCE`, and the sentence that this is not a Splunk verdict.

NOT MEASURED: a history that mixes two labs in one tab on the live server. That case is covered by the Node contract only.

### LOW-3 Ollama Explanation

CHANGE: README and prerequisites now say Ollama is the local LLM runtime for LIVE labs, that it is not part of Splunk, and that REPLAY workshops do not require it.

TEST: README contains that sentence.

OBSERVATION: documentation only.

### LOW-4 Accessibility Measurement Debt

Attack Service, headless Chrome, after the rebuild:

- 1920, 1440, 1280, 1024: `scrollWidth` equaled `clientWidth`. No horizontal overflow on that page. OBSERVED.
- 200%: CSS zoom 200% at a 1024 CSS-pixel width. `scrollWidth` still equaled `clientWidth`. OBSERVED. This was not a manual browser zoom menu on Academy.

Academy and other Studio pages: NOT MEASURED. Login wall.

Keyboard on Attack Service: NOT MEASURED in this pass. Visible focus on Studio tabs: NOT MEASURED.

SCREEN READER: NOT TESTED

WCAG: not claimed.

The previous debt is not closed.

## Branding Footprint

Attack Service Branding: OBSERVED. The header mark image was present. The favicon link pointed at `/static/agentsec-favicon.svg`, which returned HTTP 200.

Splunk App Icon: files `static/appIcon.png`, `appIcon_2x.png`, `appIconAlt.png`, and `appIconAlt_2x.png` are in the app package. A GET of `/static/app/agentsec/appIcon.png` returned HTTP 404 because that URL serves `appserver/static`, not the app icon directory. The icon in Splunk chrome was NOT OBSERVED.

Academy Home Branding: the Home definition contains the mark image pointing at `/en-US/static/app/agentsec/agentsec-mark.svg`. That SVG returned HTTP 200. The rendered Home page was NOT OBSERVED.

Architecture Diagram: DOCUMENTATION ONLY

Evidence Sequence Diagram: DOCUMENTATION ONLY

16x16 Favicon: OBSERVED. Headless Chrome wrote a screenshot of `agentsec-favicon.svg` at a 16px window. The image shows a navy vertical bar and a teal horizontal bar on a light background. Dashed claim strokes are omitted in this favicon variant. The primary mark SVG was not replaced.

32x32 Favicon: OBSERVED the same way. The gate remains visible. The dashed claims are still absent from this variant.

Do not read this as branding complete. Academy Home and the Splunk app icon were not seen in the product chrome.

## Remote Deployment Regression

Rebuild command, as `ubuntu`, no volume delete and no prune:

`./scripts/lab-up.sh --build --refresh-app --remote`

Exit 0. Elapsed 2m 53s. Checkout `0eeae924c643eec9edffdc28b679a4f21073a8d6`.

OBSERVED in the browser: Attack Service Search and Academy links used `http://3.17.29.24:8000`. Home and Search unauthenticated requests stayed on `3.17.29.24` and redirected to login. Before launch, the Attack page text did not contain `input_pattern_matched`.

## Answer Leakage Regression

Before launch, `leak` was false on the page text. The unit test still fails the LAB-PI-001 HTML if it contains `input_pattern_matched`. After the runs, the live comparison showed the measured reason. That is the response, not a pre-launch answer. After reload the reconstructed panel showed `DENY` and did not print `input_pattern_matched`.

## Security Semantics Regression

The fresh pair kept decision and execution apart. ATTACK `ALLOW` with `llm_call_count` 4 and terminal `completed_allowed`. RETEST `DENY` `input_pattern_matched` with `llm_call_count` 0 and terminal `completed_denied`. The pre-reload comparison, which reads the launch responses, showed operation attempted and execution evidence `true` versus `false`. Schema on both responses was `1.9.0`. CTRL-MCP-001 was not modified. This RETEST does not prove universal safety. `completed_allowed` is not a measured resource impact.

## Live ATTACK

run.id: `52d1a80e-8f29-4586-a07b-5f9604445b41`

Decision: `ALLOW`

Reason: vulnerable-profile fail-open for `ignore_previous_instructions` on CTRL-INPUT-001

Execution Evidence: `llm_call_count` 4. The launch-response comparison also showed operation attempted true and execution evidence true. Those fields are from the launcher response, not from Search.

Terminal Outcome: `completed_allowed`. Visible status `WAITING FOR SPLUNK`. Evidence state `WAITING_FOR_EVIDENCE`.

Splunk Search: NOT MEASURED

## Live RETEST

run.id: `b7d897a1-1952-47d8-91fa-9186a52d3992`

Decision: `DENY`

Reason: `input_pattern_matched`

LLM Count: 0

Terminal Outcome: `completed_denied`. Visible status `RUN DENIED`. Evidence state `WAITING_FOR_EVIDENCE`. The launch-response comparison showed operation attempted false and execution evidence false.

Splunk Search: NOT MEASURED

## Accessibility

1920: Attack Service, no horizontal overflow. OBSERVED. Academy NOT MEASURED.

1440: same.

1280: same.

1024: same.

200%: Attack Service CSS zoom, no horizontal overflow. OBSERVED. Academy NOT MEASURED.

Keyboard: NOT MEASURED this pass.

Screen Reader: NOT TESTED

WCAG Claim: none

## Tests

Focused: learner console, session contract, web UI, and Home dashboard tests passed before the full suite (the Home test was re-run after the builder rewrite and passed).

Full Offline: `1085 passed, 3 deselected` in 9.81s. Marker `not live_ollama and not live_splunk`. No failure. No skip beyond the three deselected live tests.

Repeated Reliability: 10 further consecutive runs, each `1085 passed, 3 deselected`. FAILURES=0. Durations were between 8.22s and 9.61s.

## Secret Hygiene

`.env` is not in the commit. The diff scan found no private key, AWS access key, GitHub token, live secret key, or certificate block. The only match on a public IPv4 string was a test assertion that the new docs must not contain that address. No new cryptographic implementation was added. Codeguard: this change does not add credentials, certificates, or crypto.

## Known Limitations

- Studio tab focus rendering is NOT MEASURED.
- Splunk Search rows for the fresh run ids are NOT MEASURED.
- Academy Home rendering and the Splunk app-icon chrome are NOT OBSERVED.
- Screen reader is NOT TESTED.
- Windows and Podman remain NOT VALIDATED from earlier docs. This pass did not change that.

## Remaining Findings

BLOCKER: 0

HIGH: 0

MEDIUM: the Studio focus rule is served, and the rendered tab was not measured. Treat MEDIUM-2 as not closed until that computed style is read.

LOW: Academy viewport and keyboard measurements from the earlier pilot remain open. Screen reader remains NOT TESTED. App-icon chrome was not seen.

## Final Recommendation

READY FOR INDEPENDENT v1.1 REMEDIATION RE-REVIEW

Not a release. `v1.1.0` was not created.
