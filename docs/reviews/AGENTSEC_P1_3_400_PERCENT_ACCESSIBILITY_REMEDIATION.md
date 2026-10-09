# AgentSec P1.3: 400% accessibility remediation trial (Option A)

Date: 2026-10-08. Branch: `develop`. Scope: the bounded Option A trial approved by the owner (P1.2 section 7). The accepted dashboard `ws_lab_mcp_001` was **not changed**.

Evidence labels used below: **MEASURED** (number read from the live page or host by a probe; saved in the evidence folder), **OBSERVED** (seen in a saved screenshot or probe output), **DOCUMENTED** (Splunk documentation), **INFERRED** (reasoning, not tested), **UNTESTED**.

All pointer and keyboard input in this report came from Playwright automation driving Chrome for Testing: real mouse-wheel, mouse-click and key events at screen coordinates. No `element.click()` or synthetic DOM events were used. **No person did manual testing.** Browser zoom was set with `chrome.tabs.setZoom` from a test extension, which is the same as a person choosing 400% in Chrome. Window: 1920×1080. Effective viewport at 400%: **480×248 CSS px** (MEASURED; `devicePixelRatio` 4).

## 1. Executive result

**Acceptance: CONDITIONAL. Promotion: NO. Accepted dashboard changed: NO.**

- The Option A candidate (lab-boundary statements moved onto START, dashboard title/description hidden) works as designed. All lab-boundary statements stay visible and readable on START at 100%, 200% and 400%. Saved-search SPL, tokens, inputs, drilldowns, tabs and the other three layouts are byte-identical to the accepted definition (MEASURED, structural diff).
- At 400% in Display → Fullscreen, the notebook window grows from **20 px (accepted) to 119 px (candidate)**, out of 248 px (MEASURED). In that mode, automated mouse and keyboard runs completed every required task on all four tabs: reading START, answering the three INVESTIGATE dropdowns, and reaching the end of REFERENCE and REFERENCE · ANSWERS.
- Gate 6 (mouse) fails, so the candidate was not promoted. At 400% in **normal view** the notebook is **0 px** for both the accepted dashboard and the candidate, and the **Display → Fullscreen menu item renders off-screen** (y=667 in a 248 px viewport). Wheeling the page closes the menu. A mouse-only user therefore cannot reach the one layout that works. Keyboard users can (27 Tab stops, then Enter, Enter). This is a Splunk page-layout limit that applies equally to the accepted dashboard. The gate rule requires all 14 gates to pass, and one critical gate does not. Section 22 has the gate table.
- A documented Studio option that P1.2 said did not exist, `applicationProperties.collapseNavigation`, removes the need for the Fullscreen step. It was measured as an evidence-only variant. It gives the same 119 px window on load, but in normal view the dashboard is 928 px wide in a 480 px viewport, so content overflows horizontally. It is outside the approved Option A changes and is left for the owner (section 18).

## 2. Starting HEAD

| Item | Value | Label |
|---|---|---|
| Local and `origin/develop` at start | `6229ec0be243746096c52e86349022811b72a0c5`, divergence 0/0 | MEASURED |
| Deployed SHA on the host | `5e7ea0c323451ffcb6dd3479721a2e91a8d9bf56` (start and end) | MEASURED (SSM) |
| Implementation commit (guard test) | `f2494fc292dcf8cb4cd0546af4c4b68fec74a767` | MEASURED |
| P1.2 report | `docs/reviews/AGENTSEC_P1_2_ACCESSIBILITY_QUALIFICATION.md` | DOCUMENTED |
| Working tree at start | clean except the pre-existing untracked `.tmp-path-pre/` (untouched) | MEASURED |

## 3. P1.2 findings carried forward, and corrections

Carried forward and re-measured in this session:

- Normal view at 400%: notebook 0 px for the accepted view (MEASURED again: `LayoutContainer` height 0; the outer dashboard container is 12 px).
- Fullscreen at 400%: accepted view 20 px (MEASURED again: rect 0,220,480,20; the container starts at y=99 below the title/description).
- Hiding title/description gives 119 px in Fullscreen (MEASURED again on the real candidate).

Corrections to P1.2:

1. **Screenshots at 400% in P1.2 were quarter-crops.** Under genuine browser zoom, Playwright's `page.screenshot()` returns an image of `innerWidth × innerHeight` *device* pixels (480×248), which is the top-left quarter of the 1920×993 viewport (MEASURED in `shot_test`). P1.3 uses CDP `Page.captureScreenshot`, which captures the full viewport. The P1.2 sentence "title and description filling the whole viewport" came from such a crop and overstates the problem: the title and description took the top 99 px of the Fullscreen viewport (MEASURED). The P1.2 geometry numbers are unaffected.
2. **"Header/navigation customization: not available through supported options" was wrong.** Splunk documents `applicationProperties.collapseNavigation` ("collapse the Splunk bar, app bar, and Dashboard Studio menu when the dashboard loads in View mode") plus `hideViewModeActionMenu`, `hideOpenInSearch`, `hideExport` and `hideEdit` (DOCUMENTED: help.splunk.com, Dashboard Studio, "View mode configuration options"). The definition already contains `collapseNavigation: false`.
3. P1.2 entered Fullscreen by focusing the Display button in script, not by Tab. P1.3 measured the real Tab path: 27 Tab stops to Display, Enter, and the Fullscreen item is focused first, Enter (section 15).

## 4. Network access status

- At the start of P1.3, direct requests from the operator machine to ports 8000 and 5001 failed. The host was healthy over AWS SSM. The security group `sg-0af39dc78b9126eb1` allows 8000, 5001, 5000, 22 and all traffic (`-1`) only from `99.232.130.106/32` (8888 also from `151.186.182.87/32`) (MEASURED, read-only `describe-security-groups`). The operator's public IP at the time was `184.94.36.185` (MEASURED).
- Browser work was done through AWS SSM port forwarding (`AWS-StartPortForwardingSession`: local 18000 → 8000, 15001 → 5001). This needed no security-group, allowlist, auth or TLS change. The tunnels dropped several times. A local supervisor script restarted them, and the probes wait for the tunnel before logging in.
- At the end of P1.3 the operator's public IP was `99.232.130.106` (MEASURED), and a direct request to `http://<host>:8000` returned 200 (MEASURED).
- **Diagnosis: local (client egress address).** The operator's network egress changed during the session, not the host or the rule. No firewall or exposure change was made.

## 5. Disk capacity

| Where | Start | End | Label |
|---|---|---|---|
| EC2 host `/` | 92% (88G of 96G used, 8.6G free) | 91% (8.8G free) | MEASURED (SSM `df`) |
| Operator machine `/` | 3% used | 3% used | MEASURED |

No build or deploy ran on the host. Host writes were limited to three temporary XML files, which were removed, and a three-line view manifest.

## 6. Evidence backup status

- P1.2 evidence (git-ignored) has an immutable backup: `~/Documents/AgentSecLab-evidence-archive/p1.2-studio-400pct-20261007.tar.gz` (mode 0444), sha256 `8aba15ced2a90531ee9057f10eced09f47af0bc03e562debbbe42a6c345cc581`. Re-verified at the end of P1.3 with `shasum -c`: OK (MEASURED). `artifacts/p1.2-studio-400pct-20261007/` was not modified.
- P1.3 evidence: `artifacts/p1.3-studio-400pct-20261008/` (git-ignored) and an archive in the same folder as the P1.2 backup (section 21).

## 7. Safety statements inventory

Sources: the dashboard `description` (hidden by the candidate), the XML `<description>` (kept), the README "Simulated." paragraph, and `workshop.md`. The table shows the wording placed on START, kept as close to the original as possible.

| # | Statement on START (candidate) | Source of wording |
|---|---|---|
| 1 | **Bounded lab simulation.** A fixture is not a production system, and it is not proof of a real customer incident. | README.md line 151 ("Simulated." paragraph); "Bounded lab simulation" heading added |
| 2 | Saved search **DET-MCP-001** is packaged disabled; this dashboard does not enable it. | dashboard description (verbatim) |
| 3 | Splunk is used here to observe, investigate and analyze. **Splunk does not ALLOW or DENY a tool.** | second sentence verbatim from description; first sentence is new wording for the brief's "observation, investigation and analysis" requirement |
| 4 | This workflow is **not a production security control**. CTRL-MCP-001 is a lab allow-list, not production IAM. | first sentence is new wording for the brief's requirement; second from workshop.md / builder |
| 5 | Controlled lab authorization failure; not a production exploit. Not a notable-event pack. | workshop.md line 61; description (verbatim) |
| 6 | WS-MCP-001 Dashboard Studio workshop. Reuses validated Q-MCP investigation SPL. | description (verbatim) |

The existing START line `REQUEST != GRANT · ALLOW != EXECUTION · SPLUNK != ENFORCEMENT` was kept. The XML `<label>` and `<description>` ("DET-MCP-001 packaged disabled. Not a notable-event pack. ... Splunk does not ALLOW or DENY a tool.") were left unchanged. The packaged saved search for DET-MCP-001 remains `disabled = 1` (asserted by the new test). Two sentences (3a and 4a) are new wording that the owner should check before any future promotion.

## 8. Candidate implementation

The candidate was built in a scratch copy of the repo, not in the working tree.

- **Pipeline determinism:** `build_lab_mcp_001_dashboard.py` → `apply_workshop_flows.py` → `apply_guided_learning.py` reproduces the accepted JSON (`bfaa1394…083a`) and XML (`154783d5…a91c`) byte for byte (MEASURED).
- **Builder change** (patch preserved as `candidate/candidate-builder.patch`, sha256 `4c2c937b…2e7b`; not committed):
  - added `SAFETY_BOUNDARY_STATEMENTS` and `BOUNDARIES_H = 330`;
  - added a `viz_start_boundaries` markdown panel titled LAB BOUNDARIES, placed under the START journey bar and above the mission panel;
  - set `showTitleAndDescription: False`;
  - grew the START layout height from 876 to 1214.
- **Structural diff, candidate vs accepted (MEASURED):** six differences, all intended:
  - `showTitleAndDescription`;
  - START layout height;
  - START structure length and item order (two entries);
  - the moved mission panel position;
  - one new visualization.

  These were equal (MEASURED): `dataSources` (all SPL / saved-search references), `inputs` (tokens `run_id`, `live_run_id`, `nb_a1..3`), `globalInputs`, `tabs`, every other visualization (so drilldowns), and the `layout_investigate`, `layout_evidence` and `layout_path_b` definitions. No panel was enlarged.
- **Candidate ID and hash:** disposable view `zz_p13_cand` (owner admin, app agentsec, sharing user). XML sha256 `736c894b1de773b27b1634ab2ee60d04ed49d590cd72f3d69fb52f5fda6bd6ef`; definition JSON sha256 `4d7b2091460672ebd6685deff44b34f84111b3d93f34e0f50b57af1cc3c44076`. The hash read back from Splunk REST before deletion matched (MEASURED).
- **Evidence-only variants (never promotion candidates):**
  - `zz_p13_c2` = candidate + `collapseNavigation: true` (sha256 `a04fb1d0…b294`);
  - `zz_p13_c3` = C2 + `hideViewModeActionMenu: true` (sha256 `6dd6c2ae…a994`).
- **Cleanup:** all three views were deleted at the end, after each name/owner was checked against the run manifest. Each returned DELETE 200, then GET 404 (MEASURED). Temporary XML files on the host and in the container were removed.
- **Repo state:** the builder was restored to `HEAD` after the trial, so the repo still builds the accepted dashboard. The only tracked changes are the guard test and this report.

## 9. 400% measurements

Notebook = `[data-test="LayoutContainer"]`, Studio's scrolling tab panel. All rows are MEASURED.

| View / mode | Viewport (CSS px) | Notebook height | Notebook width | Content height (START / INV / REF / ANS) |
|---|---|---|---|---|
| Accepted, 400% normal | 480×248 | **0** | 928 | 876 / 6114 / 7806 / 24180 |
| Accepted, 400% Fullscreen | 480×248 | **20** | 480 | same |
| Candidate, 400% normal | 480×248 | **0** (outer container 81) | 928 | 1214 / 6114 / 7806 / 24180 |
| Candidate, 400% Fullscreen | 480×248 | **119** | 480 | same |
| C2 (collapseNavigation), 400% normal, no user action | 480×248 | **119** | **928** (horizontal overflow) | same |
| C3 (C2 + hideViewModeActionMenu), 400% normal | 480×248 | 119 | 928 | same |

In candidate Fullscreen, the top 121 px of the 248 px viewport are the global inputs (REPLAY example selector and LIVE run.id box, 90 px) and the tab bar (31 px). The tab bar is 523 px wide in a 480 px viewport, so the "REFERENCE · ANSWERS" label is clipped by 43 px. Its click target centre is still on screen (MEASURED).

Clipped panels (text overflowing inside a fixed-height panel, which gives the panel its own scroll) in candidate 400% Fullscreen: INVESTIGATE 11, REFERENCE 8, REFERENCE · ANSWERS 17, START 0 (MEASURED). These come from panel heights sized for 1024 px / 200% layouts. Fixing them was out of Option A scope ("avoid unnecessary panel enlargement").

## 10. START validation

| Check | Result | Label |
|---|---|---|
| All 10 key phrases of the 6 statements readable inside the visible notebook window (400% Fullscreen, mouse wheel) | 10/10, 48 wheel stops of 95 px, end reached, no clipped panel | MEASURED |
| Same with keyboard only (400% Fullscreen) | 14 Tab stops to the LAB BOUNDARIES panel; Arrow keys scroll the notebook 10 px per press; 10/10 readable | MEASURED |
| 200% normal (mouse) | 10/10, 14 wheel stops | MEASURED |
| 100% normal (mouse) | 10/10, 2 wheel stops; whole boundaries panel visible on load | MEASURED |
| Accepted view START at 200% (for comparison) | 0/10 on START (they are in the description header instead) | MEASURED |
| Screenshot | `results/mouse-zz_p13_cand-z4-fs/start-*.png` | OBSERVED |

## 11. INVESTIGATE validation (candidate, 400% Fullscreen)

- Reached by mouse click on the tab, and by keyboard (ArrowRight + Enter), MEASURED.
- Wheel sweep reached the end (199 stops; 83 distinct text blocks were fully readable at some stop), MEASURED.
- Each of the three answer dropdowns was brought into view with the wheel (104, 90 and 78 steps of 47 px) and opened with a real click on a 454×32 px target. `elementFromPoint` at the click point was the dropdown, every option was on screen and hit-testable, and the chosen answer registered: DENY, "Handler did not start", "Scopes differ" (MEASURED). Screenshots are in `results/answer-zz_p13_cand-z4-fs/`.
- Keyboard: first answer dropdown at Tab stop 53, second at 80. Enter opened the five options; ArrowDown ×3 then Enter selected ERROR. PageDown scrolled a clipped notebook panel from 0 to its maximum (165 px) with focus kept (MEASURED).

## 12. REFERENCE validation (candidate, 400% Fullscreen)

Reached by mouse click and by keyboard. The wheel sweep reached the end (95 stops). 8 clipped panels. The first keyboard stop in the content is the REFERENCE header panel, with focus-visible (MEASURED).

## 13. REFERENCE · ANSWERS validation (candidate, 400% Fullscreen)

Reached by mouse click and by keyboard. The first content stop is the "Stop — this tab contains the answers" gate, with focus-visible (MEASURED). A dedicated wheel sweep reached the end of the 24,180 px tab only after **1,002 wheel stops** (about 190 s of automated scrolling). Along the way there were 83 scroll-latch events, 69 of which needed the pointer moved to the 1 px gutter (MEASURED). The tab is reachable, but it is not a practical mouse experience at 400%.

## 14. Mouse

| Test (automation pointer events) | 400% Fullscreen | 400% normal | 200% | 100% |
|---|---|---|---|---|
| Open START, read boundaries | PASS | FAIL (0 px window) | PASS | PASS |
| Switch tabs by click (all four) and return to INVESTIGATE | PASS | not reachable | PASS | PASS |
| Wheel-scroll notebook | PASS, with scroll latching (below) | FAIL | PASS (16 latch events) | PASS (4) |
| Open and choose all three answers | PASS | not reachable | PASS | PASS |
| Reach Display → Fullscreen by mouse | n/a | **FAIL**: Display button only partly on screen (click on its visible part worked), the Fullscreen item is drawn at y=667 of 248, and wheeling closes the menu | n/a | n/a |

**Scroll latching (OBSERVED in automation; effect on people INFERRED):** when the pointer is over a clipped panel, the wheel scrolls that panel. When the panel reaches its end, more wheel events in quick succession did not move the notebook. Both elements have `overscroll-behavior: auto` (MEASURED), so this is Chrome's per-gesture scroll latching, not a CSS block. In the 400% Fullscreen run there were 97 latch events: 33 cleared by repeating the wheel, 64 only by moving the pointer, none stuck. The accepted dashboard shows the same behaviour (22 events at 200%). A person who pauses between scroll gestures may chain normally; that was not tested.

Real manual mouse or touch testing: **not done**.

## 15. Keyboard

| Test (automation key events) | Result | Label |
|---|---|---|
| Enter Fullscreen from normal view at 400% | 27 Tab stops to Display (all on screen), Enter, the Fullscreen item is focused first, Enter → 119 px notebook | MEASURED |
| Tab stops to the first meaningful control (Fullscreen, INVESTIGATE) | tab bar at stop 9; first in-canvas stop 10 (CURRENT EVIDENCE panel) | MEASURED |
| Tab stops to the first answer dropdown | 53 (400% FS); 75 (100% normal); P1.2 accepted FS: 54 | MEASURED |
| Between answer dropdowns 1 and 2 | 27 stops (FS); 25 (100%) | MEASURED |
| Enter/Space activate tabs; arrows move between tabs | ArrowRight + Enter activated REFERENCE; Home + Enter → START; ArrowRight + Space → INVESTIGATE; separately all four sections were activated in turn | MEASURED |
| Dropdown selection by keyboard | Enter, ArrowDown, Enter: PASS | MEASURED |
| Keyboard scroll of a clipped panel | PageDown 0 → 165 (end), focus retained | MEASURED |
| Return to earlier sections | Shift+Tab back to the tab bar: 34 stops from the first answer dropdown (after answering it); 40–65 from deep REFERENCE content. After a tab is activated with Enter, focus drops to `body` | MEASURED |
| Every required panel reachable | START boundaries, the three answers, the first content of REFERENCE and REFERENCE · ANSWERS: yes. Each REFERENCE panel was not individually focused | MEASURED / UNTESTED (per panel) |

Why so many Tab stops: each table panel adds a sort button and a resize handle per column, plus five panel action buttons (open search, inspect, fullscreen, refresh, export) (OBSERVED in the stop list). Supported ways to cut this exist but are outside Option A: `hideViewModeActionMenu` (DOCUMENTED) would remove the five action buttons per panel. Its Tab-count effect was **not measured** (C3 geometry only). Studio has no supported skip link into the canvas; the "Skip Navigation" link in the Splunk bar skips only the app menu (OBSERVED in the Tab path). No DOM workaround was used.

## 16. Focus visibility

- `:focus-visible` matched on 80 of 80 stops in the 400% Fullscreen INVESTIGATE run (MEASURED).
- A visible ring was computed on the element itself for 62 stops. For the other 18 stops: the LIVE run.id text box draws a 3 px `rgb(0,110,170)` ring on its wrapper (MEASURED), and a column resize handle shows a blue bar (OBSERVED, `focusdetail-…-resize-focus.png`). One "clickable" stop inside the CHECK panel was not inspected (UNTESTED).
- **Focus not visible: in Fullscreen, Tab stops 1–5 land on the hidden dashboard header controls** (Add favorite, Download, Display, Actions, Edit), which are off screen (MEASURED). In an earlier 260-stop run, stops 158–167 landed on Splunk bar items hidden by Fullscreen (probe output in this session; its JSON file was overwritten by the later 80-stop run, so this item is not backed by a saved file). This is Splunk Fullscreen behaviour. It is the same for the accepted dashboard and the candidate.
- No focused stop inside the notebook was obscured by another element (`elementFromPoint` check, MEASURED).
- The first answer dropdown with focus at 400% is shown in `results/kbd-zz_p13_cand-z4-fs/focus-select1.png` (OBSERVED).

## 17. Normal-zoom regression

| Check | 100% | 200% | Label |
|---|---|---|---|
| Notebook height, candidate vs accepted | 785 vs 726 | 201 vs 132 | MEASURED |
| START statements readable | 10/10 | 10/10 | MEASURED |
| All tabs by mouse, ends reached | yes | yes | MEASURED |
| Three answers by mouse | PASS | PASS | MEASURED |
| Clipped panels, candidate vs accepted (INV/REF/ANS) | 0/0/7 (accepted at 100% not run) | 0/0/8 vs 0/0/8 | MEASURED |
| Keyboard (Tab path, answer, sections) | PASS | **UNTESTED** (the run happened after cleanup, got a 404, and was discarded) | MEASURED / UNTESTED |
| Fullscreen at 100% / 200% | UNTESTED | UNTESTED | — |

The candidate gains notebook height at every zoom, because the title and description no longer take space.

## 18. Fullscreen persistence

- **Not fixed, and not claimed.** Display → Fullscreen is not remembered: after a reload the page returns to normal view (notebook 0 px), and the URL has no Fullscreen parameter (MEASURED).
- A documented persistent alternative exists: `applicationProperties.collapseNavigation: true` (DOCUMENTED). Measured as evidence-only C2: on load at 400% the notebook is 119 px with no user action (MEASURED). But in normal view the Splunk page keeps a 928 px wide dashboard in a 480 px viewport (MEASURED). The flow diagram and the right half of every panel are off-screen; the C2 screenshot shows this (OBSERVED). A click at the centre of an answer dropdown fell outside the viewport and did not open it (MEASURED). Clicking the visible part was not tested. C2 also hides the Splunk bar for everyone at 100% and 200% (reachable from Display → Show navigation, DOCUMENTED). That is a product decision, outside Option A.
- **Web-wizard instruction: not added.** It would help only with the candidate layout. With the accepted layout, Fullscreen gives a 20 px window, so telling learners to use it would mislead mouse users. The line from P1.2 ("At 400% zoom, use Display → Fullscreen in Splunk") is ready if the owner promotes a candidate.

## 19. WCAG 2.2 AA criteria assessed (no certification claim)

| Criterion | Candidate result | Basis |
|---|---|---|
| 1.4.10 Reflow | 400% Fullscreen: content reflows to 480 px (tab bar overflows by 43 px). 400% normal: **fails**: 928 px page, 0 px notebook (accepted the same) | MEASURED |
| 2.1.1 Keyboard | Pass for the tasks tested, including entering Fullscreen | MEASURED |
| 2.4.3 Focus Order | Not formally assessed. Order follows the layout; focus drops to `body` after tab activation | OBSERVED |
| 2.4.7 Focus Visible | Pass inside the dashboard. **Fails** for stops on hidden header and Splunk-bar controls in Fullscreen | MEASURED |
| 2.4.11 Focus Not Obscured (Minimum) | Same hidden-control stops fail; no in-canvas stop obscured | MEASURED |
| 2.5.7 Dragging / single-pointer operation | Tasks need only clicks and wheel; no dragging needed | OBSERVED |
| 2.5.8 Target Size (Minimum) | Dropdowns 454×32, tabs ≥82×30: pass. Column resize handle 9×32 is under 24 px wide; the spacing exception was not evaluated | MEASURED |
| 3.3.2 Labels or Instructions | Answer dropdowns have visible labels ("Q1 · What did it decide?") | OBSERVED |
| Mouse operation at 400% (brief requirement) | Fullscreen: tasks complete. Normal view: cannot reach Fullscreen by mouse | MEASURED |
| 1.4.3/1.4.11 contrast, 1.3.x, 4.1.2 name/role, 1.4.13, 320 px (1280×1024 window) geometry, screen readers, touch | **UNTESTED** in P1.3 | — |

## 20. Test results and exit codes

| Run | Result | Exit code |
|---|---|---|
| New guard `tests/splunk/test_p1_3_safety_statement_guard.py` (normal, bypass attempt, malformed option, boundary, saved search disabled) | 8 passed | 0 |
| Focused dashboard and workshop tests **on the candidate build** (scratch copy: `test_lab_mcp_001_dashboard`, `test_investigation_notebook`, `test_p0_1_learner_evidence`, `test_learner_ux_p0`, `test_lab_mcp_001_workshop`, guard) | 215 passed | 0 |
| Full suite on the repo (`pytest -q`) | **1513 passed, 3 skipped** | 0 |
| Skips | `test_ollama_live` (local Ollama not reachable); `test_external_evidence_live` and `test_live_transport` (live Splunk ingest is opt-in, `AGENTSEC_LIVE_SPLUNK=1`) | — |
| Browser probes | JSON and screenshots in `results/`. Process exit codes were not recorded per run; results were read from the saved JSON. One post-cleanup run (200% keyboard) hit a 404 and was discarded | — |

No SPL was run against Splunk indexes and no telemetry was generated in P1.3. Saved-search and token correctness rests on the structural diff and the existing contract tests.

## 21. Accepted dashboard integrity

| Check | Value | Label |
|---|---|---|
| Repo definition JSON | `bfaa1394590780af5baa28d8c1be90efe96bce83190bd2f92075e65f5350083a` (unchanged) | MEASURED |
| Repo view XML | `154783d5520473391b36266c86dee3883616605026c1b30c7c7e571976aba91c` (unchanged) | MEASURED |
| Installed app file in Splunk container `default/…/ws_lab_mcp_001.xml` | `154783d5…a91c` (equals repo) | MEASURED |
| `local/` override for `ws_lab_mcp_001` | none | MEASURED |
| REST view | `ws_lab_mcp_001`, owner nobody, sharing global, still served | MEASURED |
| Host repo files | same two hashes at deployed SHA `5e7ea0c…` | MEASURED |
| Containers | attack_service, acmebank and splunk healthy; otel_collector up; ollama healthy | MEASURED |
| Restorable | nothing to restore; the accepted view was never modified | — |
| Host untracked files `refreshAPP.sh`, `test` | present on the host; not created by P1.3; not touched | OBSERVED |

P1.3 evidence: `artifacts/p1.3-studio-400pct-20261008/` (308 files: probe scripts, zoom extensions, results JSON, full-viewport screenshots, host install/cleanup scripts, candidate patch/JSON/XML, C2/C3 XML, a pre-commit snapshot of this report, and `SHA256SUMS` over the other 307). A secret scan of the folder for the Splunk password value was clean. Read-only archive: `~/Documents/AgentSecLab-evidence-archive/p1.3-studio-400pct-20261008.tar.gz` (mode 0444), sha256 `afe51c2c4daedc420fd2b7f6fc4e2ed3760dc1cb04cc5b7ff737fa3c19ab9e34`.

## 22. Promotion decision

**NO.** Gate results for the candidate:

| # | Gate | Result |
|---|---|---|
| 1 | Safety statements preserved | PASS |
| 2 | START usable | PASS (400% Fullscreen, 200%, 100%); 400% normal view unusable |
| 3 | INVESTIGATE usable | PASS with limitation (119 px window, scroll latching) |
| 4 | REFERENCE usable | PASS with limitation |
| 5 | REFERENCE · ANSWERS usable | PASS with heavy limitation (1,002 wheel stops) |
| 6 | Mouse passes the supported validation method | **FAIL**: mouse cannot reach Fullscreen at 400%, and normal view has a 0 px notebook |
| 7 | Keyboard passes | PASS |
| 8 | Focus visible | **FAIL (partial)**: focus lands on hidden header and Splunk-bar controls in Fullscreen |
| 9 | Scrolling works | PASS with limitation |
| 10 | Normal-zoom regression passes | PASS for mouse at 100%/200% and keyboard at 100%; keyboard at 200% UNTESTED |
| 11 | Saved searches and tokens correct | PASS (identical `dataSources` and `inputs`; contract tests) |
| 12 | No security or operational boundary change | PASS |
| 13 | Screenshot and test evidence preserved | PASS |
| 14 | Accepted dashboard restorable | PASS (unchanged) |

Gates 6 and 8 fail for reasons that also apply to the accepted dashboard and come from the Splunk page and Fullscreen implementation, not from the candidate. The rule requires all 14, so the accepted dashboard stays as it is. The candidate is a measured improvement and is ready if the owner accepts the residual limits.

## 23. Known limitations

- Automation only; no person tested with a mouse, touch screen or screen reader.
- One window geometry (1920×1080). The WCAG reference case of 320 px (1280×1024 at 400%) was not run.
- The effect of scroll latching on people is inferred, not tested.
- Keyboard at 200% and Fullscreen at 100%/200% were not tested on the candidate.
- Tab-count effect of `hideViewModeActionMenu` not measured.
- Two START sentences are new wording (section 7).
- Host access depended on SSM tunnels, which dropped several times. Every run used in this report completed after its tunnel check.

## 24. Remaining blockers

1. A mouse-only user cannot use the Studio notebook at 400% in this Splunk layout, accepted or candidate. Fixing that needs either a product option outside Option A (`collapseNavigation`, which brings horizontal overflow) or a decision to document 400% Studio use as keyboard plus Fullscreen, with the web wizard as the mouse path.
2. In Fullscreen, focus visits hidden Splunk controls (Splunk behaviour; no supported setting found).
3. Clipped panels at 480 px width on INVESTIGATE, REFERENCE and ANSWERS (needs taller panels; outside Option A).

Owner decision options:

- (a) Promote the Option A candidate as a partial improvement and accept gates 6 and 8 as known limits.
- (b) Approve testing `collapseNavigation` and/or `hideViewModeActionMenu` as a follow-up.
- (c) Keep the accepted dashboard and document 400% as keyboard-only for Studio.

## 25. Phase 2 readiness

**NOT READY**, pending the owner decision in section 24. The P1.3 acceptance outcome is CONDITIONAL. No Phase 2, PyRIT, `main` merge, tag or release work was started.

Credentials: no secret was written to code, logs, evidence or this report. The browser harness reads `SPLUNK_PASSWORD` from `.env` at run time, types it into the login form, and never prints it. Host REST calls use the password from the Splunk container's environment.
