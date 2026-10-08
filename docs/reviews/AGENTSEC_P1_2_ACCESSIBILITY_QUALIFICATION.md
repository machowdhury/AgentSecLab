# AgentSec P1.2 — Studio 400% Accessibility Qualification

Scope: LAB-MCP-001 Golden Path, Splunk Dashboard Studio view `ws_lab_mcp_001` at true 400% browser zoom.
Evidence labels: **MEASURED**, **OBSERVED**, **DOCUMENTED**, **SIMULATED**, **UNVERIFIED**.

## 0. Scope note

The P1.2 brief did not list its work items. I read it as: take the open item from P1.1 (P-1, Studio at 400%), qualify mouse and keyboard operation using only supported Studio options, and change the accepted dashboard only if the brief's section 6 conditions are met. Those conditions were not met, so **no tracked file other than this report changed**.

## 1. Result

**Verdict: P1.2 CONDITIONAL — ACCESSIBILITY LIMITATION REQUIRES OWNER DECISION.**

- Keyboard-only use of Studio at 400% worked in the runs I did: in Fullscreen (this session) and in normal view (P1.1 session). Dropdowns open, answers register, clipped panels scroll. The Tab path is long. In the P1.2 runs, Fullscreen was entered by focusing the Display button through the script, not by Tab.
- Mouse and wheel use at 400% does not work in normal view. A supported user action (Display → Fullscreen) improves it, but the dashboard title and description still take almost the whole 248 px viewport, and only a 20 px strip of the notebook is visible.
- The best supported variant I found (hide the dashboard title/description, plus Fullscreen) gives a 119 px strip. I did not apply it: it removes the description text that holds lab boundary statements, and mouse operation of the dropdowns was not shown on it.

## 2. SHAs and state

| Item | Value |
|---|---|
| Start `develop` = `origin/develop` | `13463059957b1ad56b76614c190a7b57540f0fe0` |
| Implementation commit | none (no code or dashboard change) |
| Deployed SHA (host `git rev-parse HEAD`, checked at start and end) | `5e7ea0c323451ffcb6dd3479721a2e91a8d9bf56` |
| Report commit | recorded in the final message |
| Accepted dashboard definition sha256 (repo and host) | `bfaa1394590780af5baa28d8c1be90efe96bce83190bd2f92075e65f5350083a` (unchanged) |
| Host untracked files | `refreshAPP.sh`, `test` (pre-existing, untouched) |
| Local untracked | `.tmp-path-pre/` (pre-existing, untouched, not committed) |

No deployment was needed or performed in P1.2. Disk: 91% used, 8.8 GB free at the end (9.1 GB at the start; the cause of the 0.3 GB drop was not investigated; this work only created and deleted three small views).

## 3. Method and safety

- Real Chrome for Testing with a zoom extension (true 400%: viewport 480×248 CSS px at dpr 4, from a 1920×1080 window). Run id for the examples: ATTACK `03c5c61e-c025-4dac-8ede-f7590f98c1ed`.
- The accepted view was only read. Selecting an answer is a normal learner action.
- Disposable views were created for the `admin` user in app `agentsec` through the REST API, derived at run time from the accepted definition (copy). Recorded in a manifest with owner, creation time, purpose and hash:

| View | Change | XML sha256 |
|---|---|---|
| `zz_p12_t0` | `showTitleAndDescription: false` | `e1b3deac77cda534b8750b6b3f725d0e0a29784b778b1fc44bc7b3d3f1e1cc90` |
| `zz_p12_t1` | t0 plus every INVESTIGATE item `y` and `h` × 1.8 | `4b3ffb52d6feb89ddcc26c6e31e3983d096ee9d7546544862506a158209f9867` |
| `zz_p12_h2` | INVESTIGATE items × 1.8 only | `3b7346af82f0c5ae9d91bf616e4ecd076347cd38300856e8a1d9ca9c7903afce` |

- Each view was verified as owner `admin`, named in the manifest, then deleted; each returned 404 afterwards. The accepted `ws_lab_mcp_001` returned 200 afterwards. A leftover XML copy in the container `/tmp` and on the host `/tmp` (my own) was removed.
- No JavaScript, no custom CSS, no Splunk Core change, no restart, no data or index operation.
- Not used: an independent QA agent for browser behavior (see section 10).

## 4. Findings at 400% (OBSERVED / MEASURED)

### 4.1 Why the dashboard is not usable with a mouse

The notebook scrolls inside Studio's `LayoutContainer` (overflow auto, 6114 px of content). Its visible height is whatever is left of the 248 px viewport after Splunk's own chrome and the dashboard header:

Rows are at 400% unless a row says otherwise.

| Condition | Visible height of the scrolling notebook area | Label |
|---|---|---|
| Accepted view, normal: outer `DashboardLayoutContainer` | 12 px (overflow hidden) | MEASURED (`mouse-ws_lab_mcp_001-z4.json`) |
| Accepted view, normal: notebook `LayoutContainer` | 0 px high when probed | MEASURED (probe output recorded in this session; the saved file `scroll-z4-n.json` was later overwritten by a variant run) |
| Accepted view, Display → Fullscreen: notebook `LayoutContainer` | 20 px (rect 0,220,480,20; 6114 px of content) | MEASURED (probe output recorded in this session; the saved file `scroll-z4-fs.json` was overwritten by the `h2` run, which also gave 20 px. A re-run was blocked, see section 10.) |
| `t0` (title/description hidden), normal | 0 px | MEASURED (`geo.out`) |
| `t0`, Fullscreen | 119 px | MEASURED (`geo.out`) |
| `t1` (t0 + taller panels), Fullscreen | 119 px | MEASURED (`geo.out`) |
| `h2` (taller panels only), Fullscreen | 20 px | MEASURED (`geo.out`) |
| Accepted view at 200%, normal | 132 px (wheel scrolls it) | MEASURED (probe output recorded in this session; saved file `scroll-z2-n.json` has no view name) |
| Accepted view at 100% | 726 px | MEASURED (same note, `scroll-z1-n.json`) |

A screenshot of the accepted view in Fullscreen at 400% shows the dashboard title and the long description filling the whole viewport (OBSERVED).

Taller panels (`h2`) do not help: the limit is the height of the scrolling window, not the panel height. They do remove clipping inside panels (12 of 12 clipped before, 0 of 12 after, measured in P1.1 on a variant with the same scaling), but that is not the barrier here.

### 4.2 Mouse

| Check | Result | Label |
|---|---|---|
| Wheel over the dashboard area, normal view | Scrolls the page (scrollY 0 → 100 → 200 → 300); the notebook strip is 0 px high, so there is nothing for the wheel to scroll. In the P1.2 file the wheel points were over the header area. | OBSERVED |
| Click on an answer dropdown, normal view | Fails with a timeout. The element at the click point was a plain container `div`, not the dropdown. P1.1 identified it as `DashboardLayoutContainer` (12 px high) by `elementFromPoint` and Playwright's intercept log; the P1.2 file records only `DIV` and a truncated log. | OBSERVED (identity of the blocking element: P1.1 only) |
| Reaching the Display button | The button sits outside the 480 px width; scrolling the page horizontally and vertically brings it into reach, and a scripted click opened the menu | OBSERVED |
| Display → Fullscreen ("Hide navigation") | Present and working. Changes the layout container to 480×149 px. Not remembered: the URL does not change and a reload returns to normal view. | OBSERVED |
| Click on an answer dropdown, Fullscreen | The scripted click worked and the answer (DENY) registered. Playwright scrolls elements into view itself, so this does not prove a person can do it through a 20 px strip. | OBSERVED, with that caveat |
| Wheel over the notebook strip, Fullscreen, accepted view | In the recorded probe output the strip scrolled by 100 px per wheel step (`LayoutContainer` scrollTop 100, 100, 200). Separately, `fs2-z4.json` shows no scroll at all because that probe's wheel pointed at the header (y=100), not the strip (y=220). Reading anything through 20 px is not realistic. | OBSERVED (saved file for the first probe was overwritten; see section 10) |

### 4.3 Keyboard

| Check | Result | Label |
|---|---|---|
| Clipped markdown panels that can be focused (`focus()` makes them the active element) | INVESTIGATE 12 of 12, REFERENCE 8 of 8, REFERENCE · ANSWERS 17 of 17 | MEASURED |
| Tab stops to the first answer dropdown | 54 in Fullscreen (`kbd-layout_investigate-z4-fs.json`). 79 in normal view came from the P1.1 session; its file was lost, so it is not backed by a saved file. | MEASURED (Fullscreen); P1.1 session output (normal view) |
| Clipped panels met on that path (2 in Fullscreen) | PageDown scrolled each to its end | OBSERVED |
| Answer dropdown | Enter opens ALLOW / DENY / ERROR / UNSURE; ArrowDown + Enter chooses (ALLOW recorded in the select labels). That the CHECK table updates was seen in the P1.1 probe, not in the P1.2 scripts. | OBSERVED |
| REFERENCE tab Tab walk | In 699 Tab stops only 3 of the 8 clipped panels were reached, so Tab alone is impractical there even though each panel is focusable | OBSERVED |
| Visible focus indicator at 400% | Not assessed separately for Studio in this run | UNVERIFIED |

### 4.4 Conclusion

- Keyboard-only operation of INVESTIGATE at 400% worked in the runs listed above (Fullscreen in P1.2, normal view in P1.1) but is long. Entry into Fullscreen was scripted, not by Tab.
- Mouse operation is not usable without Fullscreen, and still impractical with it (20 px visible).
- A person using only a mouse or touch cannot read or answer the notebook at 400%. I do not label this acceptable because the platform is Splunk.

## 5. Supported alternatives evaluated

| Alternative | Result |
|---|---|
| Grid `display` option (`actual-size`, `fit-to-width`) | No change at 400% (P1.1) |
| Taller panels (×1.8) | Removes clipping inside panels; does not enlarge the scrolling window (`h2`: still 20 px) |
| Hide title and description (`showTitleAndDescription: false`) | Raises the Fullscreen strip from 20 px to 119 px. Normal view stays at 0 px. |
| Display → Fullscreen (user action) | Raises the container from 12 px to 149 px but the notebook strip is only 20 px unless the title is hidden |
| Header/navigation customization | Not available through supported options. Not attempted. |

## 6. Decision on the accepted dashboard

Not changed. Conditions in the brief (section 6) and why they were not met:

1. "Confirm supported interaction and accessibility requirements pass": no variant gave a usable mouse path. The best (`t0`/`t1` in Fullscreen) still shows 119 of 248 px, needs a manual Fullscreen step on every load, and I did not run a mouse click on its dropdowns (UNVERIFIED).
2. "Confirm no security behavior changes": hiding the title/description drops the description text, which says this dashboard does not enable the saved search `DET-MCP-001`, is not a notable-event pack, and that Splunk does not ALLOW or DENY. That text would have to move into a START panel first. That is a content change for the owner to approve, not a layout tweak.
3. The immutable copy and hash of the original are recorded above (the repo file at the deployed SHA).

## 7. Candidate change for the owner (not implemented)

1. Move the lab boundary statements from the description into the START tab markdown.
2. Set `showTitleAndDescription: false`.
3. Add a one-line learner note on the web handoff: "At 400% zoom, use Display → Fullscreen in Splunk."
4. Re-test: mouse click on the dropdowns, wheel reading through the 119 px strip, 100% and 200% regression, and the REFERENCE tabs.

Expected result is still a 119 px strip at 400% on a 1920×1080 window. That is better than 20 px but is not a clearly accessible mouse experience. The owner may prefer to document 400% as keyboard-only for Studio, with the web wizard as the primary mouse path.

## 8. Tests

| Run | Result |
|---|---|
| Full suite at HEAD (`pytest -q`) | 1505 passed, 3 skipped (summary line; the exit code was not captured in this run; the identical run at `5e7ea0c` earlier returned exit 0) |
| New tests in P1.2 | none: nothing in the product changed |
| Splunk SPL / evidence | Not changed. No new telemetry. Not re-queried in P1.2. |

## 9. Security invariants

Unchanged. No product, policy, schema, telemetry, credential, TLS or exposure change. Splunk remains evidence-only; CTRL-MCP-001 remains the decision point. The harness read `SPLUNK_PASSWORD` from `.env` at run time and never printed it.

## 10. Skipped items and limits

- **Independent QA agent for browser behavior: skipped.** Browser checks were run by the same agent that wrote the probes. I used a read-only review of this report against the saved evidence instead (below).
- **Network blocker at the end of the session.** After the main probes, my machine could no longer reach Splunk web (port 8000) or the AgentSec web app (port 5001) on the host: `curl` and the browser both timed out. At the same time, over AWS SSM the host showed all containers healthy, and local requests on the host returned 200 for both ports. My current public IP is `184.94.36.185`. The likely cause is a source-address allow rule that does not include this address; I did not confirm it and I did not change any network rule (that would change production-facing exposure). Skipped for that reason: re-running the accepted-view geometry probes with view-named output files, and a normal-view keyboard probe in this session. The values affected are labelled in section 4.
- **Independent review of this report.** A read-only subagent compared the report with the saved files. It found four mislabelled or overstated items (accepted-view Fullscreen height taken from a file overwritten by the `h2` run; the 12 px figure being the outer container; the wheel-in-Fullscreen result; the interception claim) and a keyboard overclaim. I corrected the wording and labels above. The geometry numbers themselves were reproduced by the probe output in this session.
- Persistent unattended runner: not available and not claimed. The work was done in one session.
- Mouse click on the `t0`/`t1` dropdowns: UNVERIFIED.
- Studio focus indicator visibility at 400%: UNVERIFIED.
- START and REFERENCE tabs not tested with the variants: UNVERIFIED.
- Real-person mouse/touch testing: not done; scripted pointer actions only.
- The 1920×1080 window at 400% is one geometry; a 1280×1024 window gives about 320×256 CSS px and was not run.
- During the session a probe folder from an earlier step contained files I had not created. I continued with a new folder (`/tmp/agentsec-p12`) to avoid collisions.

## 11. Evidence inventory

Local, not committed (the `artifacts/` directory is git-ignored): `artifacts/p1.2-studio-400pct-20261007/` holds the probe scripts (`p12_*.js`), result JSON (`mouse-*`, `full-*`, `fs2-*`, `scroll-*`, `kbd-*`, `audit-*`), `geo.out`, the install/cleanup scripts, `host_outputs.txt` (view hashes and delete results, transcribed from the SSM output, not machine-captured), the checkpoint, and screenshots. Two files (`scroll-z4-fs.json`, `scroll-z4-n.json`) hold the later variant runs, not the accepted view; see section 4.1. It is also the only copy of the screenshots.

## 12. Recommended owner decision

1. Decide between (a) the candidate change in section 7, or (b) documenting 400% as keyboard-only for Studio.
2. Optionally ask for real mouse/touch testing on a 1280×1024 window at 400%.

STOP. Await owner review. Phase 2, PyRIT, `main` merge, tagging and release are not started.
