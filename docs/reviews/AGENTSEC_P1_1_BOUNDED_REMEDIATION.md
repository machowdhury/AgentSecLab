# AgentSec P1.1 — Bounded Learner Experience Remediation

Scope: LAB-MCP-001 Golden Path only. Branch `develop`.
Evidence labels: **MEASURED** (instrumented number from a run), **OBSERVED** (seen in a real browser/Splunk), **DOCUMENTED** (from docs/code), **SIMULATED** (local run, not the deployed runtime), **UNVERIFIED** (not shown).

---

## 1. Executive summary

| Item | Result |
|---|---|
| D-1 START CTA below the fold at 1024×768 | **Fixed.** CTA now 592–652 px in a 768 px viewport (was 984–1044). MEASURED on the deployed app. |
| D-2 PREDICT CTA below the fold at 1920×1080 | **Fixed.** CTA now 979–1043 px (empty) / 979–1039 px (answered), viewport 1080 (was 1111–1175 / 1146–1206). MEASURED on the deployed app. |
| P-1 Studio at true 400% | **Not fully resolved.** Clipped panels are reachable by keyboard and the dropdowns work by keyboard. Mouse wheel and mouse selection of the answer dropdowns do not work. A supported change (taller panels) removes the clipping in a disposable test. Not implemented; it needs owner approval (section 6, 7). |
| D1 RETEST deep link | Verified from the real RETEST completion screen, then confirmed in Splunk. |
| D2 DENY contrast | 6.03:1 (requirement 4.5:1). MEASURED. |
| D3 Evidence-source clarity | Mostly verified. One gap: there is no per-run LIVE chip on the web ATTACK / RETEST / COMPARE steps. |
| Security and telemetry | Unchanged (section 13). |
| Tests | Full suite 1505 passed, 3 skipped, exit 0 (section 10). |

Verdict: **P1.1 CONDITIONAL — ACCESSIBILITY DECISION REQUIRED.**

## 2. Starting and ending SHAs

| | SHA |
|---|---|
| Start `develop` = `origin/develop` | `8c42ed10a1ed1d343f95f278368e48ce6d185314` |
| Deployed before P1.1 | `49de0f82785707625a1db5c3f336dc21c2568c48` |
| Implementation commit (pushed, deployed) | `5e7ea0c323451ffcb6dd3479721a2e91a8d9bf56` |
| Deployed after P1.1 (host `git rev-parse HEAD`, re-checked at report time) | `5e7ea0c323451ffcb6dd3479721a2e91a8d9bf56` |
| This report | docs-only commit after `5e7ea0c`; no redeploy needed (no runtime change) |

Pre-existing untracked files were left alone: local `.tmp-path-pre/`; host `refreshAPP.sh` and `test`.

## 3. Changed files and rationale

| File | Change | Why |
|---|---|---|
| `src/agentsec/templates/attack_mcp.html` | START: the primary CTA row and its note now sit directly after the flow diagram and before the three explanation panels. The panels are unchanged. PREDICT: form top margin 28 px → 16 px. | D-1, D-2. Same content, same reading order. |
| `src/agentsec/static/agentsec-academy.css` | Appended a P1.1 block, scoped to `body.academy` and `#step-predict`: tighter predict spacing; the "Selected" label no longer forces a new line; smaller rail/main spacing. | D-2: the selected-state label had wrapped onto its own line and pushed the CTA down by 18 px. |
| `tests/unit/test_p1_1_learner_layout.py` (new) | 3 offline structure tests and 3 real-browser layout tests. | Regression coverage (section 10). |
| `docs/reviews/AGENTSEC_P1_1_BOUNDED_REMEDIATION.md` (new) | This report. | Deliverable. |

Not changed: Studio dashboard definition (`learning/level_1/LAB-MCP-001/dashboard.definition.json`, sha256 `bfaa1394…083a`, identical on the host), prediction logic, session keys, runtime code, policy, telemetry.

## 4. D-1 START CTA before/after (MEASURED, deployed app)

The "before" numbers were measured on the deployed `49de0f8`. An earlier local number came from a stale server process and was discarded.

| Viewport | CTA before (top–bottom px) | CTA after | Visible without scrolling? |
|---|---|---|---|
| 1024×768 | 984–1044 | 592–652 | before: no (276 px below the fold). After: yes. |
| 1920×1080 | 863–923 | 583–643 | before: yes. After: yes. |
| 200% (960×496 CSS px) and 400% (480×248 CSS px), local zoom check | normal scrolling | normal scrolling | In order, readable, no horizontal overflow measured. SIMULATED (local server). |

Preserved: title, objective, context, the three explanation panels, safety boundaries, font sizes (unchanged), reading order. No absolute positioning. One primary CTA only.

## 5. D-2 PREDICT CTA before/after (MEASURED, deployed app)

| Viewport 1920×1080 | CTA before | CTA after |
|---|---|---|
| Empty (both questions open) | 1111–1175 | 979–1043 |
| Answered (both questions answered) | 1146–1206 | 979–1039 |

Behavior verified (real browser, test + deployed walk):

- The disabled CTA is visibly different (dashed border, slate fill) and `aria-disabled="true"`. Pressing Enter on it does nothing.
- Both questions are kept: ALLOW / DENY / ERROR / UNSURE, and YES / NO / UNSURE. UNSURE is kept (not renamed).
- The CTA position does not shift when an option is selected.
- The keyboard-only path works: Tab, arrow keys, then Enter on the enabled CTA moves to ATTACK.
- No outcome words (`ALLOW`/`DENY` result, "executed") are shown as an outcome before the attack.
- Prediction semantics, session handling and progression rules are untouched.

## 6. Studio 400% investigation (P-1)

### C1. Reproduction on the real deployed Studio (read-only; true 400% via browser zoom: viewport 480×248 CSS px, dpr 4)

| Check | Result | Label |
|---|---|---|
| INVESTIGATE markdown panels clipped | 12 of 12 | MEASURED |
| REFERENCE markdown panels clipped | 8 of 9 scrollable (`overflow:auto`); none hidden-without-scroll | MEASURED |
| Same dashboard at 100% and 200% | 0 of 12 clipped, no horizontal overflow | MEASURED |
| Clipped panels have a scroll container | yes, `markdown-container` with `overflow:auto` | MEASURED |
| Keyboard scroll of a clipped panel | The container is a Tab stop. Arrow keys / PageDown moved `scrollTop` 0 → 57.75 (maximum 58). Tested on one panel ("1 of 5 — What did the control decide?"). | OBSERVED (one panel) |
| Mouse wheel over a clipped panel | `scrollTop` did not change | OBSERVED |
| Answer dropdown by keyboard | Enter opened the list (ALLOW / DENY / ERROR / UNSURE). ArrowDown + Enter selected ALLOW and the CHECK table updated. | OBSERVED |
| Answer dropdown by mouse | The click lands on `DashboardLayoutContainer` (about 12 px high) instead of the control | OBSERVED (`elementFromPoint` and Playwright's intercept log) |
| Top REPLAY selector by keyboard | works | OBSERVED |
| Page-level horizontal overflow | Splunk's own header is 960 px wide in a 480 px viewport. This is also true for every variant. | MEASURED |
| Splunk header height | The first 248 px viewport is filled by Splunk chrome; the dashboard is reached after about 60–78 Tab stops. | OBSERVED |
| Focus visibility after opening the dropdown | The screenshot after opening showed only the Splunk header; the focused filter input is reported at y=23 in the viewport. I could not show a visible popup. | UNVERIFIED |

A correction: an earlier probe run suggested the answer dropdown did not open at 400%. That was a bug in my probe (a stray extra Tab moved focus to the next element). With the bug removed, Enter works at 400% as it does at 100% and 200%.

Essential instructional content: reachable at 400% by keyboard scrolling (one panel confirmed; not every panel was exercised, and wheel and mouse do not work). REFERENCE keyboard scrolling was not exercised: **UNVERIFIED**.

### C2. Supported alternatives (disposable views only)

Method: four private views (`zz_p11_c2_v0..v3`) were created for the `admin` user in the `agentsec` app through the Splunk REST API. They were derived at run time from the accepted definition (copy; accepted file untouched). No JavaScript, no custom CSS, no Splunk Core change. The views were deleted afterwards (all four returned 404 after DELETE). The accepted `ws_lab_mcp_001` returned 200 and its definition hash is unchanged.

| Variant | Change (supported Studio option) | 400% clipped | 200% clipped | 100% clipped | Page height at 100% |
|---|---|---|---|---|---|
| v0 control | accepted definition copy | 12/12 | 0 | 0 | normal |
| v1 | `layout_investigate` `display: actual-size` | 12/12 | 0 | 0 | same as control |
| v2 | `display: fit-to-width` | 12/12 | 0 | 0 | same as control |
| v3 | all item `y` and `h` × 1.8 and canvas height × 1.8 | **0/12** | 0 | 0 | about 1.8× longer, large empty gaps (screenshot reviewed) |

Findings (MEASURED unless stated):

- Changing the `display` option makes no difference at 400% in this Splunk build.
- Taller panels (v3) remove the clipping at 400%. Font size stays 16 px, and there is no new horizontal overflow from the dashboard.
- The dashboard container is still 12 px high at 400% in every variant. So mouse interception of the dropdowns probably remains; I did **not** test mouse clicks on v3: **UNVERIFIED**.
- Factor 1.8 was not minimized (**UNVERIFIED** that a smaller factor works). Tables did not need scaling; I scaled everything for simplicity.
- Only INVESTIGATE was tested. REFERENCE and START were not tested with variants: **UNVERIFIED**.
- The Splunk header and navigation cannot be changed with supported Studio options. DOCUMENTED / not attempted.

### C3. Decision

- No Studio change was implemented.
- Candidate (for owner approval only): scale item heights in `layout_investigate` (and probably `layout_evidence`) by about 1.8 using the supported layout definition. Risks: 100% view becomes much longer with empty space; every `y` position changes; the web handoff link does not depend on positions, but the notebook walk-through and any screenshots would need re-checking; unproven for mouse operation.
- Classification: **unresolved accessibility concern, not an acceptable limitation merely because Splunk is the platform.** Keyboard users can read and operate the INVESTIGATE tab at 400%, with a long Tab path. Mouse and touch users cannot reliably operate the answer dropdowns, and wheel scrolling of clipped panels does not work.

## 7. Supported layout alternatives evaluated

See the table in C2. Summary: panel heights (works for clipping, with cost); `display` modes (no effect); internal scrolling (already present, keyboard works, wheel does not); header and navigation mitigation (not available as a supported option).

## 8. RETEST deep-link validation (D1) (OBSERVED + MEASURED)

On the real RETEST completion screen I clicked "Investigate the RETEST evidence in Splunk".

- ATTACK run: `03c5c61e-c025-4dac-8ede-f7590f98c1ed`
- RETEST run: `098e2277-246e-4e7d-8baa-ea2b836c50d3`
- The opened Studio view carried the RETEST id (not the ATTACK id), and the Studio state tables showed the RETEST run.
- Confirmed in Splunk by query on `index=agentsec_telemetry` for that run id (not only by the URL). RETEST: `DENY` / `tool_not_granted`, no `mcp.started` or `mcp.completed`, `pipeline.stopped` present.
- The fresh pair was reconciled in Splunk. The SPL verifier showed 8 of 8 displayed/executed SPL pairs identical.

## 9. DENY contrast (D2) (MEASURED)

Rendered DENY text and background in Dashboard Studio gave **6.03:1** (WCAG formula). Requirement for normal text: 4.5:1. Pass.

## 10. Focused and full test results

| Run | Result |
|---|---|
| New file `tests/unit/test_p1_1_learner_layout.py` | 6 passed (re-run just before this report) |
| The two layout regression tests against the old code | Fail on the old layout, pass on the new (checked before the commit) |
| Focused P1 web/navigation/learner-flow set | 149 passed (before the commit) |
| Full suite at the implementation commit | **1505 passed, 3 skipped, exit 0** (baseline 1499 + 6 new tests). The 3 skips are Ollama and two opt-in live-Splunk tests. |
| Full suite re-run at report time (`pytest -q`, HEAD `5e7ea0c`) | **1505 passed, 3 skipped, exit 0** |

No unrelated test expectation was changed.

## 11. Browser accessibility results (web app)

| Check | Result |
|---|---|
| CTA visibility at 1920×1080 and 1024×768 (START) | pass |
| PREDICT CTA at 1920×1080 | pass |
| PREDICT CTA at 1024×768 | **still below the fold** (1039–1103). Not required by this brief; see section 14. |
| Keyboard-only START → PREDICT → ATTACK | pass |
| Visible focus (`:focus-visible`, 3 px navy outline) | present |
| Horizontal overflow at 1920 / 1024 / 200% / 400% (local) | none measured |
| Studio | see section 6. Reported separately. |

## 12. Deployment validation (MEASURED / OBSERVED)

- Disk before and after: 91%, 9.1–9.2 GB free. The deploy was a rebuild of the attack-service image through `./scripts/lab-up.sh --build --remote`; no prune, no volume, index or evidence deletion. No `--refresh-app` was used (Studio XML unchanged).
- Host `git rev-parse HEAD` = `5e7ea0c3…`, re-checked at report time. The host worktree shows only the two pre-existing untracked files.
- Containers at report time: attack service healthy, AcmeBank healthy, Splunk healthy, Ollama healthy, OTEL collector up. Splunk was not restarted.
- Browser-visible layout change: confirmed on `http://<host>:5001` (numbers in sections 4 and 5).
- Splunk connectivity: the live ATTACK/RETEST pair was indexed and queried (section 8).
- The disposable Studio views were created and removed with the REST API as the `admin` user (private user context, outside the repository mount). A first attempt in the shared app context failed with HTTP 500 and created nothing.

## 13. Security invariants

All held, because no runtime, policy, schema or Studio file changed. DOCUMENTED by the diff (templates, CSS, one test file) and OBSERVED in the live pair:

- CTRL-MCP-001 remains the decision point. ATTACK = ALLOW (`vulnerable_profile_fail_open`), RETEST = DENY (`tool_not_granted`).
- Splunk is evidence only. Runtime schema 1.9.0, ExternalEvidence 1.0.0; no new event types.
- No change to the vulnerable/defended profiles, TLS, credentials, or port 5000 exposure.
- The harness read `SPLUNK_PASSWORD` from `.env` at run time and never printed it.

## 14. Remaining defects and limitations

1. **P-1 (400% Studio):** mouse and wheel operation fails; keyboard works; the fix is not applied (owner decision).
2. PREDICT CTA is below the fold at 1024×768 (1039–1103). Not in scope. A two-column layout would fix it (section 15).
3. At 1024×768 the first prediction card can sit partly below the fold when focused (existing).
4. REFERENCE tables scroll internally at 1024 (known L-1).
5. D3 gap: no explicit per-run LIVE chip on the web ATTACK / RETEST / COMPARE steps. Baseline REPLAY and live LIVE labels are clear in Studio and on the baseline step.
6. COMPARE was checked on the fresh ATTACK/RETEST pair only; other run pairs: **UNVERIFIED**.
7. REFERENCE keyboard scrolling at 400%, and mouse clicks on the v3 variant: **UNVERIFIED**.
8. Host disk is still 91% used.
9. **Scratch evidence note:** the scratch folder `/tmp/agentsec-p11` contained files and run logs I did not create (`c2_matrix*`, probe profiles for `ws_lab_mcp_001`), and several of my earlier scratch files (screenshots, JSON, logs) were no longer there at report time. It looks like another process or session worked in the same folder. The numbers in this report are the ones recorded during this session's runs; the before/after screenshots are not stored in the repository and are not recoverable from `/tmp`. The 6 regression tests re-measure the layout and can be re-run. The v0 control values at 100% and 200%, and the accepted-view control values, come from the probe result files (`c_probe_v.js` output) that were present in that folder; I did not run those particular combinations in my own loop, so treat them as MEASURED but with that provenance caveat.

## 15. Recommended owner decision

1. Decide on P-1: (a) approve a narrowly scoped Studio change (taller panels, tested for mouse operation, REFERENCE and START, with the smallest working factor), or (b) accept the limit and document that 400% is keyboard-only for Studio. This report does not label it acceptable.
2. Optionally approve a separate small phase for a two-column PREDICT layout and per-run LIVE/REPLAY chips.

### Figma-to-production gap assessment (design reference: `Design AgentSec Learning Platform_v2.zip`)

Note on order: the Figma archive was supplied after the D-1/D-2 fixes were built from the P1 design. I reviewed `src/App.tsx`, `src/index.css` and `CURSOR_SETUP.md` afterwards and checked the fixes against it. No UI was changed after that review.

| Area | Figma prototype | Production P1.1 | Decision |
|---|---|---|---|
| Layout | Sidebar + topbar shell; the lab page has a header, a business story, a stepper and a two-column grid (lesson plus a sticky prediction panel at ≥1180 px) | Single-column wizard in one academy shell | **Deferred**: the sticky prediction panel would fix the PREDICT CTA at 1024×768. It is a layout change beyond P1.1. |
| CTA hierarchy | One `.button--primary` per area (teal, 44 px minimum height); disabled = 0.45 opacity plus a helper line | One primary CTA per step (60 px high); disabled = dashed border, slate fill, `aria-disabled`, helper text | **Adopted in principle** (already similar). Production kept its own treatment, which is more visible than opacity. |
| START CTA position | "Begin" action sits in the business-story block above the lesson content | CTA moved above the explanation panels | **Adopted** (consistent). |
| Typography | Manrope and DM Mono, 14 px base | Existing academy fonts | **Deferred** (font hosting needs a decision). |
| Spacing | Large padding (25–30 px) in panels | Tightened only where needed | **Rejected** for P1.1. |
| Navigation | Sidebar with collapse, 8 pages | Wizard rail and Studio tabs | **Deferred** (broad redesign). |
| Responsive | Breakpoints at 1180, 820, 620 px | Existing breakpoints | **Deferred**. |
| Accessibility | Skip link, 3 px focus ring, `aria-live` on lifecycle | 3 px focus ring present; no skip link added | **Deferred** (skip link is a small candidate for the next phase). |
| Evidence chips | LIVE / REPLAY / INDEXED badges | Labels in text; no per-run chip on web steps | **Deferred**: closes the D3 gap. |
| Comprehension | Stepper, "Before you click", privacy note | Present in the P1 wizard | Already aligned. |
| Prototype data | In-memory run IDs, "Indexed evidence found · 3 events", fictional scenarios (wallet, multi-agent), "UNKNOWN" label | Real runs and real Splunk evidence | **Rejected**: never imported into production. UNSURE is kept in place of UNKNOWN. |
| Architecture | React/Vite, pnpm | Flask templates plus Dashboard Studio | **Rejected** for P1.1. |
| Dashboard Studio | Notebook as cards in a custom UI | Studio markdown, tables, tokens, tabs | Supported: markdown, tables, tokens, drilldowns, tabs, layout sizes. Needs unsupported customization: sticky panels, custom fonts, card styling, sidebar shell, header changes. |

Nothing from the Figma prototype's metrics, scenarios or mock outcomes entered production.

STOP. Await owner review.
