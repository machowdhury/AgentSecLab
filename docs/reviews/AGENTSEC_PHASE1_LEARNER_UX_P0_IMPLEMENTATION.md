# AgentSec Phase 1: Learner-UX P0 Implementation Report

Date: 2026-10-06. Scope: bounded P0 learner-UX work on LAB-MCP-001 only.
No P1/P2 work, no tag, no release, no merge to main.

## Verdict

**CONDITIONAL — P0 REMEDIATION INCOMPLETE**

The P0 code is implemented, committed and pushed to `develop`, and the offline
suite passes. It was **not deployed**, so every claim that needs the deployed
Splunk or a live ATTACK/RETEST run is **NOT TESTED**. The session could not
establish SSH access to the EC2 host (see "Why deployment stopped"). Nothing in
this report is represented as a live measurement unless it says MEASURED and
names what was measured.

## Why deployment stopped

- Stage 13 needs shell access to the EC2 host. `ssh ubuntu@3.17.29.24` returned
  `Permission denied (publickey)` with the default identities, and again with the
  one other key file present in `~/.ssh`. I did not try other usernames, other
  keys, or other access routes: guessing credentials is not "establishing state".
- Local `127.0.0.1:8000` is a **different** project's Splunk
  (`splunk-netspout-standalone`), not AgentSec. I did not touch it, and I did not
  start a local AgentSec stack on top of it.
- Result: Stages 13 to 18 are NOT TESTED. This is an access gap, not a design
  conflict. No hard-stop condition about evidence, security semantics or schema
  was triggered.

## Starting and resulting state

| Item | Value |
| --- | --- |
| Starting SHA (validated candidate) | `b68d0ddf951349bf410fd7449ea3ed46b71d8a58` |
| Design provenance commits | `1bb1c67` (design spec + mockups), `8aed1a2` (review docs) |
| Implementation SHA | `a42d7bf` "feat: clarify Phase 1 learner journey" |
| Deployed SHA | **NONE. NOT DEPLOYED.** |
| `origin/develop` | `a42d7bf` (push succeeded, develop only) |
| `origin/main` | local tracking ref still `0178c70e20cfe0152648e2aafb8e607280625c40`; I did not push to or merge main. The remote was not re-queried (the network call was blocked), so "unchanged on the remote" is NOT VERIFIED |
| Schema / ExternalEvidence | 1.9.0 / 1.0.0, unchanged (pinned by a test) |
| Splunk app build | 4 -> **5** (see "Identity change") |

### Identity change to note

`flow-lab-mcp-001.svg` is a packaged static asset and it changed. The repository
contract (`scripts/static_cache_identity.py`) requires the app build to move, so
`[install] build` went 4 -> 5 and `splunk_app/static_cache_identity.json` was
rewritten. The product version (1.1.0) is unchanged. The Home dashboard was
regenerated because its Build Information panel reads the build and digest.
The brief listed "Splunk app build 4" as the starting baseline; build 5 is the
intended consequence of the diagram change, not an unexpected control change.

## Sources reviewed

- A: `docs/design/AGENTSEC_PHASE1_LEARNER_UX_REDESIGN.md` (primary spec, with the section 12 Figma reconciliation).
- B: `docs/design/mockups/phase1-learner-ux.html` and `docs/design/mockups/frames/*`.
- C: `Design AgentSec Learning Platform_v2.zip`. DOCUMENTED: readable; used as a visual reference only; not modified; no build artifacts copied into the repo.

Figma v2 adopted: stage grouping (UNDERSTAND / TEST / PROVE), the left-to-right
trust-path idea, a clear "you are here" marker, large radio cards for prediction.
Figma v2 rejected: "LLM calls: 4" (real LAB-MCP-001 has zero LLM events),
invented run IDs and canned event counts, `get_customer_transactions` (the real
baseline tool is `lookup_policy`), canned notebook answers, Denial-of-Wallet /
Sensitive Disclosure / multi-agent scenarios, a global cross-surface sidebar, and
9 to 11 px learner type.

## Files changed (implementation commit)

- `scripts/build_lab_mcp_001_dashboard.py` and the regenerated `learning/level_1/LAB-MCP-001/dashboard.definition.json`, `splunk_app/agentsec/default/data/ui/views/ws_lab_mcp_001.xml`
- `src/agentsec/search_handoff.py`, `src/agentsec/attack_app.py`, `src/agentsec/templates/attack_mcp.html`, `src/agentsec/static/agentsec-workbench.css`
- `src/agentsec/workshop_flows.py` and `splunk_app/agentsec/appserver/static/flows/flow-lab-mcp-001.svg`
- `splunk_app/agentsec/default/app.conf`, `splunk_app/static_cache_identity.json`, regenerated Home dashboard (`learning/home/…`, `ws_agentsec_home.xml`)
- Tests: new `tests/splunk/test_learner_ux_p0.py`; updated `test_investigation_notebook.py`, `test_lab_mcp_001_dashboard.py`, `test_agentsec_ui_shell.py`, `test_static_cache_identity.py` (each edit carries a "CONTRACT CHANGE" comment, none was loosened to pass).
- Not touched: `agentsec_learner_path.js` (Your Path), schemas, controls, telemetry, runtime, Splunk or Mongo configuration, any other lab.

## P0 results

Evidence class for everything in this section: **DOCUMENTED** (repository
contract tests) unless marked MEASURED.

| ID | Change | Result |
| --- | --- | --- |
| P0-A | Notebook prose is mode-neutral. The header and cells no longer say the run requested `lookup_customer_tier`; they send the learner to Questions 1 to 3 to establish which tool the run requested. | Pinned by test. Whether it reads correctly for a LIVE BASELINE run: NOT TESTED (BASELINE is REPLAY only here). |
| P0-B | `investigate_url()` builds `…/ws_lab_mcp_001?tab=layout_investigate&form.live_run_id=<run.id>`. Strict lowercase-UUID check; token name and tab come from fixed tables; nothing else is forwarded. The unprefixed `live_run_id=` is never generated. The plain `workshop_url` and the manual paste fallback remain. | **SUPPORTED WITH CONSTRAINTS.** Earlier OBSERVED: `form.<token>` prefilled the Studio input on one deployment and the unprefixed form did not. It is not in Splunk's documentation. Deployed behavior of this build: **NOT TESTED** (no deployment). `studio_token_binding` stays `NOT SUPPORTED / DO NOT BUILD`. |
| P0-C | The REPLAY selector is titled "REPLAY evidence to read (recorded, not your run)" with `(REPLAY)` labels; the LIVE input is titled "LIVE evidence: your run.id (filled by the Workbench link)". Both are said to select evidence, not run an experiment. | Pinned by test. Rendered look inside Studio: NOT TESTED. |
| P0-D | Workbench has a surface-local ten-step journey with a "you are here" marker, a BASELINE step that links to REPLAY evidence only, a DEFEND explanation with no button, and an EXPLAIN prompt block. Studio has matching text strips on MISSION and INVESTIGATE. Nothing is marked INVESTIGATED automatically. No cross-origin sync. | Workbench layout MEASURED locally (below). Studio strips: NOT TESTED in a browser. |
| P0-E | Two separate prediction questions: ALLOW / DENY / ERROR / UNSURE and YES / NO / UNSURE. UNSURE is accepted. Stored value stays `UNKNOWN`. | MEASURED locally: real clicks recorded DENY + NO, unlocked ATTACK, journey moved to ATTACK. No launch was made. |
| P0-F | MCP golden-path diagram is left to right: USER / AGENT -> TOOL REQUEST -> CTRL-MCP-001 -> HANDLER START -> TELEMETRY. A stop bar under the control reads "DENY / ERROR: the path ends here, no handler starts". Telemetry is dashed ("Splunk observes"). No red/green. Type is 16 to 19 px. Still 1440x200, so the shared image-block geometry is unchanged for all 31 labs. | MEASURED: rendered in Chrome at 1440x200, no clipping, labels and arrows visible. Appearance inside a Studio image block: NOT TESTED. |
| O1 | After ATTACK the normal path shows an "EXPERIMENT COMPLETE" card that points to evidence and contains no outcome words. The fact cards, decision chain and comparison moved into a collapsed "Launcher result details (technical)" block with a warning. They are subordinate, not removed. | Pinned by test; collapsed on load MEASURED locally. The completion card after a real launch: NOT TESTED. |

### Notebook hierarchy

The visible SPL is still the executed SPL (`with_spl()` unchanged; existing
VISIBLE == EXECUTED tests pass). SPL now sits at the end of each cell. A full
"result first, SPL second" split into separate panels was **not** done: the
shared cell contract requires QUESTION, WHY, DOES NOT PROVE, YOUR OBSERVATION and
the printed SPL in one cell, and Dashboard Studio has no collapse. That split is
deferred as P1.

### Accessibility and contrast

MEASURED (WCAG ratios computed with a script, not assumed):

- Workbench status amber was below 4.5:1 and was corrected with a CSS override.
- Smallest learner-facing text measured on the rendered Workbench at 1920 and 1024: **15 px** (the P0 target was at least 14 to 16 px).
- State is carried by text labels, not colour alone (UNSURE, "recorded (REPLAY)", "you are here" marker).
- **Known defect, not fixed:** the DENY label in the shared evidence table measures about **3.08:1**. It lives in `EVIDENCE_TABLE_CONTEXT`, which is shared by 13 labs, so changing it is outside a LAB-MCP-001 P0. Recommended fix: `#7A4E00`. Deferred.
- Full-page keyboard walkthrough and screen reader testing: NOT TESTED.

## Test results

- Focused: `tests/splunk/test_learner_ux_p0.py` has 39 tests. All pass. They cover the deep link (encoding, UUID rejection, no unprefixed token, honest classification, fallback text), baseline constant equals the builder's `BASELINE_ID`, selector/LIVE labelling, journey, BASELINE replay-only, no fake DEFEND control, RETEST wording, prediction separation and UNSURE, collapsed launcher details, outcome-free completion card, horizontal diagram and stop bar, no LLM claims, schema 1.9.0, Your Path asset unchanged, and no hard-coded hosts.
- Full offline suite, run after the final change: `.venv/bin/python -m pytest tests -q -m "not live_ollama and not live_splunk"` gave **1366 passed, 3 deselected, exit 0** (baseline was 1327 passed; the 39 new tests account for the difference).
- No live Ollama or live Splunk test was run.

## Browser evidence

| Check | Status |
| --- | --- |
| Diagram rendered in Chrome at 1440x200 | MEASURED, screenshot reviewed |
| Workbench served locally by the Flask app (no AcmeBank, no Splunk), Chrome 1920 and 1024 | MEASURED: no horizontal overflow (scrollWidth equals clientWidth at both), launcher details collapsed, ATTACK disabled until a prediction is recorded, then enabled |
| Splunk Studio rendering of the changed tabs and panel heights | **NOT TESTED** |
| Deep link with a live run.id | **NOT TESTED** |
| Real-browser walkthrough with a live ATTACK then RETEST | **NOT TESTED** |
| 200% zoom | **NOT TESTED** (no genuine 200% browser zoom was performed) |

Screenshots are scratch files outside the repo (`/tmp/agentsec-reval/p0-workbench-*.png`, `flow-mcp-1440.png`); they are local-render evidence only.

## Fresh run evidence

- Fresh ATTACK run.id: **NONE. NOT RUN.**
- Fresh RETEST run.id: **NONE. NOT RUN.**
- Indexed event counts: **NOT MEASURED.**
- LLM-event check on a fresh run: **NOT TESTED.** The REPLAY specimens (BASELINE `163d11e2-…`, ATTACK `5e8f55f3-…`, RETEST `7a1d37b5-…`) remain REPLAYED evidence from earlier validation and are not presented as new measurements. The surfaces assert no LLM activity for this lab.

## Known debt

1. Studio panel heights (journey strip 300, header 1000, mission 600) are **unmeasured** in a real Studio render. They may clip or leave gaps. This needs a browser against the deployed app.
2. Result-before-SPL panel split (P1).
3. Shared evidence-table DENY contrast, 13 labs (P1).
4. Studio image blocks cannot stack a diagram vertically on narrow widths.
5. The Workbench prediction question about DEFEND sits above PREDICT on the page; a learner reads the DEFEND explanation before predicting. It does not name an outcome, but a reviewer should judge whether that order still protects the prediction.
6. The pre-existing MISSION "Evidence identity" bullets name the REPLAY attack outcome ("labeled fail-open ALLOW, handler=1"). That predates this work and was not changed; it deserves a leakage review in P1.
7. EVIDENCE and PATH B tabs were not changed.

## Deferred (P1/P2, not started)

Recent-runs selector (O4), SPL reference tab (O3), cross-surface progress sync,
progress persistence, new telemetry, schema or control changes, new labs,
PyRIT, garak, MITRE mapping, Denial-of-Wallet, Sensitive Disclosure,
multi-agent, Phase 2.

## Git status

Implementation committed (`a42d7bf`) and pushed to `develop`. This report is
committed separately. Untracked `.tmp-path-pre/` scratch files are not staged.
Nothing was merged to main, tagged or released.

## What is needed to finish

1. Provide the EC2 SSH user and key (or run the deploy yourself): `git pull` to `a42d7bf` and `./scripts/lab-up.sh --build` (templates changed, so `--refresh-app` alone is not enough), no prune, no volume deletion, AcmeBank `:5000` not exposed.
2. Then: confirm deployed HEAD equals `a42d7bf`; run a fresh ATTACK and RETEST; confirm indexed counts and zero LLM events; walk the real browser flow; test the deep link; measure Studio panel heights at 1920 and 1024; do a genuine 200% zoom pass.

## Recommendation

Do not run independent learner-UX validation yet. Complete the deployed checks
above first. If the deep link or panel heights fail on the deployed build, fix
those two items only.
