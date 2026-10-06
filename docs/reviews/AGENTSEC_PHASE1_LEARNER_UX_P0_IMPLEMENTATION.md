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

> **UPDATE 2026-10-06 (later session):** the candidate was deployed and live-qualified. The earlier NOT TESTED statements below are preserved as written; see **LIVE QUALIFICATION** at the end of this document for the measured results and the superseding verdict.

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


---

# LIVE QUALIFICATION (2026-10-06, after the deployment-access gap)

Evidence classes: **MEASURED** = observed in this session on the deployed host or
a real browser; **DOCUMENTED** = read from repository/config; **NOT TESTED** = not
done. No simulated or replayed evidence is presented as new live evidence.
Application code was not changed during qualification.

## Verdict

**CONDITIONAL — LIVE QUALIFICATION INCOMPLETE**

Deployment, evidence integrity, the golden path, the outcome-spoiler control, the
deep link and the Splunk corroboration all passed. The verdict is conditional
because (a) usability at true 200% browser zoom could not be established and the
measured geometry is poor, and (b) two learner-facing copy/label findings (F1, F2
below) would need an application fix, which this session was not allowed to make.
No evidence, security-semantics or schema regression was found.

## Access and remote state

- Access route: AWS SSM to the AgentSec instance (`i-03e570d023ce16d6f`, region `us-east-2`, hostname `agentlabs`), running as user `ubuntu` in `/home/ubuntu/AgentSecLab`. SSH key login still fails; SSM is the working route. No key contents were read or printed.
- Remote refs (MEASURED via `git ls-remote` before deploying): `origin/develop` = `db406fe361e7adc1a616c7326289ecce2b91d12d`, `origin/main` = `0178c70e20cfe0152648e2aafb8e607280625c40` (unchanged).
- `git diff --stat a42d7bf db406fe`: only `docs/reviews/AGENTSEC_PHASE1_LEARNER_UX_P0_IMPLEMENTATION.md` and `docs/learning-notes/learner-ux-p0-journey.md`. No application change after `a42d7bf`.
- **DEPLOYED REPO SHA:** `db406fe361e7adc1a616c7326289ecce2b91d12d` (host was at `b68d0dd`, fast-forwarded with `git pull --ff-only`).
- **APPLICATION IMPLEMENTATION SHA:** `a42d7bf`. These are different values and are not conflated.
- Host working tree: two untracked files that pre-date this work (`refreshAPP.sh`, `test`); not touched.

## Deployment

`./scripts/lab-up.sh --build --refresh-app --remote` (images rebuilt, app restaged, Splunk restarted), 2m 55s. No prune, no volume removal, no Splunk/Mongo/kernel change, no secrets printed. Host disk was 91% used (9.1 GB free) before and after.

| Check | Result |
| --- | --- |
| Containers (actual names) | `agentsec_attack_service`, `agentsec_acmebank`, `agentsec_otel_collector`, `agentsec_splunk`, `agentsec_ollama`: all Up; attack service, acmebank, splunk, ollama healthy (MEASURED) |
| AcmeBank `:5000` | bound `127.0.0.1` on the host; external probe from this machine got no response (MEASURED) |
| HEC `:8088` | bound `127.0.0.1`; external probe got no response (MEASURED) |
| Splunk Academy `:8000`, Attack Service `:5001` | reachable from this machine (HTTP 303 / 200) (MEASURED). HTTP 200 is not evidence readiness. |
| Product identity | AgentSec 1.1.0 (package and `app.conf` version), Splunk app build **5** in the container's `app.conf` and in the Home Build Information view, runtime schema **1.9.0** (in the running attack service), ExternalEvidence **1.0.0** (`EXTERNAL_CONTRACT_VERSION`, DOCUMENTED) |
| Deployed diagram asset | `flow-lab-mcp-001.svg` present in the container with the new stop-bar text (MEASURED) |

## REPLAY regression (Splunk, independent search; MEASURED)

| Specimen | run.id | Indexed | Mode / profile | Tool | Decision / reason | Execution events |
| --- | --- | --- | --- | --- | --- | --- |
| BASELINE | `163d11e2-e751-4282-9406-19b490542ed4` | 7 | BASELINE / defended | `lookup_policy` | ALLOW / `tool_granted` | `mcp.started`, `mcp.completed` |
| ATTACK | `5e8f55f3-eb46-47ee-b979-b72d9c9b1f49` | 7 | ATTACK / vulnerable | `lookup_customer_tier` | ALLOW / `vulnerable_profile_fail_open:…` | `mcp.started`, `mcp.completed` |
| RETEST | `7a1d37b5-d589-4dfd-8322-25ebd0152dbc` | 6 | RETEST / defended | `lookup_customer_tier` | DENY / `tool_not_granted` | `pipeline.stopped`, no `mcp.*` |

These are REPLAYED specimens from earlier validation, re-read from the index; they
are not new experiments. ALLOW in BASELINE means the granted tool was allowed. It
does not mean "safe".

Notebook opened with no LIVE run (1920 and 1024): REPLAY baseline rows render, no
unresolved `$token$`, no "Set token value", no `none<run-id>`. BASELINE prose
is mode-neutral: it names `lookup_customer_tier` only as an example of a known but
ungranted tool and tells the learner to establish the requested tool from Questions
1 to 3. The BASELINE evidence itself shows `lookup_policy` (MEASURED).

## Fresh runs (new, through the real learner workflow)

| | run.id | Indexed (Splunk) | Local evidence pack | Decision / reason | `mcp.started` | `mcp.completed` | `pipeline.stopped` | LLM events |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **ATTACK** | `db3e1c85-768b-41bb-a3cf-84092d85a01c` | 7 | 7 | CTRL-MCP-001 ALLOW / `vulnerable_profile_fail_open:…` | 1 | 1 | 0 | **0** |
| **RETEST** | `a16e6531-7a7d-4077-9fdb-c22b9dc104ff` | 6 | 6 | CTRL-MCP-001 DENY / `tool_not_granted` | 0 | 0 | 1 | **0** |

All MEASURED by an independent Splunk search from the Splunk container, not from
the launcher. Local pack terminals: ATTACK `completed_allowed`, RETEST
`completed_denied`.

- Positive controls: the `mcp.started` / `pipeline.stopped` counters return 1/0 and 0/1 for the REPLAY ATTACK and RETEST specimens through the same logic. The LLM counter (`agentsec.llm.*`) returns 64 events across 8 other runs, so a zero on the MCP runs is a real zero, not a broken counter.
- Execution evidence for ATTACK is the `mcp.started` + `mcp.completed` events and the runtime result. It is not inferred from ALLOW. RETEST's non-execution rests on the absence of `mcp.*` plus the runtime handler count of 0 shown by the launcher, and the stop event. A DENY here does not mean the system is secure.
- Cell 2's query (`ds_nb_execution`) does not contain `agentsec.control.decision` (MEASURED by reading the deployed definition). No LLM evidence is shown or invented for LAB-MCP-001.

## Golden path (real Chrome, 1920 wide; MEASURED)

AcmeBank -> "See how the AI did this" -> "Investigate tool authorization in the AgentSec workshop" -> Workbench -> BASELINE link -> PREDICT -> ATTACK -> investigate -> DEFEND -> RETEST -> investigate -> compare -> explain.

- **Where am I:** the journey strip showed PREDICT on arrival, then ATTACK, OBSERVE, (INVESTIGATE on the Splunk side), COMPARE. Clear.
- **BASELINE:** shown as "STEP · BASELINE · recommended, not required", labelled "recorded (REPLAY) evidence, not something you launch". Its link opened INVESTIGATE with `form.run_id=163d11e2-…` selected and LIVE = `none`. There is no baseline launch button; only ATTACK and RETEST buttons exist.
- **PREDICT:** two separate questions (ALLOW / DENY / ERROR / UNSURE and YES / NO / UNSURE). ATTACK and RETEST were disabled until the prediction was recorded; then ATTACK enabled and the strip moved to ATTACK. Learning state only, not sent to Splunk.
- **ATTACK outcome spoiler (O1): PASS.** After the run the visible state was "EXPERIMENT COMPLETE / Evidence has been generated. Your prediction is locked. Now determine what actually happened from the evidence", with the prediction echoed and "The outcome is deliberately not shown here". The launcher details block stayed collapsed. A scan of the visible page text found no decision or execution outcome beyond the static explanatory copy (the generic "ALLOW != EXECUTION" teaching text and the prediction option labels). Operational detail is still reachable in the collapsed "Launcher result details (technical)" block.
- **DEFEND:** an explanation with zero buttons, links, inputs or forms; says the profile is server-owned, there is no "apply defense" control, and that RETEST "does not show the system is secure". It sits above PREDICT on the page, so it is read before predicting (see F9).
- **RETEST:** card says the evidence is for "the same request under the defended profile" and asks what that profile changed and did not change. The words SAFE, SECURE(D) and FIXED did not appear anywhere on the page.
- **COMPARE:** the collapsed launcher block, once opened, shows the ATTACK vs RETEST table (same fingerprint, tool, scope; different profile, decision, reason, handler count 1 vs 0). EXPLAIN gives four prompts and ends with "does not show a system is compromised, and it does not show a system is secure".

## Deep link (the learner's own "Investigate evidence" click; MEASURED)

- ATTACK handoff landed on `…/ws_lab_mcp_001?tab=layout_investigate&form.live_run_id=db3e1c85-768b-41bb-a3cf-84092d85a01c&form.run_id=163d11e2-…` (Studio appended the REPLAY default). The LIVE input held the run.id, the state panel reported `ATTACK / vulnerable / 7 INDEXED EVIDENCE PRESENT`, no manual paste, no `none<run-id>`, no "Set token value".
- RETEST handoff did the same for `a16e6531-…` (`RETEST / defended / 6`).
- The run.id stays visible as technical metadata on the Workbench, with a Copy button, and the manual fallback paragraph is present.
- Classification: **SUPPORTED WITH CONSTRAINTS.** OBSERVED on this deployment and browser, twice. I did not find authoritative Splunk documentation for URL-prefilling a Studio text input with `form.<token>`, so the class is not upgraded.

## Notebook (five cells; MEASURED, ATTACK and RETEST)

All five cells rendered with QUESTION, WHY THIS MATTERS, the result table, WHAT THE EVIDENCE SUPPORTS, WHAT THIS DOES NOT PROVE, YOUR OBSERVATION and the printed SPL. Visible SPL carries the same run selection the table used. Cell 1 showed CTRL-MCP-001 ALLOW / DENY with the reasons above. Cell 2 showed `mcp.started` and `mcp.completed` (ATTACK) and `pipeline.stopped` (RETEST). Cell 3 showed `requested != allowed` (`customer:read` vs `policy:read`). Cell 4 showed the ordered 7 and 6 events. Cell 5 showed the ATTACK/RETEST pair. The SPL block precedes the result table inside each cell; the P1 restructuring was not attempted.

## Diagram (deployed, MCP MISSION tab; MEASURED)

At 1920 and 1024 it is left to right: USER / AGENT -> TOOL REQUEST (dashed) -> CTRL-MCP-001 -> HANDLER START -> TELEMETRY (dashed, "Splunk observes"), with a stop bar under the control reading "DENY / ERROR: the path ends here, no handler starts". Arrows are clear and there is no red/green. At 1920 it spans most of the panel width. At 1024 it scales down and the sub-labels render at roughly 11 px effective. Narrow vertical stacking is not supported by an image block and was not tested below 1024.

## Responsive (MEASURED)

| Width | Workbench | Notebook (Studio) |
| --- | --- | --- |
| 1920 | no horizontal overflow; journey, BASELINE, prediction, completion card, collapsed launcher block all readable | Studio scroll region 813 px high; all five cells reachable by scrolling; no clipped markdown panel detected |
| 1024 | no horizontal overflow; same elements readable | scroll region 435 px high; reachable; one panel ("Compare your two real runs", 909 vs 902 px) overflowed its box by 7 px |

## 200% zoom

- Genuine browser-level zoom was established this time: Chrome for Testing with a local test extension that calls `chrome.tabs.setZoom(tab, 2.0)` (no CSS transform). Verified in the page: `innerWidth` 960 in a 1920 window, `devicePixelRatio` 2. (Earlier attempts via the Preferences file did not apply, as the previous report said.)
- Workbench at true 200%: no horizontal overflow (960 vs 960).
- Splunk notebook at true 200%: the page itself does not scroll (496 px), the tab bar sits at y = 326, and the notebook scroll region is **132 CSS px high (about 27% of the window)** at y = 357 to 489, because Splunk's own three-row app navigation and header fill the rest. A learner can only read the notebook through that strip. The LIVE run was present in the page text.
- My screenshots at 200% were cropped by the browser automation and do not show the notebook strip, so **visual usability at 200% is NOT TESTED**. The measured geometry suggests it is poor (F3). I did not record a PASS.

## Findings (observed, not fixed)

| ID | Severity | Finding |
| --- | --- | --- |
| F1 | MEDIUM | MISSION "What you do now" still says "Return here and paste it into LIVE run.id. Studio cannot receive that id on its own." That generic guided-learning text (`scripts/apply_guided_learning.py`, shared across labs) now contradicts the deep link on this lab. Needs an application text fix; not made here. |
| F2 | MEDIUM | Studio truncates the two selector titles ("REPLAY evidence to read (rec…", "LIVE evidence: your run.id (fill…") and the dropdown value ("Baseline evidence: n…") at 1920 and 1024, so "recorded, not your run" is cut off. The dropdown still reads Baseline while a LIVE run is the one being read. The words LIVE and REPLAY are visible and the notebook prose and state panel explain the rule, but the selector alone does not say it is only choosing evidence. |
| F3 | MEDIUM | True 200% zoom leaves a 132 CSS px notebook region (see above). Pre-existing Splunk app-navigation cost, not introduced by P0, but P0 did not fix it. |
| F4 | LOW | Workbench launcher block still says "WAITING FOR INDEXING" after the evidence was indexed, until the evidence probe button is used (client-side last-known state, inside the collapsed block). |
| F5 | LOW | Journey strip panel (300 px) leaves about 100 px of blank space. On INVESTIGATE with no LIVE run it still says "Just done: the experiment finished", which is untrue for a REPLAY-only view. |
| F6 | LOW | Cell 5's live pair shows the most recent earlier RETEST (`901a0169-…`) when the learner opens an ATTACK before running RETEST. That is by design ("most recent"), but it is not the learner's run. |
| F7 | LOW | Cell prose "it does not prove nothing else ran" reads as a double negative. SPL still precedes results (P1). |
| F8 | LOW | Diagram sub-labels are about 11 px effective at 1024. |
| F9 | LOW | The DEFEND explanation is read before PREDICT; two identical "Investigate evidence" buttons; ATTACK stays enabled after completion. |
| F10 | INFO | Browser console showed transient 503/404 for Splunk's own `launcher/home` immediately after the restart; no AgentSec asset error was observed. |

Known debt from the earlier report is unchanged: shared evidence-table DENY contrast about 3.08:1 (not re-measured), result-first/SPL-second restructuring (P1), MISSION "Evidence identity" bullets naming the replayed ATTACK outcome. None blocked the flow.

## Test regression

`pytest tests -m "not live_ollama and not live_splunk"` at `db406fe`: **1366 passed, 3 deselected**, matching the earlier run. No test was weakened. No live Splunk/Ollama pytest markers were run; the live checks above are the browser and search evidence in this section.

## Not done

True 200% visual usability (NOT TESTED), widths below 1024, keyboard-only and screen-reader passes, mobile, and any P1/P2 work. Screenshots are scratch files outside the repo.

## Git

Documentation-only commit for this section. No tag, no release, no merge to main, no application code change.
