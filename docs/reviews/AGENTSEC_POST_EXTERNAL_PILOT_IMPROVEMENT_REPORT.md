# AgentSec post-external-pilot improvement report

Evidence classes in this report are labeled. A browser observation is not a Splunk search result. An index-file match is not a search row. A listed model is not a digest.

## Identity

Starting Commit: `07f37e736553689d63d6068b5ed50502218ec6f2`

Ending code commit: `496e84917313e41667da5138cccdaf68f9de94f4`

The review documents are committed on `develop` immediately after that code commit. The ending commit recorded in `AGENTSEC_V1_1_READINESS_REVIEW.md` is the commit that contains both reviews.

Origin/Develop: `496e84917313e41667da5138cccdaf68f9de94f4` at the code push. Updated again when these reviews are pushed.

Main: `15f379e37773f250f70bc43270e64325590525e4` (local and `origin/main`)

v1.0.0 Integrity: tag object still peels to `537be71a13a5776c42a59ee9a25e2d4051d34ad0`. `v1.0.0-rc1`, `v1.0.0-rc2`, and `v1.0.0-rc3` were not moved. No force push. No merge into `main`. No `v1.1.0` tag. No GitHub Release.

`develop` contains `07f37e736553689d63d6068b5ed50502218ec6f2` as an ancestor.

Untracked and left untouched: `docs/plans/` and `docs/reviews/AGENTSEC_REMOTE_DEPLOYMENT_VALIDATION.md`.

## Security contracts

ATTACK Contract: preserved. Final remote ATTACK `20a3d2e1-91a4-4519-b214-b8f2324e2873` returned `terminal=completed_allowed`, profile `vulnerable`, schema `1.9.0`, control decision `ALLOW` with the vulnerable fail-open reason, and `llm_call_count=4`. The visible state was `WAITING FOR SPLUNK` / `RUN IN PROGRESS`. The meta line still said `request=accepted`. Completion was not treated as a successful attack.

RETEST Contract: preserved. Final remote RETEST `db8ba6ba-f4df-4016-a6de-a2373b1f18cd` returned `terminal=completed_denied`, profile `defended`, schema `1.9.0`, control decision `DENY`, reason `input_pattern_matched`, and `llm_call_count=0`. The visible state was `RUN DENIED`. That sentence says authorization is not execution.

CTRL-MCP-001: unchanged. It remains the tool authorization PDP. Splunk remains downstream.

Authorization vs Execution: the ATTACK response carries `ALLOW` and a separate `llm_call_count` of 4. The RETEST response carries `DENY` and a separate `llm_call_count` of 0. The UI does not treat one as the other.

Schema: `1.9.0` (`SCHEMA_VERSION` in `src/agentsec/experiment.py`). Both final launch responses reported `1.9.0`.

ExternalEvidence: `1.0.0` (`EXTERNAL_CONTRACT_VERSION`).

DET-MCP-001: saved search `AgentSec - MCP Execution After Authorization Deny` remains `disabled = 1` and `enableSched = 0`. It was not enabled.

## Remote deployment

Command, both times, as `ubuntu` in `/home/ubuntu/AgentSecLab`:

`./scripts/lab-up.sh --build --refresh-app --remote`

No `compose down -v`. No `docker system prune`. No `git reset`. No certificate-verification change. Named volumes were left in place.

First rebuild in this program moved the checkout `07f37e7..77a4f0d`. `lab-up` exited 0 in 2m 47s. `SERVICE READY`. Model name `llama3.2:1b` listed. That listing is not a digest.

Final rebuild moved `77a4f0d..496e849`. `lab-up` exited 0 in 2m 42s. `SERVICE READY`. The script still prints that external browser reachability is not measured by `lab-ready`. The browser measurements below were made from this workstation.

Home -> Search: OBSERVED. `http://3.17.29.24:8000/en-US/app/search/search` stayed on `3.17.29.24` and redirected to Splunk login with `return_to` for Search. The logged-in Search page was not rendered. No Splunk password was read.

Home -> Attack Service: the served `agentsec_open_attack.js` was fetched after the final deploy (655 bytes). It uses `window.location.hostname` and contains no `127.0.0.1` and no `localhost`. Execution of that script onto `http://3.17.29.24:5001/` was OBSERVED earlier the same day on this host. The script file was not part of commit `496e849`.

Attack Service -> Search: OBSERVED on the final page. Open Splunk Search, Open ATTACK in Search, Open RETEST in Search, and Compare in Search all used `http://3.17.29.24:8000/...`.

Attack Service -> Academy: OBSERVED. Return to Academy was `http://3.17.29.24:8000/en-US/app/agentsec/ws_agentsec_home`.

Learner-facing loopback defects: 0 on the final Attack page. Visible text did not contain `127.0.0.1` or `localhost`. Served HTML did not contain `http://127.0.0.1:8000` or `http://localhost:8000`.

## Attack Service

Prediction UX: the form offers control `ALLOW` / `DENY` / `ERROR` / `UNKNOWN` and execution `YES` / `NO` / `UNKNOWN`. It is stored in `sessionStorage` under `agentsec.learner.session.v1`. The launch JSON body remains `lab_id`, `specimen_id`, `mode`, and `execution: "live"`. After the final RETEST, the page compared the stored guess with the response and said the comparison is not a grade.

Launch-state UX: final ATTACK showed `RUN IN PROGRESS` with `request=accepted` still in the meta line. Final RETEST showed `RUN DENIED`. The copy still separates that control outcome from `BACKEND UNAVAILABLE`, and it still says completion is not proof the attack succeeded.

run.id UX: both ids were shown in the meta line as an investigation handle, not a verdict. Copy run.id, Copy SPL, Open Splunk Search, and Return to Academy are on the page.

Search handoff: remote host and port 8000, as above. Local, loopback, remote IPv4, and DNS hostname behavior remains covered by the existing navigation tests. The real EC2 address is not hardcoded in production code or in those tests.

ATTACK/RETEST comparison: one browser session held both runs. Session history listed RETEST `RUN DENIED` `db8ba6ba-f4df-4016-a6de-a2373b1f18cd` and ATTACK `RUN IN PROGRESS` `20a3d2e1-91a4-4519-b214-b8f2324e2873`. Compare in Search used both ids on `3.17.29.24:8000`. The history line is mode, state, run id, and timestamp. It is not a verdict.

Session history: browser tab only. No account. No identity claim.

## Curriculum

Workshops reviewed for this cycle: A2A auth delegation, HITL approval, credential lifetime, and component provenance. The other workshops were not rewritten for novelty.

Workshops diversified: A2A (Card Cedar, Card Birch, Card Alder), HITL (Packet North, Packet South), credential lifetime (Story Elm, Story Oak). Order is static. Path B answer keys remain for after the learner writes a classification.

Answer leakage removed: the self-review found the Attack Service still printing expected decisions before launch. That was removed in `496e849`. See the review section below. Path A of the three diversified workshops does not open with the old mode-pair sentence. Path B is still an answer key.

Active reasoning added: the launcher asks for a control prediction and an execution prediction. The diversified workshops ask which card or story is outside the grant, which packets match, and which evidence is missing. Free-form text is not graded.

Evidence semantics preserved: `MEASURED`, `OBSERVED`, `DOCUMENTED`, `REPLAYED`, and `SIMULATED` stay separate from claim-strength words such as `PROVEN`, `SUPPORTED`, `INFERRED`, `NOT OBSERVED`, `NOT MODELED`, `NOT PROVEN`, and `REFUTED`.

## Provenance

Ollama lesson: `ollama/ollama:latest` remains unpinned. No digest was invented.

Generic dependency lesson: a SIMULATED graph, not a scan of this repository and not an npm or PyPI lookup: `classroom-ledger` → `ledger-client@1.4.2` → `sigil-utils@0.9.1`.

Inventory vs trust: the workshop states that an inventory line is not trust, a package name is not provenance, a version string is not integrity, and `latest` is not an immutable identity.

Provenance claims: the graph is labeled SIMULATED. A simulated signature is not a verification that occurred.

Unverified claims: no Cisco AI-BOM compliance claim was added. No digest was measured for the Ollama image.

## Visual identity

Gated-A: `src/agentsec/static/agentsec-mark.svg` and `docs/brand/agentsec-mark.svg`. Dashed claim lines meet a gate. The description says the gate is not proof that every claim was authenticated. No shield, padlock, robot, or sparkle mark.

Evidence sequence: `docs/brand/agentsec-evidence-sequence.svg`. Claim, delegation/context, CTRL-MCP-001, execution. Dashed links are not proof those stages occurred.

README architecture: `docs/brand/agentsec-architecture.svg` is included from `README.md` and `docs/ARCHITECTURE.md`. The existing text diagram remains. CTRL-MCP-001 is the gate. Splunk is downstream. No new component was added.

Accessibility descriptions: the SVGs include text descriptions. They are drawings, not a certification.

## Documentation

Linux: prerequisites and Docker Engine / Compose v2 are documented. The measured clean-room host was macOS. Linux is the documented container path and was the EC2 host for this remote rebuild (Ubuntu). That rebuild is a remote deploy of an existing checkout, not a from-empty Linux install timing study.

macOS: quickstart and prerequisites describe Docker Desktop. Hardware minimums are not benchmarked.

Windows: documented as NOT VALIDATED. No PowerShell installer was added.

Prerequisites: `docs/AGENTSEC_PREREQUISITES.md` and `docs/QUICKSTART.md`.

Precheck: `./scripts/precheck.sh` runs the same checks as `lab-preflight.sh`. `WARN` exits 0. `FAIL` exits 1. Neither is a control DENY. The 8 GB disk line is a planning floor, not a benchmarked minimum.

lab-up: starts the local Compose profile. `--build` rebuilds images. `--refresh-app` restages the Splunk app. `--remote` publishes 8000 and 5001 on `0.0.0.0` and leaves the private ports private. Existing named volumes stay.

lab-ready: `SERVICE READY` means the health checks answered. It does not mean a `run.id` is searchable. HEC HTTP 200 is not indexed evidence. A healthy service is not a successful attack. A listed model is not a digest. Academy views loading is not an accessibility certification.

Remote deployment: `docs/REMOTE_ACCESS.md` and `./scripts/lab-up.sh --remote`. An SSH tunnel is not the documented learner path.

Timing guidance: the quickstart quotes the earlier qualification clocks as observations, not guarantees, and lists what makes the next boot differ.

Troubleshooting: empty Search is not DENY. Certificate verification is not disabled as a workaround.

## Accessibility

Measurements are of the Attack Service page in headless Chrome after the console changes. Academy and Splunk pages behind login were not opened. Splunk chrome was not modified.

1920: Attack Service `scrollWidth` 1920 equals `clientWidth` 1920. No wider elements. OBSERVED.

1440: same, 1440. OBSERVED.

1280: same, 1280. OBSERVED.

1024: same, 1024. OBSERVED.

200%: CSS `zoom: 200%` at a 1024 CSS-pixel layout. `scrollWidth` still equaled `clientWidth`. OBSERVED. This was CSS zoom in headless Chrome, not a manual browser zoom menu on a logged-in Academy page.

Keyboard: eight Tab events in headless Chrome left `document.activeElement` on an anchor. That is not a reliable measurement of sequential tab order. Focusing `#fire-attack` in script showed `outline-style: solid` and `outline-width: 2px`. Launch buttons are native `type="button"`. Sequential keyboard reachability: NOT RELIABLY MEASURED.

Visible Focus: OBSERVED for programmatic focus on Launch ATTACK, as above.

Screen Reader: NOT TESTED

WCAG Claim: none.

## Live validation

Host: `3.17.29.24`. Checkout `496e84917313e41667da5138cccdaf68f9de94f4`. One browser session on `http://3.17.29.24:5001/labs/LAB-PI-001`.

ATTACK run.id: `20a3d2e1-91a4-4519-b214-b8f2324e2873`

ATTACK searchable: the Search handoff URL uses that id on `http://3.17.29.24:8000`. Splunk Web was not logged in, so a search result row was NOT MEASURED. After the run, `hot_v1_3/Strings.data` and `hot_v1_3/rawdata/0` both contained the id. That is index presence, not a search row.

ATTACK decision: `ALLOW`. Reason text is the vulnerable-profile fail-open reason for `ignore_previous_instructions`. Four control rows.

ATTACK execution: `llm_call_count=4`. `terminal=completed_allowed`. `evidence_state=WAITING_FOR_EVIDENCE`. These are separate from the decision.

RETEST run.id: `db8ba6ba-f4df-4016-a6de-a2373b1f18cd`

RETEST searchable: same split. Handoff URL on `3.17.29.24:8000`. Both the lexicon file and `rawdata/0` in `hot_v1_3` contained the id. A Splunk Web result row was NOT MEASURED.

RETEST decision: `DENY`. Reason `input_pattern_matched`.

RETEST execution: `llm_call_count=0`. `terminal=completed_denied`. `evidence_state=WAITING_FOR_EVIDENCE`.

## Testing

Focused tests: launcher, web UI, RAG, memory, identity, academy, and capstone unit tests: 83 passed.

Full suite: `1082 passed, 3 deselected` (`not live_ollama and not live_splunk`).

Repeated reliability: after the launcher copy fix, 11 consecutive full offline suites in this session were clean (`1082 passed, 3 deselected` each). An earlier loop in this program, before that copy fix, recorded one failure of `test_concurrent_rag_attack_and_retest_do_not_leak_profile` in a ten-run loop, then isolated repeats of that test passed and a later full suite passed. The assertion was not changed.

git diff --check: clean on the launcher remediation diff.

Secret hygiene: the remediation diff had no password assignment, API key, private key, AWS access key, GitHub token, or certificate block. `.env` was not committed. No new cryptographic implementation was added.

Codeguard: this cycle did not add credentials, certificates, or cryptographic algorithms. Existing lab defaults and the Splunk password stay in `.env` and in the container environment. They were not printed and were not committed.

## Learner-style review

This review was written after the first five commits were already on `develop`, using the served page and the docs rather than the author's intention.

Findings, recorded before the fix:

1. MEDIUM. The Attack Service printed the expected control decision before launch. On LAB-PI-001 the RETEST card stated `DENY` and `input_pattern_matched`. Memory, goal, and identity cards, and the MCP, context, and authority launchers, also printed the expected decision beside the buttons. A learner could confirm the page instead of reading the response.

2. LOW. `/favicon.ico` still returns an empty 204. The page links the SVG mark. Browsers that only request `/favicon.ico` do not get the mark.

3. LOW / measurement gap. Sequential Tab in headless Chrome did not move focus. Visible focus was observed only when the button was focused in script.

4. Measurement gap. Academy and Splunk pages at 1920, 1440, 1280, 1024, and 200% were not measured. Splunk login was not used, because that would have meant reading the lab password.

5. Measurement gap. Splunk Web did not return a search row in this session. Index files did contain the run ids. `lab-ready` already says HEC HTTP 200 is not indexed evidence.

6. Not a defect. Path B in the workshops still contains the answer key. That is after the learner is asked to classify.

Remediation of the MEDIUM finding: commit `496e849`. The launcher asks for the prediction and does not print the decision or the reason. Headings the existing tests require (`Predict before ATTACK`, `Predict before RETEST`, `WHAT WOULD FALSIFY THIS?`) remain. A unit test now fails if the LAB-PI-001 page contains `input_pattern_matched`.

Rerun after the fix:

- Unit tests 83 passed. Full suite 1082 passed, 3 deselected, then 10 more consecutive clean runs.
- Served `http://3.17.29.24:5001/labs/LAB-PI-001` after the rebuild: prediction form present, `input_pattern_matched` absent, loopback Search hrefs absent.
- The same page, in one browser session, launched the ATTACK and RETEST recorded above. Visible text still had no loopback. Search and Academy links stayed on `3.17.29.24`.

No BLOCKER, HIGH, or MEDIUM finding remained after that rerun.

## Counts

BLOCKER: 0

HIGH: 0

MEDIUM: 0

LOW: favicon route still empty; sequential keyboard order not reliably measured; Academy viewports behind login not measured; Splunk Web result rows not measured.

Accepted Debt: those LOW items and measurement gaps. Windows and Podman remain NOT VALIDATED. Path B answer keys remain. The earlier concurrent RAG flake was not reproduced in the final 11 full-suite runs and was not patched by weakening the test.

FINAL VERDICT:

PASS — READY FOR INDEPENDENT v1.1 EXTERNAL LEARNER PILOT
