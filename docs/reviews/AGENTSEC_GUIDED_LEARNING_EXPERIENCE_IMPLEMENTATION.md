# AGENTSEC GUIDED LEARNING EXPERIENCE IMPLEMENTATION

Starting Commit: 0178c70e20cfe0152648e2aafb8e607280625c40
Ending Commit: 97b121e2d5a146bbd729634662b60af96aff47df
Remote Sync: develop is pushed after this record. main was not updated. The commit that writes this hash is a child of 97b121e and does not change product code.

Product Version: 1.1.0 (unchanged; this is post-v1.1.0 work on develop, not a release)
Schema: 1.9.0
ExternalEvidence: 1.0.0
DET-MCP-001: disabled (`disabled = 1`, `enableSched = 0`)
CTRL-MCP-001: tool PDP, unchanged

## PRODUCT DIRECTION

Guided Learning North Star: Academy Home, Your path, and a guide band on the first tab of each existing workshop. The learner sees level, lesson, current step, an inline Splunk search, what the rows do not prove, and the next workshop.
Existing Curriculum Preserved: L0–L10 labs and checkpoints remain. No workshop view was removed. LIVE and REPLAY modes were not reclassified.
CTF/Arena Position: Arena is a separate nav view after Mastery. It is labeled optional and links to the existing LIVE launchers. It is not the default view.

## LEARNER SHELL

Where Am I: generated from `learning/academy/curriculum.json` into `viz_guide_shell` (level, title, step, mode).
Objective: the level `learn` text, or the checkpoint title.
Current Step: numbered position in the grouped curriculum order.
Investigation: LIVE workshops bind an empty `live_run_id` text input to `ds_guide_events`. REPLAY workshops that already have `run_id` reuse that specimen token. Workshops with no run token get the orientation band only.
Interpretation: the guide states that a decision row is not execution and an execution row is not a downstream resource change.
What It Does Not Prove: the same band states that an empty table is not DENY, HEC HTTP 200 is not the table, and one RETEST is not universal protection.
Next Step: the next view in the same order, then Arena after Mastery Check.

Mechanism: `scripts/apply_guided_learning.py` writes the shell into the existing Studio definitions and the matching `*.definition.json` files. It does not delete tabs.
Live Browser Validation: MEASURED on local Splunk after `./scripts/lab-up.sh --refresh-app --build`. Headless Chrome, logged in, opened `ws_lab_pi_001`. The rendered text included "LIVE run.id", "Where you are", "Direct Prompt Injection", and "What this does not prove". An input with aria-label `LIVE run.id` was present and empty. After the native value setter and an input event for run id `24b5237e-01b4-41ef-a28c-b8bd38e9e705`, a `search/jobs` POST contained that id and the page text contained it. That run id was absent from the page text before the token was set.

## PROGRESS

Persistence: `localStorage` key `agentsec.learner.progress.v1` on the Splunk origin. Classic view `learner_path` with `agentsec_learner_path.js`.
States: NOT STARTED, IN PROGRESS, INVESTIGATED. `setState` rejects any other word, including ALLOW.
Home Progress: Home links to Your path. Studio Home cannot read `localStorage`. The counts render on Your path.
Workshop Progress: the guide links to Your path. Opening a workshop does not mark it investigated.
Reset: the reset control removes only that key. The Node contract test observed the workshop return to NOT STARTED and the Attack Service session key untouched.
Server-Side State Added: none.
Security Evidence Relationship: progress is navigation state. It is not indexed evidence and not a control decision.
Rendered button clicks on Your path: NOT MEASURED. Unauthenticated curl of `learner_path` returned HTTP 303 (login redirect), not 404.

## NAVIGATION

Top-Level Entries Before: 21 `<collection>` elements plus Home, Mastery Check, and Search.
Top-Level Entries After: 13. Home, Your path, nine curriculum collections, Arena, Search.
Final Groups: Foundations; Context Security; Agent Intent; Capstone; Blue Team and Threat Modeling; Identity and Delegation; Data and Memory Governance; Operational Scenarios; Mastery. The groups follow the existing L1–L10 and checkpoint order. Singleton menus were collapsed. View names and human labels were kept.
Curriculum Alignment: view order inside the groups is the previous learner order. `next_lab` still walks level labs and was not retargeted through checkpoints.
Broken Links: not found in the nav contract tests. Every collection view has a file. Headless Chrome rendered the new labels on the PI page.
Why 13 rather than 12: Your path, Arena, and Search each need to stay visible. Hiding Your path would hide the only progress surface.

## IN-PAGE INVESTIGATION

Direct Prompt Injection Pilot: implemented on `ws_lab_pi_001` and then the same generator was applied to the other workshops. The input primitive rendered.
Run.ID Input: `input.text`, title `LIVE run.id`, token `live_run_id`, default empty. MEASURED in Chrome.
Token Binding: the definition query is `index=agentsec_telemetry` with `"agentsec.run.id"="$live_run_id$"` and `where "$live_run_id$"!=""`. MEASURED: a search job POST contained the pasted id.
Inline Search: that POST went to `/servicesNS/-/agentsec/search/jobs`.
Inline Table: `viz_guide_events` is `splunk.table`. After the token was set, the run id appeared in the page text. The individual table cells were not separately scraped.
Visualizations: a second table, `viz_guide_summary`, counts indexed copies by event name, decision, and executed. It is not a decorative chart.
Explanation: the guide band. The rendered page included "What this does not prove".
Raw Search Required: no. Search remains linked as the advanced path.
Advanced Search Available: yes. Existing HUNT tabs still link to `/en-US/app/search/search`.

Pilot Live Validation: local Chrome, as above. The rendered no-data sentence was NOT MEASURED; `document.body.innerText` did not include "No indexed event matched" before the paste. The input was empty and the fresh run id was absent until the token was set.
Platform note: `input.text` rendered on Splunk 10.2 in this lab. Expansion was not stopped.

## LIVE LAB ROLLOUT

All seven curriculum LIVE labs have `live_run_id`, `ds_guide_events`, and `viz_guide_events`:

- LAB-PI-001 / ws_lab_pi_001 — guide plus Chrome pilot
- LAB-MCP-001 / ws_lab_mcp_001 — guide; fresh indexed ATTACK and RETEST measured in Splunk Search
- LAB-RAG-CONTEXT / ws_lab_rag_context — guide in the definition. Fresh launch was not completed (specimen id used in the check was rejected HTTP 400).
- LAB-MEMORY-001 / ws_lab_memory_security — guide in the definition. Fresh launch NOT MEASURED in this pass.
- LAB-AGENT-GOAL-INTEGRITY-001 / ws_lab_agent_goal_integrity — guide in the definition. Fresh launch NOT MEASURED.
- LAB-AGENT-DELEGATION-001 / ws_lab_agent_delegation — guide in the definition. Fresh launch NOT MEASURED.
- LAB-AGENTSEC-CAPSTONE-001 / ws_lab_agentsec_capstone — guide in the definition. Fresh launch NOT MEASURED.

## REPLAY WORKSHOPS

Canonical Specimens: existing Investigate specimen dropdowns were kept. REPLAY views did not gain a paste box.
Inline Investigation: if the view already has a `run_id` token, the guide table uses it. If it has no run token, the guide is markdown only, so an empty token cannot search the index.
ATTACK/RETEST/BASELINE Semantics: specimen labels and later tabs were not rewritten.
Historical Evidence Boundaries: the guide says a canonical specimen is not a launch just minted, and simulated or historical claims stay in the workshop's own words.

## SESSION / LEARNER STATE

LAB-PI: `attack.html` already recorded launches. It now also paints `session-pair`. Served HTML contains `session-history` and `session-pair`.
LAB-MCP: `attack_mcp.html` records through `captureLaunch` and renders the shared list. Served `/labs/LAB-MCP-001` contains `session-history` and "LAST KNOWN CLIENT STATE". Loopback Search href count in that HTML: 0.
LAB-RAG: `attack_context.html` calls `captureLaunch` with the page lab id.
Memory: same template, lab id from the page, so a memory run is not paired with a RAG run.
Goal: `attack_authority.html` calls `captureLaunch` with that page's lab id.
Identity/Delegation: same template and the same lab-id rule.
Reload: sessionStorage key `agentsec.learner.session.v1` is unchanged. The Node test reloaded the helpers against the same storage and the PI pair survived.
Last Known Client State: `historyText` and `paintSessionPair` say LAST KNOWN CLIENT STATE and not indexed evidence.
Launcher Terminal: `captureLaunch` stores `runtime.terminal` when the response has it. The label stays client state.
Indexed Evidence: not written by this browser list. Splunk Search is still the evidence query.
Comparison Rehydration: PI still rebuilds the comparison list from the stored pair and labels it as not a Splunk verdict. Other labs show the paired run ids in `session-pair` and do not copy those ids into the measured comparison table until this page launches them. The Node test showed an MCP ATTACK is not paired with a PI RETEST.

## ARENA

Implemented: `ws_agentsec_arena`.
Position: after Mastery, before Search.
Labs Available: the seven LIVE labs through `open_attack?path=/labs/<lab_id>`.
Guided Curriculum Duplicated: no. Arena does not copy workshop dashboards.
Security Semantics: the page repeats that a decision is not execution, an empty search is not DENY, and HEC HTTP 200 is not indexed evidence.
Authenticated render: NOT MEASURED. Unauthenticated curl returned HTTP 303.

## REMOTE DEPLOYMENT

Loopback Learner Links: `REPLAY_HUNT_BANNER` in `scripts/agentsec_studio.py` no longer uses `http://127.0.0.1:8000`. Existing views already used `/en-US/app/search/search`. The restaged Home view inside the local container had zero `127.0.0.1:8000` matches. Chrome page text for PI had no `127.0.0.1:8000`.
Origin-Aware Navigation: Attack Service links still use `open_attack`, which sends the browser to port 5001 on the current hostname.
Remote Browser Validation: NOT MEASURED. This pass restaged the local lab only.

## UI / UX

1920: MEASURED. `documentElement.scrollWidth` 1920 and `clientWidth` 1920 on the PI page.
1440: MEASURED. 1440 and 1440.
1280: MEASURED. 1280 and 1280.
1024: MEASURED. 1024 and 1024.
True Browser 200% Zoom: NOT MEASURED.
Horizontal Overflow: no document-element overflow at those four widths. Individual visualization overflow was NOT MEASURED.

## ACCESSIBILITY

Keyboard: NOT TESTED on a physical keyboard. The Chrome check dispatched input and keyboard events from script.
Visible Focus: the Your path script adds an outline on its own buttons. That outline was NOT MEASURED in a browser.
Focus Order: NOT TESTED.
Screen Reader: NOT TESTED.
Dashboard Studio Native Tab Focus: PLATFORM LIMITATION — SPLUNK 10.2. Not remeasured. No Studio stylesheet was added.
WCAG Claim: none.

## LIVE SECURITY VALIDATION

Local precheck was the `lab-up` readiness check. It exited 0. It printed SERVICE READY and MODEL ABSENT. HEC health HTTP 200 was printed and the script said that is not indexed evidence. Ollama `llama3.2:1b` was not listed. LIVE generation is DEGRADED. Certificate verification was not disabled.

Fresh ATTACK Run: MCP `29c9936e-d4ff-4f77-8f23-c6959208f783`. Launcher terminal `completed_allowed`. Handler count 1. Schema 1.9.0.
ATTACK Decision: Splunk Search, decision event `agentsec.control.decision` ALLOW, `executed=false`.
ATTACK Execution: separate indexed events `agentsec.mcp.started` and `agentsec.mcp.completed`, `executed=true` on those events.
ATTACK Indexed Evidence: MEASURED by `splunk search` inside `agentsec_splunk`, CSV output, not a hot-bucket string match.

Fresh RETEST Run: MCP `f24e7c19-fed8-4db8-b57d-fa3386bee7a3`. Launcher terminal `completed_denied`. Handler count 0.
RETEST Decision: indexed `agentsec.control.decision` DENY, `executed=false`.
RETEST Execution: the event-name search did not list `agentsec.mcp.started` or `agentsec.mcp.completed` for this run id.
RETEST Indexed Evidence: MEASURED. RETEST did not inherit the ATTACK execution events.

PI ATTACK `7751ec66-2884-4f7d-956d-3d1f3188d5c4`: launcher terminal `run_failed`. Indexed `agentsec.control.decision` ALLOW `executed=false`, plus `agentsec.llm.started` and `agentsec.llm.failed`, plus `agentsec.run.failed`. This is a failed LIVE generation under MODEL ABSENT, not a completed attack outcome.
PI RETEST `24b5237e-01b4-41ef-a28c-b8bd38e9e705`: indexed decision DENY `executed=false`. Event names included `agentsec.run.completed` and did not include `agentsec.llm.started`. This is the id used in the Chrome token check.

Authorization vs Execution: held for the MCP pair. The decision event and the start event are different rows.
Resource Impact: NOT PROVEN. No downstream resource change was measured.

## TESTING

Focused Tests: Splunk UI slice 337 passed, 2 skipped, after the guide injection. Two later full-suite failures were the published-view inventory, which did not yet list `ws_agentsec_arena.xml`. Those assertions were updated to include the new view. They are inventory contracts, not security assertions.
Full Offline Tests: first full run in this program, before that inventory update, exited 1: 2 failed, 1092 passed, 3 deselected. After the update, suite 1 of the reliability run exited 0.
10x Reliability: 10 consecutive runs, exit 0 each. Each reported 1094 passed, 3 deselected. Durations on the first and tenth were 9.24s and 8.41s. Output was redirected to a file. The exit code was the pytest status, not a pipe.
The earlier failed full run is not erased.

## SECURITY INTEGRITY

Schema: 1.9.0. `SCHEMA_VERSION` assertion remains.
ExternalEvidence: 1.0.0.
DET-MCP-001: saved search stanza still `disabled = 1` and `enableSched = 0`.
CTRL-MCP-001: not edited. MCP RETEST still indexed DENY with no mcp.started.
Secrets: changed files were scanned for `AKIA`, private-key blocks, certificate blocks, `ghp_`, and `sk_live_`. The only hits are absence assertions already in `tests/splunk/test_privacy_data_governance.py`. `.env` was not committed. Secret values were not printed.
Certificates: none added. The Splunk CLI printed its existing warning that server certificate hostname validation is disabled in `server.conf`. This program did not change that file and did not disable TLS verification.
Tokens: the LIVE run.id box is an investigation handle, not an authentication token. No API tokens were added.
TLS Verification: not disabled.
Cryptography Added: none.

Codeguard: no hardcoded credentials, no new certificates, and no new cryptography. The rule was applied by scanning the diff and by not adding auth material. Synthetic run ids from the lab are investigation handles.

## RELEASE INTEGRITY

v1.0.0: not moved. Peeled commit remains 537be71a13a5776c42a59ee9a25e2d4051d34ad0.
v1.1.0: not moved. Peeled commit remains 0178c70e20cfe0152648e2aafb8e607280625c40.
Main Modified: no.
v1.2.0 Created: no.
GitHub Release Created: no.

## FILES / COMMITS

Files Modified: academy dashboards and definitions, Home, navigation, Attack Service templates and `agentsec-ui.js`, curriculum groups, learner docs, and the UI tests that named the old singleton menus or the exact search-id set.
Commits Created: this report is committed with the product change. The ending hash is the develop tip after push.
Untracked Files Left Untouched: `docs/plans/` and `docs/reviews/AGENTSEC_REMOTE_DEPLOYMENT_VALIDATION.md`.

## FINDINGS

BLOCKER: none in the guided-learning scope.
HIGH: none.
MEDIUM: local Ollama model is absent, so PI LIVE generation is DEGRADED. The PI ATTACK run failed after `llm.started`. MCP ATTACK and RETEST did not need that model and were indexed.
LOW: the rendered empty-table sentence was not observed in `innerText`. Your path clicks, Arena while logged in, remote Chrome, physical keyboard, screen reader, and 200% zoom were not measured.

## KNOWN LIMITATIONS

- Studio cannot receive a fresh run.id from Attack Service. The learner pastes it. OBSERVED in the product copy and in the Chrome input starting empty.
- Progress is browser-local. MEASURED in the Node contract. Rendered clicks NOT MEASURED.
- Browser session history is LAST KNOWN CLIENT STATE. It is not a Splunk verdict.
- Dashboard Studio native tab focus remains PLATFORM LIMITATION — SPLUNK 10.2. NOT RE-MEASURED here.
- True browser 200% zoom: NOT MEASURED.
- Screen reader: NOT TESTED.
- Physical keyboard: NOT TESTED.
- Remote browser: NOT MEASURED.
- Resource impact: NOT PROVEN.
- MODEL ABSENT on this local lab. LIVE generation DEGRADED. OBSERVED.
- HEC HTTP 200 is not indexed evidence. The indexed rows above came from `splunk search`.
- Navigation has 13 top-level entries. The approximate target was 10–12. Search, Arena, and Your path are the extra visible entries beyond the nine curriculum groups and Home.

## FINAL VERDICT

READY FOR INDEPENDENT GUIDED-LEARNING PILOT

## Independent reviewer checklist

1. A new learner can see Home as the start and Direct Prompt Injection as the first action.
2. Home states the path without requiring the README.
3. Your path shows the level and the next workshop.
4. Mark a workshop in progress, reload, and see the same state.
5. Reset clears that list and leaves indexed events in place.
6. The nav is the grouped bar, not the old 21 collections.
7. Launch Direct Prompt Injection, paste the fresh run.id, and see rows on the workshop page.
8. Confirm those rows with Splunk Search for that exact run.id.
9. Complete that investigation without using raw Search.
10. Read the SPL on the guide band.
11. Open the other LIVE labs and confirm the same LIVE run.id box.
12. Open a REPLAY workshop and use Investigate specimen. Confirm it does not pretend to be a fresh launch.
13. Reload Attack Service lab pages for PI, MCP, RAG, Memory, Goal, and Identity and confirm the session list remains.
14. Launch ATTACK and RETEST in one lab, reload, and confirm the pair is labeled last known client state.
15. Confirm that label is not presented as a Splunk verdict.
16. Open the lab from a non-loopback hostname and confirm links do not jump to 127.0.0.1.
17. Before pasting a run.id, confirm the guide does not show that run's decision.
18. For an MCP ATTACK, confirm ALLOW on the decision event and execution on a separate mcp.started event.
19. For an MCP RETEST, confirm DENY and the absence of mcp.started. That is not universal protection.
20. Confirm Arena is after Mastery and is labeled optional.
21. Confirm the previous workshop tabs are still present.
22. Confirm the does-not-prove language is still on the guide.
23. Confirm schema 1.9.0.
24. Confirm ExternalEvidence 1.0.0.
25. Confirm DET-MCP-001 is disabled.
26. Confirm CTRL-MCP-001 still decides tool authorization before the handler.
27. Confirm tags v1.0.0 and v1.1.0 still peel to 537be71a13a5776c42a59ee9a25e2d4051d34ad0 and 0178c70e20cfe0152648e2aafb8e607280625c40.
28. Confirm no Studio stylesheet and no Splunk vendor JavaScript patch was added.
