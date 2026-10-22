# Batch 4 notes: complete the learner experience

## Deployed (project agentseclab)
Running now: `agentsec_acmebank` = image f842f5855910 (tag batch4-74a715a), `agentsec_attack_service` = 1f7da726749d (batch4-74a715a). Splunk, collector and Ollama containers were never recreated (uptimes 43-45 h). Volumes identical before and after (`diff` of `docker volume ls`). Splunk app volume: additive copy (`cp -a`), views/nav reloaded through Splunk `_reload`, no Splunk restart; backup tarball validated by restoring it into a scratch volume (pre-Batch-4 app, build 5, no loandesk view) and removing that volume.
Rollback was exercised for real: pre-batch4 images retagged `latest` and both containers recreated (mission gone, existing Academy and MCP-001 lab still served, volumes identical), then rolled forward again. Anchors kept: `pre-batch4-463c765b9930` (acmebank), `pre-batch4-e5dc7f88bc9a` (attack_service).
The host verifier was started with `scripts/loan_desk_verifier.sh start` and is still running on this Mac (`artifacts/loan_desk/verifier.pid`); `lab-up.sh` starts it and `lab-down.sh` stops it. Its files (key, heartbeat, requests, results) are in the lab's git-ignored `artifacts/loan_desk/`.

## Acceptance journey (real stack, UI only)
`scripts/loan_desk_acceptance.py` -> `acceptance/acceptance_run.json`, `acceptance/screenshots/` (17 images).
Final run: attack 6485db0f-e05a-4547-9ed4-42b2040d76f9 (34 events; page verified through the bridge: 34 indexed of 34), retest f494c39f-44cf-4557-be28-0d45953614da (42 events; verified 42/42; independent reconciliation identical). Compare step "Verify both runs" verified both. Earlier runs of the same journey: 7cda628d-daf8-4aa8-9b16-47188b329a98 (34/34), c163a09f-094e-4464-89c3-ec8419ceed08 (44/44). `naive_value_count` is exactly 2x events for every run (multivalue).
Offline and recovery (real): verifier stopped -> "NOT VERIFIED. The host verifier is not running..." -> verifier started -> SPLUNK-VERIFIED (screenshots 16, 17).
Splunk view `ws_lab_loandesk_001` rendered in Splunk Web with real data for both runs (screenshots 13-15).

## Bugs the real runs found (all fixed, with tests)
1. Re-verifying a run that already had an answer showed "NOT VERIFIED" instead of pending (old nonce vs new request). State machine fixed; regression test.
2. The Compare-step verification message was erased by the table re-render. Status moved outside the re-rendered area.
3. A rate-limited (429) verify click stopped watching the outstanding request. It now keeps watching.
4. My first Splunk capture typed the run id into the global search box (script error); fixed.

## Known limits and blockers
- The verification bridge requires a host with python3 and docker (Mac/Linux). Not tested on Windows. Without the verifier the page says NOT VERIFIED and why; nothing is ever shown as verified without an authenticated answer.
- The bridge key is a file in the shared artifacts directory: it stops forgery by anything that cannot read it (the model, tools, browsers) but not by a process that can write to `artifacts/`. See VERIFICATION_BRIDGE.md.
- `agentsec.sequence` duplication: root cause established (SEQUENCE_DUPLICATION.md). NO props or telemetry change was made. The 92 run-bound hunt executions are identical under `KV_MODE = none`; 49 unbound hunts and dashboard panels were not exercised, so the change is proposed, not applied.
- Hardened runs can end INCOMPLETE (the model keeps retrying the planted note). The page now says plainly that the attack was blocked and that incompleteness is a usability cost, not a control failure. Measured in Batch 3: 19/20 hosts runs completed, 3/5 in Docker.
- The mission runs only with a local Ollama model `llama3.2:latest` (digest a80c4f17acd5…); other models were not re-benchmarked this batch.
- Learner time (25-40 min) is an author estimate, not measured with learners.
- Curriculum is now 32 entries (31 preserved + LAB-LOANDESK-001), 37 Studio views. Seven inventory tests pin those sets; they were updated deliberately (comments say why). Splunk app build moved 5 -> 6 (static digest lock updated) because the learner-path script and a flow SVG changed.
- The new Splunk view was added to the running Splunk by an additive volume copy and `_reload`; a full `lab-up.sh --refresh-app` (which restarts Splunk) was not run.
