# Final pilot preparation (Batch 9): readiness report

**The human pilot has NOT been conducted.** Everything below is automated or operator-run evidence about the environment, not a usability result.
Branch `feature/phase1-hardening` (base `f6d104e`). Not merged. `develop` untouched (`b86accc`, the same 19 uncommitted entries). KV_MODE unchanged.
No lab container was recreated or restarted; no Docker volume was deleted; no model was downloaded.

## 1. The previously reported background command
- **It had not finished.** It was still running after 15 h 10 min (PID 13668 with child `grep -rl`, 0% CPU, state S).
- **Cause:** the command greps `artifacts/` in the develop tree recursively. Four **named pipes (FIFOs)** sit in `artifacts/loan_desk/rejected/`: they are the hostile FIFO requests from the Gate B forgery tests, which the verifier quarantined as FIFOs. `grep -r` blocks forever in `open()` on a FIFO with no writer.
- **Changes it made: none.** It is read-only (`os.listdir`, `grep -rl`, `git log -S`, `grep -rl`) and its output file stayed 0 bytes. Worktree clean, `develop` HEAD and its 19 entries unchanged.
- **Exit status:** **143** (SIGTERM). I terminated exactly those two PIDs after confirming their command lines; it never exited by itself.
- **Follow-up worth knowing:** any operator or tool that recursively reads `artifacts/` (for example `grep -r`) hangs on those four FIFOs. They are gitignored, inside develop's tree, and I left them (not mine to delete without your say). Recommendation: delete the four FIFOs by hand, and let the verifier's quarantine record hostile non-regular files as a metadata note instead of keeping the file.

## 2. Backup of the original September Splunk volume
| | Volume `0aa27f8fe380...` (the one you named) | Volume `65a0bd8b9afe...` (found during step 3) |
|---|---|---|
| Created | 2026-09-12 | 2026-09-11 |
| Content | 60 buckets, 2,036 events | 56 events (2026-09-11 to 2026-09-12) |
| Backup | `~/agentsec-backups/splunk-var-sept-20261023.tgz` (2.4 GB, mode 0600) | `~/agentsec-backups/splunk-var-sept11-20261023.tgz` (394 MB, mode 0600) |
| Archive SHA-256 | `2d1ee5bb...a075` (full value in the `.sha256` file beside it) | `b0695a0e...8ed1` |
| Integrity check | `gzip -t` passes; extracted into a scratch directory and **all 8,761 file hashes equal the hashes taken from the source volume** | `gzip -t` passes; hash list of 3,344 files recorded beside it |
| Original altered? | No: mounted read-only; still present, creation time unchanged | No |
A copy of each volume (not the original) was opened in a throwaway Splunk to read it; that copy reports 2,036 events, equal to the original index.

## 3. Historical dropdown specimens (PI, RAG, MEMORY, GOAL, DELEGATION, CAPSTONE)
**19 of 19 missing runs restored, 0 unavailable.** Method as in Batch 8: copy of the volume, throwaway Splunk, verbatim `_raw` per run id ordered by `agentsec.sequence`, repo validator, additive seeding.
- 15 runs came from volume `0aa27f8f`; the method check reproduced the three committed LAB-MCP-001 packs byte for byte.
- **The 4 LAB-PI-001 runs were not in that volume.** They are Phase 2 runs (about 2026-09-11) and live only in the second volume `65a0bd8b`, which I found by scanning every Docker volume read-only for an `agentsec_telemetry` index. The method check cannot be repeated there (it holds no MCP-001 run), so the check is: the repo validator passes, `agentsec.sequence` is contiguous, and the event counts equal what the Phase 2 documents recorded (6, 22, 6, 22).
- The nine CAPSTONE dropdown runs were already committed (Batch 8) under the incident labs; byte-identical copies now sit in the capstone's own folder so each lab carries its own pack. The advanced capstone's three goal packs are copies as well; its scanner and garak envelope runs stay with the labs that already own them (Batch 8) and are not duplicated.
- **Files:** 31 added under `learning/level_1/<LAB>/specimens/`, 28 distinct runs. Provenance, per-pack SHA-256 and the backup hashes: `specimen_recovery.json`. All events remain `LIVE` / `OBSERVED` as recorded; the labs stay labelled REPLAY. No event, timestamp, run id or schema version was changed.
- **Live Splunk:** seeded additively with the unchanged `splunk_hec_init.sh` seeder ("VERIFIED searchable" for all 19; 56 already-present runs: "No action"). Then, per run: count equals the pack, `dc(_raw)` equals the count (no duplicates), and the `_raw` multiset equals the pack: **28 of 28 identical**. The index total is now 3,628 events (it was 2,714 after Batch 8); that includes the new packs and also the events from the 21-launch sweep and the two mission runs made for regression, which are ordinary live runs. Nothing was removed.
- **One conflict, resolved in the project's own mechanism:** the recovered PI-001 events carry the retired label `AML.T0054`, and a Batch 1 guard allowed only declared legacy ids (`AML.T0050`). The project policy already says pre-correction specimens are "historical evidence, not rewritten", and `AML.T0054` was already listed as a retired label for ATK-002. I declared it in `learning/academy/framework_refs.json` (`legacy_specimen_ids`, and the note). It is still not a verified framework id and learners still never see it as one. I did not touch the evidence or the guard.
- **One stale test updated:** `test_run_id_without_a_committed_pack_is_reported_unseeded` used a RAG run id as its "unseeded" example, which was true until this batch. It now uses an id that really has no pack, and a second test asserts the old example is seeded.

## 4. Regression
| Check | Result |
|---|---|
| 31 original entries, same probes as Batch 7 against the current tree | **0 changed or removed files, 0 launch differences, 0 page differences, 0 registry changes**; only specimen packs were added. The 21 in-process launches equal the baseline. Global differences are identical, key for key, to Batch 7's (same enhancements, nothing new): classification stays 24 PRESERVED, 7 ENHANCED, **0 REGRESSED**, 0 UNVERIFIED |
| 21 LIVE launches on the deployed lab | HTTP 200, same event counts as Batch 8 (`live_lab_sweep_after_batch9.json` equals the Batch 8 sweep row for row) |
| New specimens, bound queries in the live Splunk | 162 searches over 27 selector states, **0 errors**, every state has rows |
| New specimens, Splunk Web views | 6 labs, **27 states, 0 search errors, 0 "No results found" panels** (`restored_views_live.json`, screenshots). The capstone's INVESTIGATE tab is instructional text by design, so its data panels were checked separately on the EVIDENCE tab for the attack and the retest sets: 32 and 28 event names, 0 errors, 0 empty panels |
| `learner_ready.py` | **28/28**, now checking the 15 specimen labs (was 9) |
| Loan Desk mission, real browser, real model, deployed lab | attack `5f47536e-e0ab-4bab-a5c0-15009abd9192` 34/34 and retest `5acdaa6d-37d2-498e-848b-686517696f90` 44/44, both SPLUNK-VERIFIED by the host verifier and independently reconciled; "Workflow complete". The retest has 44 events this time (48 in Batch 8): a 3B model varies |
| Test suite | **1965 passed, 35 skipped, exit 0** (1947 at Batch 8; +18 new tests) |
**Zero material regressions.**

## 5. Pilot launch checklist
`docs/PILOT_LAUNCH_CHECKLIST.md`: one page, eight steps with pass conditions and fixes: machine, whole-lab check, model readiness (with warm-up), Splunk login, verifier health, browser reset, evidence check, hand-over, plus disclosures, in-session fixes and after-session steps.
Facts found while writing it, now in the checklist:
- **Ollama unloads the model about 5 minutes after last use** (`ollama ps` showed "34 seconds from now"), so the first participant would hit a cold model unless the operator warms it within 5 minutes of hand-over. The load time was not measured.
- **The reset control the earlier checklist named does not do the job.** "Reset this mission" is inside the final step, which a participant who stopped early cannot reach. Mission answers live in the browser tab; the progress marker is cleared by "Reset browser progress" on `/academy/path`. Procedure: close the tab, open a new one, press that button. `scripts/pilot_reset_check.py` proves it through the real UI (`reset_check.json`: ok). The progress marker itself is only written by later steps, so this check proves the tab state and the reset control but not a marker written by a full run.
- The mission page has no standing verifier status line; the verifier is covered by `learner_ready.py` and `loan_desk_verifier.sh status`.

## 6. What could still stop five real learners from completing the mission
**Would prevent it:**
1. **Participants must sit at this Mac** (or share its screen). Every URL is `127.0.0.1`; nothing is exposed to the network. Five remote participants cannot do the mission.
2. **Sessions must be one at a time.** Concurrent participants were never tested; one Ollama instance serves one 3B model and AcmeBank keeps run history in memory.
3. **Do not restart the lab from the `develop` tree before the merge.** The running containers carry the read-only receipts mounts only through a deploy override. `lab-up.sh` or `docker compose up` run from `develop` would recreate AcmeBank and the Attack Service without those mounts, and the page would refuse to show SPLUNK-VERIFIED. Recovery is `python3 scripts/deploy_acmebank_attack.py deploy` (Batch 7). Merging first removes this risk.
4. **The model must be installed and the machine must not sleep.** The lab cannot download it.

**May degrade it (disclosed):** the hardened run sometimes ends INCOMPLETE; the first run after idle is slow; the verifier is operator-run and is not supervised (a reboot kills it); Splunk Web's own session can lapse, so step 4 is re-checked each session.

**Untested, so unknown:** browsers other than Chromium; keyboard-only and screen-reader use by a person (axe and scripted keyboard tests only); Windows and Linux hosts; a first boot with a cold image cache; a restart of an existing Splunk with the Loan Desk view; any measured completion time (the 25 to 40 minute figure is an author estimate).

## Decisions for you
1. The merge (strategy in `docs/reviews/batch8/MERGE_PLAN.md`); doing it before the pilot removes blocker 3.
2. Delete the four stale FIFOs in `develop/artifacts/loan_desk/rejected/`, or leave them.
3. Docker volumes went from 25 to 29, because you said not to delete volumes. Mine: scratch copies `agentsec_recover_var` (6.3 GB) and `agentsec_recover_var2` (1.4 GB), labelled `agentsec.purpose=recovery-batch9`, plus two anonymous volumes the Splunk image created for the two stopped containers `agentsec_recover_splunk` and `agentsec_recover_splunk2` (anonymous ids start `7477de71` and `d9eeaab2`). None holds anything not already in the two backups and the repository. Approve their removal (containers first, with `docker rm -v`), or keep them.
4. Recruiting five participants and naming the operator. Nothing in this batch has measured a learner.

Also disclosed: pulling the small `busybox` image (for the read-only copy and tar) was a download of a Docker image, not a model; nothing else was fetched.

## Addendum: portable paths (commit `bbc5c0c`)
Absolute home-directory paths this branch had introduced were replaced: recorded Batch 7 deploy/preflight and both `preservation_head.json` files use `<HOME>`, and `scripts/gateb_adversarial_live.py` now defaults `ART` to the repository's own `artifacts/` directory.
**`ART` must now be set explicitly** when testing receipts stored in the `develop` tree (the lab Mac's case): `ART=<develop tree>/artifacts python3 scripts/gateb_adversarial_live.py <run id>`. The default must not be changed back to a machine path. Paths already in earlier published commits were not rewritten.
