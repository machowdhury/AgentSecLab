# Disposable cold-start results (2026-10-22)

Preflight: `COLD_START_PREFLIGHT.md`. Harness: `scripts/cold_start_disposable.sh`. Source: a fresh `git clone` of
`feature/phase1-hardening` at `93ffe02` (the commit before this document), built and started under project `agentseclab_cold`.

## What ran
| Step | Result |
|---|---|
| Preflight | PASSED: ports free, no `agentsec_cold_*` object existed, 12 GB Docker VM, four third-party images already local |
| Rendered-config isolation check | PASSED: every container name `agentsec_cold_*`, only ports 15000/15001/18000/18088/14317/14318, no bind mount outside the clone, no Docker socket |
| Clean clone, new `.env` (random credentials, 0600), new HEC certificates, new artifacts dir | done; lab `.env` never read |
| Build of AcmeBank and Attack Service from the clone | built (cached layers; seconds) |
| Splunk 10.2 cold boot (amd64 under emulation) | healthy about 2 minutes after start, here, with a warm image cache |
| Collector, HEC init, AcmeBank, Attack Service | all healthy |
| Disposable Ollama | **never started** (its entrypoint pulls a model); nothing was downloaded |

## Findings from the cold copy
1. **First-run model check, Phase A (no Ollama reachable):** the mission reported `Ollama reachable from AcmeBank: Not ready`, `Model llama3.2:latest installed: Not ready`, and showed the manual command `ollama serve` with the note "Nothing is downloaded by the lab." Screenshot `cold_start/screenshots/01_first_run_ollama_not_reachable.png`.
2. **Phase B (AcmeBank pointed at the host Ollama, which already had `llama3.2:latest`):** available, digest `a80c4f17acd5…`, same digest as the running lab. No pull.
3. **Read-only receipts verified from inside the real containers.** In both `agentsec_cold_acmebank` and `agentsec_cold_attack_service`: `touch receipts/forged.splunk.json` returned `Read-only file system`; Python `open(..., "w")` raised `OSError errno 30`; `/proc/mounts` showed the mount as `virtiofs ... ro`; `receipts_isolated()` returned `True`. `requests/` stayed writable. `find /app/artifacts -name "*.key"` found **no key** in the container.
4. **Loan Desk Splunk view and nav present on a clean install** (`ws_lab_loandesk_001.xml`, nav entry), which closes Batch 5 risk C7 for the fresh-install path (the restart path on the running Splunk is still untested).
5. **Full learner journey, browser, real model, own verifier, own Splunk:** Academy home, mission, explore, predict, attack, observe, investigate with **Verify with Splunk**, defend, retest, compare with "Verify both runs", explain, "Workflow complete".
   - Attack `b704910a-9b66-4800-aacf-d3a9853edc2b`: SPLUNK-VERIFIED, 34 of 34 events.
   - Retest `f11c2d8f-303f-4bce-9610-855454324e1f`: SPLUNK-VERIFIED, 48 of 48.
   - Independent reconciliation agrees for both (34/34 and 48/48 distinct sequences; the naive value count is exactly 2x, 68 and 96, the known duplicate extraction).
   - Receipts audited on the host with the host key: `AUTHENTIC ... scope: ... not proof the events are true`.
   - Raw: `cold_start/acceptance_run.json`, screenshots `cold_start/screenshots/`.
6. **Verifier lifecycle on a real stack.** The verifier died when the harness shell that started it ended (an environment artifact, not a defect: it had already answered everything). That left a stale pidfile; `status` correctly said "not running", `start` replaced it (pid 60698 to 61846), `stop` ended it with the log line `verifier stopped cleanly` and a `stopped` heartbeat. The lab's own verifier (pid 66419, v1) was not touched.
7. **Harness defect found and fixed:** `down` removed containers with `docker rm -f` and left the two anonymous volumes of the Splunk image. They were identified by creation time (the second the disposable Splunk was created), absence from any container, and absence from the pre-run snapshot, then removed by id. `down` now uses `rm -f -v`.

## Cleanup and proof the running lab was not affected
Removed: 6 disposable containers, the 2 named and 2 anonymous disposable volumes, the `agentseclab_cold_agentsec_mesh` network, the two `agentseclab_cold-*` images, the clone and the override file. Counts afterwards: 0 containers, 0 volumes, 0 networks, 0 images with the disposable project label or prefix.
Compared with the snapshot taken before `up`: the five running containers have **identical names, ids and images** (no restart or recreate); the volume list is **identical** (after the two orphans above were removed); `acmebank` and `attack_service` health on 5000 and 5001 answered 200; Splunk reported healthy throughout; the develop tree is still branch `develop` at `b86accc` with the same 19 dirty entries.

## Not covered
- The branch's own `lab-up.sh` was **not** run (it hard-codes the real container names); the harness used `docker compose` directly with an override. The `lab-up.sh` verifier start/stop and `mkdir` lines are still only syntax-checked plus the scratch-directory lifecycle tests.
- Splunk's first boot here reused a warm image cache; a first-ever boot on a new machine (image pull, 10 to 20 minutes) was not timed.
- A **restart** of an existing Splunk with the new view (`--refresh-app`) remains untested, by instruction.
- Windows and Linux hosts.
