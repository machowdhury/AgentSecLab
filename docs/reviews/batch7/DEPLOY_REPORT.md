# Gate B: hardened verifier deployment

Date 2026-10-22. Tooling: `scripts/deploy_acmebank_attack.py` (`preflight`, `deploy`, `rollback`), `scripts/gateb_adversarial_live.py`. Evidence: `docs/reviews/batch7/deploy/`, `deploy_acceptance/`.

## Preflight (14 of 14 passed before anything was changed) - `deploy/preflight.json`
| # | Requirement | Evidence |
|---|---|---|
| 1 | containers, image tags, mounts, verifier identity | acmebank `agentseclab-acmebank` id `f842f5855910`, attack_service `1f7da726749d`, both healthy, project `agentseclab` from the Compose labels (develop tree compose files, read only). Mounts: shared artifacts dir rw, telemetry volume, lab manifests ro; no Docker socket. Verifier: pid 66419, parent 1, started 13:24, `loan_desk_verifier.py --artifacts <lab>/artifacts`, matching the pidfile |
| 2 | backup and rollback | rollback anchors `agentseclab-acmebank:pre-batch7-f842f5855910`, `agentseclab-attack_service:pre-batch7-1f7da726749d`; `artifacts/loan_desk` archived to `~/agentsec-backups/loan_desk-<ts>.tar.gz` (0600, outside every repo; the archive lists every file) |
| 3 | historical run and evidence retention | Splunk holds 2,029 events across 84 run ids; nothing in the procedure deletes any; counts recorded |
| 4 | no running learner sessions | zero non-health requests in either container in the previous 10 minutes |
| 5 | safe migration of signing material and receipts | old `.bridge.key` backed up first and left in place until cutover was validated; old receipts archived. The new key was generated on the host only |
| 6 | no credentials exposed | no credential-named environment variable in either container; both new images scanned: no `.env`, `.pem`, `.key` or `.bridge*` file |
| 7 | Splunk, collector, Ollama untouched | `up -d --no-deps --no-build acmebank attack_service`; a dry run named only those two containers |
| 8 | no volume deleted | no `down`, `-v` or prune is in the command set; 25 volumes before and after |

## What was deployed
Images `agentseclab-acmebank:batch7-f4f8f5e` (`354f3048b5ef`) and `agentseclab-attack_service:batch7-f4f8f5e` (`8204acc82316`), built from the branch, with the new read-only receipts mount on both containers. The Attack Service image also carries `framework_refs.json` (a baseline defect fix, Gate A finding 1): the Attack UI home and all seven lab pages went from HTTP 500 to 200.
Cutover: the old verifier (pid 66419) was verified by its command line and stopped; the v2 verifier was started from the branch; the old key, v1 receipts, v1 heartbeat, pidfile and log were removed from the container-visible directory (v1 files into `legacy_v1/`, the key only in the 0600 backup).

## Validation, all on the deployed stack
| Check | Result |
|---|---|
| Real browser mission, real model (llama3.2:latest, digest `a80c4f17acd5...`) | all ten steps, "Workflow complete"; screenshots in `deploy_acceptance/screenshots/` |
| Baseline attack and hardened retest | attack run `d16165fc-3b93-4e20-b3d8-88c3eef08732`; retest `bf30e568-bd0e-452d-8aa4-1ae000cfcc8c` |
| Splunk reconciliation | independent: 34 of 34 and 48 of 48 events, distinct sequences equal, naive value count exactly 2x |
| Automatic verification | the page's Verify button gave SPLUNK-VERIFIED, 34 of 34; the compare step verified both runs |
| Forged receipt rejection | **30 of 30** live checks (`deploy/adversarial.json`). From inside both containers, creating, deleting, renaming and overwriting receipts or the heartbeat all fail with `Read-only file system`; the kernel reports the mount `ro`; no key is reachable; a receipt copy with one flipped field audits `NOT AUTHENTIC` on the host; hostile requests (garbage JSON, wrong types, a symlink to `/etc/passwd`, a FIFO, a 5 MB file) were quarantined and the verifier kept serving a legitimate request |
| Verifier shutdown and recovery | a clean stop writes a `stopped` heartbeat and the page shows VERIFIER_OFFLINE; restart verifies again; after `kill -9` the stale pid is not mistaken for a verifier, the page goes offline once the heartbeat expires, restart replaces the pidfile and verification recovers; exactly one verifier process |
| Existing labs | all 21 specimen launches through the public API reached Splunk with exactly the pre-deployment event counts (PI 22/22/6, MCP 7/7/6, RAG 5/10/9, MEMORY 6/11/10, GOAL 10/10/10, DELEGATION 10/10/9, CAPSTONE 5/5/5); Attack UI pages and `/academy*` return 200; Splunk views untouched |
| **Rollback procedure** (executed, not only written) | `rollback` restored the exact pre-deploy images and the two original mounts (receipts mount gone), left observed services untouched and volumes identical; the rolled-back stack served the old mission page and the old Attack UI behaviour (`/` 500). Then rolled forward again and re-validated |

## Defects found in the deployment tooling during the drill (fixed)
1. After the first deployment the script read the compose file list from the *new* container's labels, which now included my override, so the first rollback kept the receipts mount. It now takes only the lab's own `docker-compose*.yml` files; the rollback was repeated and verified clean.
2. The adversarial script assumed a receipt existed before the first forgery attempt; it now creates one first.

## Unavoidable effects and residual risks
- **AcmeBank's run history is in process memory.** Recreating it (the deployment, and again for the rollback drill) discarded the local views of earlier runs; their events remain in Splunk. Learners with open mission pages would have seen "run unknown" and had to restart; none were active.
- The deployment created `receipts/`, `requests/`, `rejected/` and `legacy_v1/` inside the develop tree's **git-ignored** `artifacts/` (runtime state the lab already writes). `git status` there is unchanged (19 entries, `develop` at `b86accc`).
- Splunk, the collector and Ollama kept their container ids, image ids and start times.
- The verifier runs on the host and is not supervised; it does not survive a reboot (`lab-up.sh` or `loan_desk_verifier.sh start` restarts it).
- Anything with write access to the host's `artifacts/` can still forge a receipt; anything that can read `~/.local/state/agentsec/loan_desk/` can sign one. A receipt proves consistency between AcmeBank's events and Splunk's, not that the events are true.
- The new mount lines live in this branch's `docker-compose.yml`; the develop tree's compose file was not edited, so a plain `docker compose up` from the develop tree would recreate the containers without the read-only mount. AcmeBank then reports `NOT_VERIFIED` ("receipts directory is writable"), failing safe. Use the deploy script, or merge the two mount lines.
