# EC2 pre-cutover readiness (branch `feature/portable-network-binding`)

**Status: PREPARATION ONLY. No cutover. No container was created, restarted or removed by this work. No snapshot, volume expansion, model pull, security-group change or mode switch was performed.** Identifiers are redacted (`<instance>`, `<volume>`, `<sg>`); the operator has the real ones. Only read-only AWS and SSM queries were used, plus four small approved host changes listed in section 6.

## 0. Unexplained shutdown found during the audit (read this first)
At **15:57:03 to 15:57:35 UTC** on 2026-10-23 every AgentSec container on the instance was stopped (SIGTERM, then force after 10 s) and removed, in `compose down` order. **The EC2 lab is currently down** (0 containers; all 41 Docker volumes are intact). The host's own logs do not say who did it: no SSH login, no sudo command, no cron or timer, no SSM session, no instance stop or reboot. Every SSM command sent from this work is recorded in CloudTrail: six read-only commands, none containing a stop or remove. The initiator is **unknown**. Nothing was restarted by this work. Earlier in the day (15:12 UTC) someone had recreated the containers, and the host's shell history shows repeated `lab-up.sh --build --refresh-app --remote` runs, so another operator is evidently working on this host. Confirm who, and whether the shutdown was intended, before any cutover.


## Update after the investigation (supersedes sections 0, 3 and 7 where they conflict)
Full detail: `SHUTDOWN_INVESTIGATION.md`, `docs/ops/EC2_STORAGE_RUNBOOK.md`, `docs/ops/EC2_ACCEPTANCE_CHECKLIST.md`.
- **Section 0:** the shutdown is no longer unexplained. An interactive SSH session opened from the operator's Mac at 14:41:59 deleted the old deployment (14:46), cloned and checked out `v1.1.0` (15:11), created `.env` (15:11:45), started the lab (15:12:35) and, most likely, ran `compose down` at 15:57. Best-supported reading: a deliberate clean-room install test. Still unknown: whether the shutdown was intended and who typed the commands.
- **Section 3 was wrong about "reclaimable" volumes.** Splunk's data and config volumes are **anonymous**, and `lab-down.sh` followed by `lab-up.sh` orphans them (proven with a throwaway project). About 34 of the 36 "inactive" volumes are orphaned Splunk volumes, and **two of them hold AgentSec's own telemetry history through 2026-10-07**. Nothing is to be reclaimed until the owner decides what to keep; older July and August volumes (about 23 GB) predate this project's use of the host.
- **Section 7 was wrong that `lab-down.sh` keeps Splunk data usable.** The cutover must not use `down`; use `up -d --force-recreate <service>` (keeps anonymous volumes), and decide explicitly (gate G3) whether to attach the old history.
- **New finding:** the same pattern applies to the Mac pilot lab. Its end-of-day `lab-down.sh` advice has been corrected in the pilot docs.

## 1. Environment (not the same as the Mac)
EC2 runs `0178c70` (clean ancestor of the branch, 109 commits behind), HTTP HEC, container Ollama with `llama3.2:1b` only, no Loan Desk verifier or receipt mounts. Ubuntu 26.04, t3.2xlarge, 30 GB RAM, Docker 29.6.1 / Compose 5.3.1. Full comparison table: see the previous assessment summary in the review thread.

## 2. Disk (measured, read-only)
| Filesystem | Size | Used | Free | Use |
|---|---|---|---|---|
| `/` (ext4; holds the OS, `/var/lib/docker`, `/home`, the repo) | 96 GB | 91 GB | **5.2 GB** | 95% |
| `/tmp` | 16 GB | 0 | 16 GB | **tmpfs (RAM-backed, not disk)** |

`/var` 64 GB (Docker volumes 43 GB), `/home/ubuntu` 25 GB (`attack_data` 23 GB, the repository 512 MB). Docker: images 19.76 GB (3.46 reclaimable), volumes 45.12 GB in 41 volumes of which **5 were active** (41.65 GB reclaimable), build cache 1.46 GB (1.27 reclaimable). Journals 267 MB, apt cache 107 MB, snapd 457 MB.
Splunk's default minimum free space is 5000 MB (overrides not checked): at **5.2 GB the host is within 0.2 GB of the threshold**.

**Preflight defect fixed:** `lab-preflight.sh` ran `df` on the repository path only, so a run from RAM-backed `/tmp` printed "15.5 GB free: PASS". It now measures the repository filesystem **and** Docker's storage root (`docker info`), never counts a RAM-backed filesystem, and reports the tightest figure (`scripts/preflight_disk.py`, 6 regression tests). On the real host the new check reports **5.2 GB, WARN**, in both the original failure condition (root in `/tmp`) and the normal one.

## 3. Safe storage remediation
Nothing was deleted. Other projects' data is out of bounds.
- **Recommended: expand the EBS root volume 100 GB to 150 GB.** Online, no downtime, +$4.00 per month (50 GB x $0.08). IAM permits it (dry run succeeded); the last resize was in August, so there is no cooldown. Then `growpart` and `resize2fs` on the host. Take the snapshot first. Leaves about 55 GB free.
- AgentSec-owned and safe with approval: Docker build cache, about 1.27 GB (`docker builder prune`, cache only). Not enough on its own for the 15 GB gate.
- **Not ours, owner decision, not touched:** about 36 inactive Docker volumes (about 41.65 GB; 4 are labelled for the `agentwatchrange` and `orchestraacme` projects, about 32 are anonymous with unknown owner, dated 2026-07-09 to 2026-10-23), the unused `agentwatchrange-*`, `orchestraacme-*` and `splunk/splunk:9.2.1` images (about 4.9 GB), and `/home/ubuntu/attack_data` (23 GB). Anonymous volumes cannot be attributed from labels, so by your rule they stay.
- **Gate:** at least 15 GB free before any build, model pull or restart.

## 4. EBS snapshot plan (not taken)
| Item | Value |
|---|---|
| Volume | `<volume>`, root `/dev/sda1`, 100 GB gp3, 3000 IOPS, 125 MB/s, encrypted with the account's default EBS KMS key, AZ us-east-2c, **DeleteOnTermination = true** (so a snapshot is the only protection if the instance is terminated) |
| Permission | `ec2:CreateSnapshot` allowed (dry run succeeded) |
| Existing snapshots | 0 |
| First snapshot size | about 91 GB of used blocks (up to 100 GB if freed blocks were never trimmed) |
| Price (AWS Pricing API, us-east-2) | snapshot $0.05 per GB-month, archive tier $0.0125 per GB-month, gp3 $0.08 per GB-month |
| Estimated cost | **about $4.55 per month** (91 GB), at most $5.00; later snapshots store only changed blocks. Expansion adds $4.00 per month. Archive tier would be about $1.14 per month (90-day minimum). Creating a snapshot has no API charge. |
| Consistency | Crash-consistent at the instant of the call. **The lab is currently stopped, so right now Splunk's volumes are quiescent: this is the best moment for an application-consistent snapshot.** Run `sync` first. If the lab is running, stop it gracefully (`lab-down.sh`) for the same guarantee. |
| Downtime | None for the snapshot itself (I/O continues). Completion time for a first 91 GB snapshot is not measured; expect tens of minutes to a couple of hours. The snapshot is usable as a restore point only once `completed`. |
| Restore | Lazy-loaded from S3, so slow on first read. Replacing the root volume means stopping the instance: a last resort. |

## 5. Model
- **Tag:** `llama3.2:latest`. Splunk shows both verified Loan Desk runs (attack `5f47536e`, 48 inference events; retest `5acdaa6d`, 72) with `gen_ai.request.model` and `gen_ai.response.model` = `llama3.2:latest`. Code default is the same (`LOANDESK_MODEL` overrides it).
- **Digest:** `sha256:a80c4f17acd55265feec403c7aef86be0c25983ab279d83f3bcd3abbcb5b8b72`, 3.2B parameters, Q4_K_M, **2,019,393,189 bytes (1.88 GiB)**. The events record the tag but **not a digest**, so this digest is read from the Mac's Ollama (installed 8 months ago, unchanged), not from the runs themselves.
- **On EC2:** the container Ollama holds only `llama3.2:1b` (`baf6a787fdff`, 1.23 GiB). `latest` is absent. **Storage required: about 2.0 GB in the `ollama_models` volume**, so the disk gate applies. Not downloaded. After a pull, verify the digest equals the value above before any run.

## 6. Approved host changes made (the only writes)
`.env` mode 664 to **600** (size 1196 bytes and content hash unchanged, verified). Rollback image tags `agentseclab-acmebank` and `agentseclab-attack_service` `:pre-binding-<commit>` (metadata only). 0600 copies of `.env` and the repository HEAD pointer in a 0700 directory under the home. A scratch render of the rollback compose files, removed afterwards.

## 7. Downtime and rollback
- **Cutover window:** not measured on this host. Estimate 15 to 30 minutes: image builds, a model pull (about 2 GB), `lab-down.sh` then `lab-up.sh --remote`, Splunk start (its health check allows up to 10 minutes), first-time HEC certificate creation and verifier start. Today's shutdown means the lab is already down, so the incremental downtime is the start and validation only.
- **Rollback (prepared; the execution itself is NOT tested):** `lab-down.sh`; `git checkout 0178c70`; restore the `.env` copy if it changed; `lab-up.sh` (local) using the tagged images. Verified without starting anything: the tags exist, the `.env` copy is 0600, the HEAD pointer is recorded, and the `0178c70` compose files render with all ports on `127.0.0.1`. Docker volumes are never removed (`down` without `-v`). Restoring the EBS snapshot is the last resort. HEC returns to HTTP only through the old compose, so the Splunk app volume restaged by the new branch should be copied before cutover if exact restoration of dashboards matters (it is 3 MB).

## 8. Supplying the EC2 Splunk credential for validation, without display or storage
The credential lives only in the instance's `.env` (now 0600). Do not paste it into chat, a shell variable, a script argument or a report. Recommended: the **operator runs the Splunk-login step themselves in their own terminal** with a small script that reads it via `getpass` (no echo, memory only, never written, scrubbed from every log line), types it into the login form, and writes a report that contains only pass/fail booleans. Fetch it yourself outside the Claude session (a `!` command would put the output in the conversation). Fallback with no script: log in by hand from a different machine, and have me verify every unauthenticated check. Rotate the lab password afterwards if it was ever typed on a shared device. This script is not written yet; it needs your approval.

## 9. Port 5000 and exposure
Port 5000 stays configurable (`AGENTSEC_BIND_ADDRESS`; compose test covers it). Nothing is publicly exposed now: the lab is down, the security group is unchanged (no world-open rule; 8000, 5001 and 5000 each from one address), and the only reachable ports from outside are 22 and an unrelated Jupyter on 8888.

## 10. Remaining blockers
1. Confirm the 15:57 UTC shutdown was intended and who is operating the host.
2. Disk: approve the 150 GB expansion (or an owner-approved cleanup of at least 10 GB).
3. Approve the snapshot (best taken while the lab is stopped).
4. Approve the model pull (`llama3.2:latest`, about 2 GB) after the disk gate.
5. Push the remaining local commits (preflight fix and docs correction) so the instance can fetch the branch.
6. Agree the credential method and a maintenance window.
7. Untested on EC2: HEC TLS, Loan Desk verifier and the new binding. Not safe for the public internet; gateway requirements are in `docs/REMOTE_ACCESS.md` section F.
