# EC2 acceptance checklist (before and after the cutover)

**Status: NOT RUN.** Every box is empty. A gate is passed only with evidence written next to it (command output summary, not credentials). Any failed gate is a **stop**: report it and do not continue. Nothing here authorizes a cutover; the deployment owner does that in writing. Identifiers are placeholders.
Run commands on the instance unless it says **separate machine**, which means a computer on a different network from the instance (the operator's laptop is fine; the instance itself is not).

## Gate 0: control
| # | Requirement | Evidence | Done |
|---|---|---|---|
| G0.1 | **One named deployment owner**, recorded here: ______. Nobody else changes the host during the cutover. | name, date | [ ] |
| G0.2 | No concurrent session doing lab work: `loginctl list-sessions`, `who`, `docker ps -a`, and the owner confirms the open SSH session is theirs or closed. | output | [ ] |
| G0.3 | Deploy lock taken (a lock file with owner, purpose and time), released at the end. | file | [ ] |
| G0.4 | Evidence from the 2026-10-23 shutdown preserved and `~/.bash_history` saved after the open session ended (`docs/reviews/ec2/SHUTDOWN_INVESTIGATION.md`). | file list | [ ] |
| G0.5 | Written approval for each of: snapshot, expansion, model pull, push/fetch of the branch, mode switch, maintenance window. | message ids | [ ] |

## Gate 1: storage (at least 15 GB genuinely free)
| # | Requirement | How | Done |
|---|---|---|---|
| G1.1 | At least **15 GB free on the deployment filesystem and on Docker's storage root**, measured on real disk, never `/tmp` (RAM-backed). | `python3 scripts/preflight_disk.py --root <repo> --docker-root "$(docker info --format '{{.DockerRootDir}}')"` must print `PASS`, **and** `df -h / /var/lib/docker` | [ ] |
| G1.2 | Method used to reach it is recorded: EBS expansion (`docs/ops/EC2_STORAGE_RUNBOOK.md`, Part 2) or an owner-approved cleanup. Nothing belonging to other projects was deleted. | runbook log | [ ] |
| G1.3 | Splunk's free-space threshold respected: free space stays above 5000 MB with margin after the model pull and image builds. | `df` after each step | [ ] |

## Gate 2: snapshot and recovery
| # | Requirement | How | Done |
|---|---|---|---|
| G2.1 | Snapshot of the root volume **completed** (not merely started), encrypted, tagged with owner and `DeleteAfter`. | `describe-snapshots` state `completed` | [ ] |
| G2.2 | Taken while the lab is stopped (not removed) so Splunk is quiescent. | runbook step | [ ] |
| G2.3 | **Recovery procedure documented and rehearsed**: a temporary volume created from the snapshot, mounted read-only, key files verified, then deleted. | rehearsal notes | [ ] |
| G2.4 | Rollback assets present: image tags `:pre-binding-<commit>` for acmebank and attack_service, a 0600 copy of `.env`, the pre-cutover repo HEAD recorded, and the rollback compose files render with loopback ports. | `docker image ls`, `stat`, `docker compose config` | [ ] |
| G2.5 | Limits acknowledged: full restore reverts other people's data too; the public address changes if the instance is stopped (no Elastic IP). | owner initials | [ ] |

## Gate 3: Splunk data continuity (decision, before any `up`)
| # | Requirement | How | Done |
|---|---|---|---|
| G3.1 | **Decision recorded** on the 17 orphaned Splunk volume pairs. Recommended (`docs/ops/SPLUNK_VOLUME_MIGRATION.md` section 4): **start clean on named volumes**, leave every old pair untouched, and archive AgentSec's 764 events (618 + 146, 2026-09-12 to 2026-10-08) as JSONL later. The old `etc` volumes have HEC on plain HTTP and an unknown admin password, so they must not be attached to the HTTPS deployment. No two datasets are combined. | decision text | [ ] |
| G3.2 | The cutover never uses `down` on a lab whose Splunk data must be kept, and never runs `docker volume prune`. The deployed compose uses **named** `splunk_etc`/`splunk_var`; `lab-up.sh` finds no Splunk container to protect. Verified with `docker volume inspect`. | procedure text | [ ] |
| G3.3 | The previous Splunk admin password was lost with the 14:46 `rm -rf`. If old data is attached, a documented admin reset is part of the plan. | plan | [ ] |

## Gate 4: the exact model
| # | Requirement | How | Done |
|---|---|---|---|
| G4.1 | Model tag is exactly **`llama3.2:latest`** (the tag Splunk records for both verified Loan Desk runs). | `docker exec agentsec_ollama ollama list` | [ ] |
| G4.2 | Digest equals `sha256:a80c4f17acd55265feec403c7aef86be0c25983ab279d83f3bcd3abbcb5b8b72` (3.2B, Q4_K_M, 2,019,393,189 bytes). Verified after the pull, before any run. The runs themselves recorded only the tag. | `curl -s http://127.0.0.1:11434/api/tags` from inside the Ollama container, compare `digest` | [ ] |
| G4.3 | Pulled by the owner after G1; **never with certificate verification disabled**. A TLS error is fixed at the trust layer or the cutover stops. | pull log | [ ] |
| G4.4 | `LOANDESK_MODEL` is unset (or equals the tag above) in the running AcmeBank container. | `docker exec ... printenv LOANDESK_MODEL` | [ ] |

## Gate 5: Splunk indexing verified, not merely HEC health
HEC health (`/services/collector/health`) and `splunk_hec_init` finishing prove only that the endpoint answers.
| # | Requirement | How | Done |
|---|---|---|---|
| G5.1 | A **canary event** sent through HEC (over the Docker network, token read from `.env` and never printed) with a unique marker is **found by a search** within 60 seconds, exactly once. | HEC send, then a Splunk `search index=agentsec_telemetry "<marker>" \| stats count` run inside the Splunk container; `count=1` | [ ] |
| G5.2 | The recorded REPLAY specimens are searchable (all 15 labs). | `python3 scripts/learner_ready.py` | [ ] |
| G5.3 | After a real attack run, the number of events Splunk holds for that run id equals the number the page reports, and no duplicates. | `search ... "agentsec.run.id"="<id>" \| stats count, dc(_raw)` | [ ] |
| G5.4 | `KV_MODE` unchanged in the deployed app (`props.conf` compared with the repository). | `diff` | [ ] |
| G5.5 | Indexing survives a Splunk restart *in place* (the HEC input is re-initialised by `splunk_hec_init`). | canary again after restart | [ ] |

## Gate 6: Loan Desk verifier and receipt lifecycle (never validated on EC2 before)
| # | Requirement | How | Done |
|---|---|---|---|
| G6.1 | Host verifier running with a fresh heartbeat; its signing key lives under the owner's 0700 state directory, outside the repository and not reachable from any container. | `./scripts/loan_desk_verifier.sh status`, `learner_ready.py` | [ ] |
| G6.2 | The receipts directory is mounted **read-only** in both AcmeBank and the Attack Service. | `docker inspect` Mounts show `RW=false` | [ ] |
| G6.3 | A full attack-then-retest run produces receipts written only by the host verifier, and the page shows **SPLUNK-VERIFIED** for both runs after the verifier searched Splunk. | page + receipt files | [ ] |
| G6.4 | A tampered or forged receipt is rejected and quarantined (**do not recursively grep the quarantine folder: it can contain FIFOs that hang `grep`**). | verifier log | [ ] |
| G6.5 | Verifier lifecycle: stop and start, kill and recover, and behaviour after a host reboot are understood (it is **not supervised**: it does not survive a reboot). | `docs/ops/VERIFIER_SUPERVISION.md` | [ ] |
| G6.6 | Mission page loads the Splunk Web view and the attack, defend and retest flow completes with the intended model. | browser | [ ] |

## Gate 7: remote browser access from a separate machine
| # | Requirement | How | Done |
|---|---|---|---|
| G7.1 | From the **separate machine**: Academy (8000), Attack Service (5001) and AcmeBank (5000) load by public IP or DNS; links keep that hostname (no jump to `127.0.0.1` or `localhost`). | browser | [ ] |
| G7.2 | Splunk login works. The credential is **entered by the owner** through a no-echo prompt on the separate machine or typed by hand. It is never in chat, a shell variable, a script argument, a log or a report. | pass/fail only | [ ] |
| G7.3 | Dashboard navigation (Academy home, a lab view, the Loan Desk view) and the attack, defend, retest and evidence verification work end to end. | browser | [ ] |
| G7.4 | Only the allowed learner address can connect (a connection from another network fails). | second network or the security-group check | [ ] |

## Gate 8: no unauthorized public exposure
| # | Requirement | How | Done |
|---|---|---|---|
| G8.1 | On the host exactly 8000, 5001 and 5000 listen on `0.0.0.0`; 8088, 4317 and 4318 on `127.0.0.1`; **nothing** on 8089, 11434 or 2375/2376. | `python3 scripts/agentsec_access.py classify --mode remote` and `ss -lnt` | [ ] |
| G8.2 | From the **separate machine**: 8088, 8089, 4317, 4318, 11434 and 2375 refuse the connection. | `nc -z -w4 <host> <port>` for each | [ ] |
| G8.3 | Security group unchanged except by the owner's written decision: no world-open rule (`0.0.0.0/0`, `::/0`) on any port; 8000, 5001 and 5000 from the learner address only. | `describe-security-groups` | [ ] |
| G8.4 | The unrelated Jupyter service on 8888 is reported to its owner; it is out of scope but internet-reachable. | note | [ ] |
| G8.5 | `.env` is mode 0600; no credential appears in any report or commit. | `stat`, diff scan | [ ] |

## Gate 9: not for customers yet
This deployment is **not** approved for unrestricted internet access. Before any customer use it needs, at minimum: an authenticating HTTPS gateway in front of every learner port (for example an ALB with an ACM certificate and OIDC), the instance reachable only from that gateway, one isolated stack per learner, CSRF and origin checks, per-learner sessions, rotated credentials, and a re-run of this checklist. See `docs/REMOTE_ACCESS.md` section F.

## Sign-off
Owner: ______ date: ______ result: PASS / STOP at gate ____. Reviewer: ______ date: ______.
