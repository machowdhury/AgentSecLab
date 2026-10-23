# EC2 lab recreation (15:12 UTC) and shutdown (15:57 UTC): investigation

**Read-only investigation. Nothing on the host was stopped, started, killed, disabled or removed.** Evidence copies were saved to a 0700 directory on the host (section 6). Times are UTC, 2026-10-23. Identifiers and addresses are redacted. No one is assumed to have acted maliciously.

## 1. Evidence (observed, with source)
| Time | Fact | Source |
|---|---|---|
| 14:41:58 / 14:41:59 | An interactive `ssh` process starts on the operator's Mac; the host logs a public-key login as `ubuntu` at 14:41:59, from the same /24 as that Mac, using the **one** key in `authorized_keys`. A session with a pseudo-terminal (`pts/0`) is still open. | Mac process list; host `sshd-session` journal; `loginctl`; key fingerprint match |
| 14:46:00 | `sudo rm -rf AgentSecLab/` as `ubuntu` from `/dev/pts/0` (interactive terminal). The previous deployment directory, with its `.env` and `artifacts/`, is deleted. | host sudo journal |
| 15:11:10 / 15:11:31 | Fresh `git clone` of the repository, then `checkout v1.1.0` (commit `0178c70`). | repo reflog |
| 15:11:45 | A new `.env` is created. | file mtime |
| 15:12:35 | All AgentSec containers are created (project `agentseclab`). | container metadata (earlier inspection) |
| 15:57:03 to 15:57:35 | Containers killed and destroyed in dependency order; the network is removed last (15:57:36). Compose v5.3.1 labels. **No volume-destroy events.** | `docker events`, `dockerd` journal |
| all day | Hourly `total_replay` loop (an unrelated project, running about 64 days) keeps succeeding (exit 0 at 14:47 and 15:48). It has no reference to docker, compose or AgentSec. | its log and script |
| 11:44 to 12:15 local | The only AWS Run Command (`SendCommand`) caller is the same IAM user as this review work: every command is one of the read-only commands sent for this investigation. | CloudTrail |

Also checked and **negative**: no SSM interactive sessions, no EC2 Instance Connect, no instance stop or reboot, no cron or timer touching Docker, no Docker automation (watchtower, autoheal), no `claude` or `codex` binary or directory on the host, no other SSH key, no other agent session on the operator's Mac that mentions the host, no Mac launchd or cron job for it. Compose files set `restart: unless-stopped`, which restarts a crashed container but does not remove one.

## 2. Hypotheses (consistent with the evidence, not proven)
- **H1 (best supported): the operator who opened the SSH session from the Mac ran a clean-room install of the `v1.1.0` release and tore it down.** The sequence (delete the old directory, clone, check out the tag, create `.env`, `lab-up`, later `compose down`) matches a deliberate clean install test. The `down` at 15:57 was an ordinary `compose down` without `-v`.
- **H2:** the same terminal was driven by a script or tool rather than typed. The evidence does not distinguish this from H1.

## 3. Unknowns
- Whether the shutdown was intended, and whether the person was aware another review was reading the host at the same time.
- Who or what typed the commands. The shell history file is not written until an interactive shell exits (it was last written on 2026-10-10), so the commands will only appear after that session ends. **Preserve `~/.bash_history` once it does.**
- The 15:12 creation events themselves: Docker's event history no longer holds them; only the reflog, file times and container metadata remain.
- What the hourly replay sends data to.
- Whether any data was lost with the deleted directory (section 5).

## 4. Controllers that could act on this host
| Candidate | Finding |
|---|---|
| Interactive SSH session from the operator's Mac | **Active now; the actor for 14:46, 15:11 and (most likely) 15:57.** Not interrupted. |
| This review work (SSM Run Command) | Read-only; every command accounted for in CloudTrail. |
| Another Claude or Codex session | None found on the host; none on the Mac that mentions it. |
| systemd, cron, timers, `at` | Stock only (plus Jupyter and the SSM agent). Nothing touches the lab. |
| Docker automation | None. `restart: unless-stopped` only. |
| Jupyter (`0.0.0.0:8888`, reachable from two allowed addresses) | No kernel or terminal activity logged near 15:57. It is, however, a code-execution surface owned by someone else. |
| Hourly replay loop | Unrelated; no docker or compose use. |
| AWS State Manager (`DrRobot-InstallAgents`, daily) | Failing association, unrelated. |

## 5. Important consequence discovered during the investigation: Splunk data does not survive `lab-down.sh` then `lab-up.sh`
Splunk's `/opt/splunk/etc` and `/opt/splunk/var` are **anonymous Docker volumes** (declared by the image, not in the compose file). Tested with a throwaway project: recreating a container in place keeps its anonymous volume, but **`down` then `up` creates a new empty volume and orphans the old one**. That is exactly what `lab-down.sh` followed by `lab-up.sh` does. The "indexed Splunk data remains" message is true only in the sense that the old volume still exists on disk. Splunk starts empty.
On this host that explains 34 anonymous volumes (about 17 lab-down/lab-up cycles) and the 5.2 GB free. It is also why Batch 9 had to recover September data from orphaned volumes on the Mac.
- **AgentSec's own history on the host is in orphaned volumes** created 2026-10-02: one pair holds `agentsec_telemetry` through **2026-10-07** (19 warm buckets and 1 hot) and another pair has 4 buckets from 2026-10-02. They are not reclaimable clutter.
- Several other AgentSec-era volumes hold an `agentsec_telemetry` index directory of about 1 MB with no buckets (fresh installs). The 15:12 to 15:57 run's volumes are among them.
- Older July and August volumes (about 23 GB: roughly 16 GB of Splunk data and 6 GB of config, no `agentsec_telemetry` index) predate this project's use of the host and belong to other work.
- The `rm -rf` at 14:46 deleted the previous deployment's `.env`, so **the previous Splunk admin password is gone**; the old etc volumes still contain its hash.

## 6. Preserved evidence
On the host, under a 0700 directory in the `ubuntu` home: Docker event stream (14:30 to 16:10), `dockerd` and `containerd` journals, `systemd-logind`, `sshd`, Jupyter journal and an SSM-agent log excerpt, all 0600. Journals rotate, so copy these off the host if the matter needs to be revisited.

## 7. Deployment owner (decision needed before any infrastructure change)
Single points of control today: one SSH key, one IAM user, one host. Recommendation: the owner is **the person who holds that SSH key and IAM user**, named in writing, and changes are announced before they are made. Mechanism: a lock file (`/home/ubuntu/.agentsec-deploy-lock` containing owner, purpose, start time) taken by `lab-up`, `lab-down` and any review work, checked before any change. Not created, because it is a host change you have not approved. Until an owner is named and the open SSH session's operator confirms they are not mid-test, no cutover should start.
