# Troubleshooting

Learner-oriented symptoms also live in [AGENTSEC_TROUBLESHOOTING_FOR_LEARNERS.md](AGENTSEC_TROUBLESHOOTING_FOR_LEARNERS.md). This runbook is the operator + learner canonical list for v1.0.

Rule: an infrastructure failure is not a security conclusion. A Docker or host error is not evidence that an AgentSec control allowed or denied an action.

## Where to start

| What you see | Open this section |
|--------------|-------------------|
| `docker: command not found` | Docker command not found |
| `docker info` cannot connect | Docker daemon unavailable |
| `docker compose` is missing | Docker Compose unavailable |
| permission denied on the Docker socket | Docker socket permission |
| preflight `FAIL` on a port | Port already in use |
| Splunk stays unhealthy for several minutes | Splunk still starting |
| `MODEL ABSENT` | Model absent |
| AcmeBank JSON `"status": "degraded"` | AcmeBank degraded |
| `x509: certificate signed by unknown authority` | TLS inspection |
| `open /proc/self/mountinfo: permission denied` | Container runtime cannot start |
| Remote browser cannot open the server URL | Remote URL not reachable |
| Workshop table is empty after a launch | Empty investigation table |
| Your path forgot a workshop | Browser progress |

Before changing an AgentSec file, run:

```bash
docker run --rm hello-world
```

If that fails with the same `runc` or `mountinfo` error, the host runtime cannot start containers. The AgentSec Dockerfiles are not the first place to edit.

## If a lab does not start

| What you see | What it means |
|--------------|----------------|
| precheck `FAIL` on disk, Docker, or a port | The host is not ready. This is not a control DENY. |
| Splunk stays unhealthy | Splunk is still starting, or it failed. Read `docker compose logs splunk`. |
| `MODEL ABSENT` or AcmeBank `"status": "degraded"` | LIVE generation is degraded. REPLAY pages can still open. This is not a control DENY. |
| Attack Service `RUN DENIED` | The lab control denied that run. Read the control fields. |
| Attack Service `RUN TIMED OUT` or `BACKEND UNAVAILABLE` | The evidence check or the service failed. This is not a control DENY. |
| `RUN COMPLETED` | The runtime finished. It is not proof the attack succeeded. |

## Remote URL not reachable

**Symptom:** `lab-up.sh --remote` printed a server URL, and the browser on your laptop cannot open it.
**Cause:** the cloud security group or the host firewall is blocking the port, or the printed host is a placeholder. `SERVICE READY` does not measure that path.
**Check:** on the server, `ss -lnt` shows `0.0.0.0:8000` and `0.0.0.0:5001`, and `127.0.0.1:8088`. Confirm the security group allows TCP 8000 and TCP 5001 from your IP only.
**Remediation:** fix the firewall rule. Do not open 8000, 5001, 5000, 8088, or 11434 to `0.0.0.0/0`. Do not disable the host firewall. See [REMOTE_ACCESS.md](REMOTE_ACCESS.md).
**Do not conclude:** an authorization decision.

## Docker command not found

**Symptom:** the shell cannot find `docker`.
**Cause:** Docker Engine or Docker Desktop is not installed, or this shell is not the one that can see it. On an unvalidated Windows attempt, PowerShell is the wrong shell for `./scripts/lab-up.sh`.
**Check:** `docker --version` in the same shell you will use for the lab.
**Remediation:** install Docker using [AGENTSEC_PREREQUISITES.md](AGENTSEC_PREREQUISITES.md), start the engine, and retry.
**Do not conclude:** the Academy is defective.

## Docker daemon unavailable

**Symptom:** `lab-up` or `docker info` cannot connect.
**Cause:** Docker Desktop or `dockerd` is stopped.
**Check:** `docker info`.
**Remediation:** start Docker Desktop, or start the Docker service, then rerun `./scripts/lab-preflight.sh`.
**Do not conclude:** anything about ALLOW or DENY.

## Docker Compose unavailable

**Symptom:** preflight says `docker compose is not available`.
**Cause:** the Compose v2 plugin is missing. `docker-compose` with a hyphen is not what the scripts call.
**Check:** `docker compose version`.
**Remediation:** install the Compose v2 plugin from Docker's documentation, then retry preflight.
**Do not conclude:** a lab control failed.

## Docker socket permission

**Symptom:** permission denied talking to `/var/run/docker.sock`.
**Cause:** this user cannot access the Docker daemon.
**Check:** `docker info`.
**Remediation:** on Linux, add the user to the `docker` group and start a new login session, as described in the prerequisites. Do not run `chmod 777` on the socket.
**Do not conclude:** AgentSec refused the start.

## Container runtime cannot start

**Symptom:** a build or `docker run` fails immediately with `runc run failed`, `error preparing rootfs`, and `open /proc/self/mountinfo: permission denied`.
**Cause:** the host container runtime could not prepare a container. This is seen when the engine is broken, nested inside a sandbox, or blocked from reading mount information. It happens before `apt-get` or AgentSec code runs.
**Check:** `docker run --rm hello-world`.
**Remediation:** restart Docker Desktop or the Docker service and run the hello-world check again. If hello-world fails the same way, fix the host runtime. Do not edit `docker/Dockerfile.acmebank` as the first step, and do not disable a security control to force the container to start.
**Do not conclude:** the AcmeBank image recipe is the defect.

## TLS inspection

**Symptom:** `x509: certificate signed by unknown authority` while pulling `llama3.2:1b`, or a similar certificate error while pulling an image.
**Cause:** the client inside the image does not trust the certificate chain. On the qualification host, host `curl` reached the Ollama registry and the pull inside `ollama/ollama:latest` did not. A corporate proxy can cause the same class of error.
**Check:** `docker logs agentsec_ollama` and the `MODEL ABSENT` lines from `./scripts/lab-ready.sh`.
**Remediation:** ask the system or network administrator to install the inspection certificate in the engine and in the image trust store. Do not pass `--insecure` and do not disable certificate verification. Academy REPLAY does not need the model.
**Do not conclude:** LIVE generation passed, or that a control denied the pull.

## Model absent

**Symptom:** `lab-ready` prints `MODEL ABSENT`, and `lab-up` prints `DEGRADED`.
**Cause:** `ollama list` does not show `OLLAMA_MODEL` (default `llama3.2:1b`).
**Check:** `docker exec agentsec_ollama ollama list` and `curl -sS http://127.0.0.1:5000/health`.
**Remediation:** after trust is fixed, `docker exec agentsec_ollama ollama pull llama3.2:1b`. Until the name is listed, LIVE generation stays degraded. Open Academy Home for REPLAY work.
**Do not conclude:** `DEGRADED` is a pass, or that the Academy is down.

## AcmeBank degraded

**Symptom:** `http://127.0.0.1:5000/health` returns HTTP 200 with `"status": "degraded"` and `"ollama_reachable": false`.
**Cause:** the model name was not listed, or the tags request failed. The Ollama process can still be up. Docker can report the AcmeBank container healthy because `/health` is HTTP 200 in both cases.
**Check:** the JSON body, not only the container health line.
**Remediation:** use the model-absent steps. Attack Service `/health` can still be `"status": "healthy"`.
**Do not conclude:** AcmeBank crashed, or that a tool was denied.

## Disk space

**Symptom:** image pull or container create fails with a disk error. Preflight may only have printed free KiB.
**Cause:** images, Splunk's writable layer, and `ollama_models` need space. No minimum was benchmarked.
**Check:** the preflight `INFO` disk line and the Docker disk error.
**Remediation:** free disk on the Docker data volume, then retry `./scripts/lab-up.sh`.
**Do not conclude:** the lab blocked an attack.

## Container crash or health check failure

**Symptom:** `lab-ready` prints `NOT READY`, or a container is restarting.
**Cause:** the named container is stopped, still starting, or a one-shot init did not exit 0.
**Check:** `docker ps --filter name=agentsec_` and `docker logs` for the container named in the `NOT READY` line.
**Remediation:** read that log. Use `./scripts/lab-up.sh` again after the cause is fixed. A Splunk restart that drops HEC is handled by `./scripts/lab-up.sh --refresh-app`.
**Do not conclude:** an authorization decision.

## Port already in use

**Symptom:** bind errors or preflight FAIL on 5000/5001/8000/8088/4317/4318.  
**Cause:** another process, or a leftover container.  
**Check:** `./scripts/lab-preflight.sh`, `docker ps`.  
**Remediation:** stop the other listener, or `./scripts/lab-down.sh` if AgentSec leftovers exist.  
**Do not conclude:** the lab “blocked an attack.”

## Splunk Web unavailable

**Symptom:** :8000 not HTTP 200.  
**Cause:** still booting (10–20 min first time), crashed container, port conflict.  
**Check:** `docker inspect -f '{{.State.Health.Status}}' agentsec_splunk`.  
**Remediation:** wait; `./scripts/lab-up.sh`; logs for `splunk`.  
**Do not conclude:** experiments failed.

## Splunk login failure

**Symptom:** admin password rejected.  
**Cause:** `.env` `SPLUNK_PASSWORD` does not match the volume created on first boot.  
**Check:** you did not change password after first `lab-up` without recreating the Splunk volume.  
**Remediation:** use the password from the `.env` used at first boot, or FULL RESET (destructive) if you accept losing indexed data.  
**Do not conclude:** authorization succeeded.

## HEC unhealthy

**Symptom:** :8088 health not 200.  
**Cause:** Splunk not ready; `splunk_hec_init` not completed; HEC lost after Splunk restart without re-init.  
**Check:** `docker inspect agentsec_splunk_hec_init`; `./scripts/lab-ready.sh`.  
**Remediation:** `./scripts/lab-up.sh --refresh-app` (re-runs HEC init after restart).  
**Do not conclude:** a control DENY.

## Attack Service unavailable

**Symptom:** :5001 down.  
**Cause:** container stopped; image stale; AcmeBank unhealthy (depends_on).  
**Check:** `curl http://127.0.0.1:5001/health`.  
**Remediation:** `./scripts/lab-up.sh --build` if UI/source mismatch; else `lab-up`.  
**Do not conclude:** RETEST passed.

## AcmeBank unavailable

**Symptom:** :5000 health fail; launches error.  
**Cause:** Ollama still starting; crash.  
**Check:** `curl http://127.0.0.1:5000/health`; `docker logs agentsec_acmebank`.  
**Remediation:** wait for ollama healthy; restart acmebank.  
**Do not conclude:** DENY.

## Collector unhealthy

**Symptom:** no events in Splunk after a successful runtime.  
**Cause:** collector not running; HEC token mismatch.  
**Check:** `docker ps` `agentsec_otel_collector`; mesh HEC in `lab-ready`.  
**Remediation:** fix `.env` token to match HEC init; restart collector.  
**Do not conclude:** prevention.

## Events generated but not searchable

**Symptom:** Attack Service run.id exists; Search empty.  
**Cause:** indexing delay; wrong index/sourcetype; wrong id; HEC ok but pipeline lag.  
**Check:** wait; quoted run.id; `index=agentsec_telemetry sourcetype=otel:agentic:json`.  
**Remediation:** wait and retry; confirm WAITING_FOR_EVIDENCE vs READY.  
**Do not conclude:** blocked.

## WAITING_FOR_EVIDENCE

**Symptom:** launcher says waiting.  
**Cause:** honest default until export/searchability is known.  
**Check:** Search later; local artifacts if present.  
**Remediation:** wait; do not invent rows.  
**Do not conclude:** SAFE or DENY.

## Empty Studio table

**Symptom:** Path B / data-driven panel empty.  
**Cause:** REPLAY id not on this volume; token not your LIVE id; hunt zero-rows.  
**Check:** LIVE vs REPLAY; Search independently.  
**Remediation:** Path A with LIVE id; or another specimen.  
**Do not conclude:** DENY.

## LIVE run.id not found

**Symptom:** Search empty for a UUID you copied.  
**Cause:** typo; different Splunk; not indexed yet; copied specimen id.  
**Check:** Attack Service page for **this** launch.  
**Remediation:** recopy; wait; confirm index.  
**Do not conclude:** blocked.

## REPLAY run.id absent

**Symptom:** canonical UUID empty.  
**Cause:** this volume never ingested that specimen.  
**Check:** documented as expected on a fresh Splunk.  
**Remediation:** use LIVE labs for evidence; treat Path B as expected shape only.  
**Do not conclude:** the historical experiment was DENY.

## Schema mismatch

**Symptom:** fields missing.  
**Cause:** expecting a schema bump that did not happen. v1.0 schema is **1.9.0**.  
**Check:** `agentsec.schema.version`.  
**Remediation:** hunt with documented 1.9.0 fields.  
**Do not conclude:** product version equals schema.

## Stale container image

**Symptom:** Attack UI missing copy that exists in git (e.g. ATLAS qualifier).  
**Cause:** Python is baked into the image; no source bind for `src/`.  
**Check:** `./scripts/lab-up.sh --build`.  
**Remediation:** rebuild.  
**Do not conclude:** the repository lacks the fix.

## Studio XML not restaged

**Symptom:** dashboards show old copy.  
**Cause:** named volume copy is stale.  
**Check:** `./scripts/lab-up.sh --refresh-app`.  
**Remediation:** refresh-app. Browser hard reload if needed.

## HTTP 400 from launch

**Symptom:** launch JSON rejected.  
**Cause:** unknown_fields, unknown_lab, unknown_mode, malformed JSON.  
**Check:** only four fields; mode BASELINE|ATTACK|RETEST; execution live.  
**Remediation:** use the UI buttons; do not add profile/grants.  
**Do not conclude:** coded_policy DENY.

## unknown_fields

Authority-like keys are rejected as **ERROR**, not DENY.

## Profile / experiment mismatch

**Cause:** expecting browser-selected profile.  
**Remediation:** read ExperimentContext; ATTACK vs RETEST specimens.

## Ollama unavailable

**Symptom:** PI/LIVE model path fails; AcmeBank waits.  
**Cause:** model pull; ollama unhealthy.  
**Check:** `docker logs agentsec_ollama`.  
**Remediation:** wait through start_period; do not use host :11434 unless you changed compose.

## Browser cache

**Symptom:** old Attack UI.  
**Remediation:** hard reload; confirm rebuild.

## Empty investigation table

**Symptom:** the workshop table has no rows after you paste a run.id.  
**Cause:** the id is empty, indexing has not caught up, or that id is not in this index.  
**Check:** Attack Service evidence state. Then run the same SPL in Search.  
**Remediation:** wait, then paste the id again.  
**Do not conclude:** DENY, timeout, or backend failure. Those words appear on the launcher, not as an empty table. HEC HTTP 200 is not this table.

## Browser progress

**Symptom:** Your path shows NOT STARTED after a new browser or a reset.  
**Cause:** progress is `localStorage` on this Splunk origin. It is not an account.  
**Remediation:** mark the workshop again. Reset clears only that list. It does not delete indexed evidence.

## HTTP 400 workshop page

**Symptom:** Studio view fails to parse.  
**Cause:** bad XML restage.  
**Remediation:** `--refresh-app`; do not hand-edit volume files.
