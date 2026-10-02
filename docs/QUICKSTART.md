# AgentSec Quickstart

A technically capable person should be able to follow this linearly. Run every command from the **repository root**.

Use `main` or annotated tag `v1.1.0`. That tree is the L0–L10 academy. Tag `v1.0.0` is the previous release. Tag `v1.0.0-rc1` peels to the earlier baseline and stops before L6. Tags `v1.0.0-rc2` and `v1.0.0-rc3` stay on their original commits. These steps are the documented path. The v1.0.0 release notes record the 2026-10-02 clean-room: service start was proven, and LIVE generation was degraded because the model was not listed. That measurement was not repeated as a new benchmark for v1.1.0.

After the first lab, continue with the README academy section and [AGENTSEC_RELEASE_LAB_MATRIX.md](AGENTSEC_RELEASE_LAB_MATRIX.md). Do not treat the L5 Capstone as the end of the academy. L10 is the Advanced Capstone. Mastery Check is a separate unscored self-check. Arena is optional after that. It is not the start.

On a LIVE workshop, launch from Attack Service, copy the run.id, and paste it into **LIVE run.id**. The table on that page is a Splunk search. Rows are indexed evidence only when Splunk returns them. Search remains available when you want to edit the SPL. REPLAY workshops do not need Ollama. Ollama is the local LLM runtime AgentSec uses for LIVE labs. It is not part of Splunk.

## 1. Prerequisites

- Git
- Docker Engine and Docker Compose v2
- `python3` and `curl` on the host
- A browser
- This repository

Hardware minimums: **NOT BENCHMARKED**. The measured clean-room host was Docker Desktop on Apple Silicon with Splunk 10.2 (`linux/amd64`, emulated). Podman is not validated. Windows is not validated.

Details: [AGENTSEC_PREREQUISITES.md](AGENTSEC_PREREQUISITES.md).

## 2. Configure

```bash
cp .env.example .env
```

Do not commit `.env`. The example file contains **lab defaults** for localhost, not production secrets. Rotate them if you bind anything beyond `127.0.0.1`.

## 3. What does the AgentSec preflight check?

```bash
./scripts/precheck.sh
```

`./scripts/precheck.sh` is the learner name for `./scripts/lab-preflight.sh`. Both run the same checks, including free disk. Neither deletes Docker data.

`scripts/lab-preflight.sh` installs nothing and does not start the lab. It prints `PASS`, `WARN`, `FAIL`, or `INFO`. The result line is `RESULT PASS`, `RESULT WARN`, or `RESULT FAIL`.

| Check | What it means |
|-------|----------------|
| `docker` on `PATH` | The Docker CLI exists. |
| `docker info` | The Docker daemon answers. A failure here is an environment failure. |
| `docker compose version` | Compose v2 is installed. |
| `git` on `PATH` | Missing git is `WARN`, not `FAIL`. |
| `docker-compose.yml` and `docker-compose.local.yml` | You are in a checkout that contains the lab. |
| `.env.example` and `.env` | The example exists, and you already copied it to `.env`. |
| `splunk_app/agentsec` and `src/agentsec/templates/attack.html` | Application source is present. |
| Ports 5000, 5001, 8000, 8088, 4317, 4318 | A non-AgentSec listener is `FAIL`. An existing AgentSec container on that port is `WARN`. If `lsof` is absent, a free-port `PASS` only means `lsof` was not there to contradict it. |
| Free disk | An `INFO` line in KiB. No minimum is claimed. |
| Ollama model | Only when `agentsec_ollama` is already running. A listed model is `PASS`. A missing model is `WARN`. |

Preflight does not check Splunk health, HEC, Academy views, or AcmeBank. It does not read whether `SPLUNK_PASSWORD` is acceptable to Splunk. `RESULT PASS` does not prove the next start will become healthy.

`RESULT FAIL` exits 1. Fix the `FAIL` lines before `lab-up.sh`. `RESULT WARN` exits 0. You may start, and you should read the warnings. A Docker `FAIL` means the host runtime is not ready. It is not evidence that a security lab behaved incorrectly.

## 4. What does ./scripts/lab-up.sh actually do?

```bash
./scripts/lab-up.sh
```

The script does not run preflight. It requires `.env`, then runs Docker Compose with `docker-compose.yml`, `docker-compose.local.yml`, and profile `local`.

In order:

1. Exit if `.env` is missing.
2. With `--build`, run `docker compose build` before start. Without `--build`, Compose still builds AcmeBank and Attack Service when those images are absent, and it pulls images that are not local.
3. With `--refresh-app`, copy `splunk_app/agentsec` into volume `splunk_app_agentsec`, restart Splunk, and run HEC init again. Without that flag, `splunk_app_init` still copies the app once as part of a normal start.
4. Run `docker compose up -d`. Compose creates the named volumes if they are missing and leaves existing volumes in place.
5. Unless you passed `--no-wait`, call `scripts/lab-ready.sh` up to 80 times, sleeping 15 seconds between tries.
6. On success, print that the service health check exited 0. If `lab-ready` printed `MODEL ABSENT`, the same output says LIVE generation is `DEGRADED` and that is not a pass.

Flags that exist:

| Flag | Effect |
|------|--------|
| `--build` | Rebuild AcmeBank and Attack Service from this repository, then start. |
| `--refresh-app` | Restage the Splunk app and re-run HEC init after a Splunk restart. |
| `--no-wait` | Start containers and return without `lab-ready.sh`. |
| `--remote` | Publish learner ports 8000 and 5001 on `0.0.0.0`. Leave HEC, OTel, AcmeBank, and Ollama private. |
| `-h`, `--help` | Print the script usage and exit. |

Without `--remote`, `lab-up.sh` forces `AGENTSEC_BIND_ADDRESS=127.0.0.1` for ports 8000 and 5001. The script prints four steps: prerequisites, the bind plan, container start, and readiness. It prints elapsed time at the end. That elapsed time is this run, not a promise about the next machine.

Remote install, firewall rules, and the public URL: [REMOTE_ACCESS.md](REMOTE_ACCESS.md).

`lab-up.sh` does not itself run `ollama pull`. Starting the stack starts container `agentsec_ollama`. That container's entrypoint, `scripts/ollama_init.sh`, tries `ollama pull` for `OLLAMA_MODEL` (default `llama3.2:1b`). If the pull fails, the entrypoint continues, and the container can still become healthy. `lab-up.sh` does not load a historical Splunk index or a sample `run.id`. It does not delete volumes.

Help text in the script says the first Splunk boot can take 10–20 minutes and that later starts are usually faster. That sentence is the script's planning note, not a measured duration.

## 5. How long will installation take?

Two clean-room clocks are recorded. They are not a guarantee, and they are not a measurement of a cold image download.

| Record | What was measured |
|--------|-------------------|
| v1.0 qualification, 2026-10-02, fresh volumes | Containers running at 22 seconds. Splunk healthy at 3 minutes 20 seconds. Compose exit 0 at 4 minutes 38 seconds. `lab-ready` service ready and the Home sentence at 6 minutes 7 seconds. |
| RC3 clean-room, 2026-10-01, fresh directory and new volumes, Darwin arm64, Docker 29.7.2 | Containers running at 5 seconds. Splunk healthy at 3 minutes 8 seconds. Compose exit 0 at 4 minutes 26 seconds. Home sentence read at 11 minutes 47 seconds. |

Both runs were on a Mac that already had Docker. The notes do not say the image cache was empty. Time to download Splunk, Ollama, and the other images is **UNKNOWN**. Time to download `llama3.2:1b` is **UNKNOWN** on a path where the pull succeeds. The qualification pull failed before a model download completed.

Use the categories this way:

| Situation | What to plan |
|-----------|----------------|
| Lab already started once on this machine | The script says later starts are usually faster. No separate warm-start clock was published. |
| First start, images already local | The measured service-ready clocks above were about 6 to 12 minutes, then the script still allows up to 80 readiness tries. |
| First start, images must download | Add the unmeasured download. The script still says to allow 10–20 minutes for the first Splunk boot after the stack is starting. |
| Model pull and corporate TLS inspection | The model pull can fail. That failure does not have a success duration in these notes. |

A corporate proxy or a TLS inspection appliance can add delay or fail the pull. Ask the network administrator to put the inspection certificate in the Docker engine and in the image trust store. Do not disable certificate verification.

## 6. Readiness words

`./scripts/lab-up.sh` already runs `./scripts/lab-ready.sh`. You can run `lab-ready.sh` again later.

| Word | Where it appears | Meaning |
|------|------------------|---------|
| `RESULT PASS` / `RESULT WARN` / `RESULT FAIL` | Preflight | Host checks. `FAIL` exits 1. `WARN` still exits 0. |
| `NOT READY` | `lab-ready.sh` | A required container, Splunk health check, view, or HTTP check failed. The script exits 1. |
| `SERVICE READY` | `lab-ready.sh` | Containers, Splunk Web, HEC health, Academy view files, AcmeBank HTTP, and Attack Service HTTP answered. Exit 0. |
| `MODEL PRESENT` | `lab-ready.sh` | `ollama list` shows the configured model name. A name is not a measured digest. |
| `MODEL ABSENT` | `lab-ready.sh` | The model is not listed. The script still exits 0. |
| `DEGRADED` | `lab-up.sh` and AcmeBank `/health` | LIVE generation is not a pass. `lab-up.sh` prints `DEGRADED` when `lab-ready` printed `MODEL ABSENT`. |
| `healthy` | Attack Service `/health`, or AcmeBank `/health` when the model name is listed | Attack Service uses this for its own HTTP check. AcmeBank uses `healthy` only when `ollama_reachable` is true. |
| `degraded` | AcmeBank `/health` JSON | The model name was not listed, or the tags request failed. HTTP status is still 200, so Docker can show the AcmeBank container healthy while this JSON says `degraded`. |
| `ollama_reachable` | AcmeBank `/health` | True only when `/api/tags` lists a name containing the model prefix. False does not mean the Ollama process is stopped. |

`SERVICE READY` does not mean a `run.id` is searchable. HEC HTTP 200 is not indexed evidence. A healthy service is not a successful attack. A listed model name is not a measured digest. Academy views being loaded is not an accessibility certification. `DEGRADED` is not a pass. Academy REPLAY pages can still be opened when the model is absent. LIVE generation that needs the model stays degraded until `docker exec agentsec_ollama ollama list` shows it.

Precheck `WARN` means you may continue and should read the warning. Precheck `FAIL` means the host is not ready to start. Neither word is a control DENY. The 8 GB disk line is a planning floor, not a benchmarked minimum. `lab-up.sh` leaves existing named volumes in place. It does not delete indexed evidence.

Observed clocks above vary with network speed, image cache, CPU, memory, disk, Splunk initialization, and whether the model is already present. They are not a promised install time.

Confirm the model:

```bash
docker exec agentsec_ollama ollama list
curl -sS http://127.0.0.1:5000/health
```

The pull command the entrypoint and `lab-ready.sh` name is:

```bash
docker exec agentsec_ollama ollama pull llama3.2:1b
```

On the qualification host, host `curl` to `https://registry.ollama.ai/v2/library/llama3.2/manifests/1b` returned HTTP 200, and the same pull inside `ollama/ollama:latest` failed with `x509: certificate signed by unknown authority`. That is an external trust failure of the image's client. Fix trust at the host or image trust layer. Do not disable certificate verification.

## 7. Setup security

Do not commit `.env`. Do not paste a production password, token, or cloud key into it. The example values are lab defaults for localhost. Leave the published ports on `127.0.0.1`. Do not add an unrelated MCP server while installing. REPLAY workshops do not need a GitHub credential, a cloud credential, or a production identity provider.

## 8. URLs

| URL | Role |
|-----|------|
| http://127.0.0.1:8000/en-US/app/agentsec/ws_agentsec_home | Academy Home |
| http://127.0.0.1:8000 | Splunk login (user `admin`; password from `.env` `SPLUNK_PASSWORD`) |
| http://127.0.0.1:5001 | Attack Service |
| http://127.0.0.1:5000/health | AcmeBank |

## 9. First Academy lab

Open Home → **Direct Prompt Injection**. Read LEARN. Predict before you launch.

## 10. First LIVE launch

On Attack Service, select Direct Prompt Injection, mode **ATTACK**, execution **live**. Launch. Wait until the launcher reports evidence status (WAITING_FOR_EVIDENCE can be honest; Search later).

## 11. Copy `run.id`

Copy the UUID the Attack Service shows for **this** launch. Do not use an Investigate-specimen UUID as if it were this launch.

## 12. Starter Splunk Search

Open Search. Constrain:

```
index=agentsec_telemetry sourcetype=otel:agentic:json
"agentsec.run.id"="<paste-run-id>"
```

Use quotes around the run.id. Empty is not DENY. If empty, wait, check the id, or see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

## 13. Shutdown

```bash
./scripts/lab-down.sh
```

`./scripts/lab-down.sh` stops containers and says indexed Splunk data and named volumes remain. Next start: `./scripts/lab-up.sh`. The command that deletes those volumes is in [OPERATIONS.md](OPERATIONS.md). Read the warning there before using it.

## 14. What to do next

Return to Academy Home and follow L1 through L10. The L5 menu label **Capstone** is Lending Assistant Investigation, the last LIVE launcher. Complete **Splunk Defender Bridge** before L6. **Advanced Capstone** is L10. **Mastery Check** is optional and unscored.

Specimen ids printed on a dashboard are reference evidence. Investigate the `run.id` from the launch you just made.

## 15. More help

[TROUBLESHOOTING.md](TROUBLESHOOTING.md) · [OPERATIONS.md](OPERATIONS.md) · [LIVE_VS_REPLAY.md](LIVE_VS_REPLAY.md) · [AGENTSEC_RELEASE_LAB_MATRIX.md](AGENTSEC_RELEASE_LAB_MATRIX.md) · [INSTRUCTOR_GUIDE.md](INSTRUCTOR_GUIDE.md)
