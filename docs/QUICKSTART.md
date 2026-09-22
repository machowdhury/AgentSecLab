# AgentSec Quickstart

A technically capable person should be able to follow this linearly. Run every command from the **repository root**.

## 1. Prerequisites

- Git
- Docker Engine + Docker Compose v2
- A browser
- This repository

Hardware minimums: **NOT BENCHMARKED**. Observed development used Docker Desktop on macOS with Splunk 10.2 (`linux/amd64`, emulated on Apple Silicon). First boot pulls images and an Ollama model.

Details: [AGENTSEC_PREREQUISITES.md](AGENTSEC_PREREQUISITES.md).

## 2. Configure

```bash
cp .env.example .env
```

Do not commit `.env`. The example file contains **lab defaults** for localhost, not production secrets. Rotate them if you bind anything beyond `127.0.0.1`.

## 3. Preflight

```bash
./scripts/lab-preflight.sh
```

Expect PASS (or WARN if the lab is already running). FAIL means fix the printed reason. The script does not install software.

## 4. Start

```bash
./scripts/lab-up.sh
```

What it starts: AcmeBank, Attack Service, Ollama, OpenTelemetry collector, Splunk (local profile), Splunk app init, HEC init.

First Splunk initialization can take **10–20 minutes**. Output from compose/health retries can be noisy; the stop condition is `lab-ready` printing READY.

Rebuild images from this repository (required after Attack Service UI/source changes):

```bash
./scripts/lab-up.sh --build
```

## 5. Readiness

```bash
./scripts/lab-ready.sh
```

READY means **SERVICE HEALTH**: Splunk Web, HEC health endpoint, published Academy views, AcmeBank, Attack Service.

READY does **not** mean a given `run.id` is searchable. HEC HTTP 200 is not indexed evidence.

## 6. URLs

| URL | Role |
|-----|------|
| http://127.0.0.1:8000/en-US/app/agentsec/ws_agentsec_home | Academy Home |
| http://127.0.0.1:8000 | Splunk login (user `admin`; password from `.env` `SPLUNK_PASSWORD`) |
| http://127.0.0.1:5001 | Attack Service |
| http://127.0.0.1:5000/health | AcmeBank |

## 7. First Academy lab

Open Home → **Direct Prompt Injection**. Read LEARN. Predict before you launch.

## 8. First LIVE launch

On Attack Service, select Direct Prompt Injection, mode **ATTACK**, execution **live**. Launch. Wait until the launcher reports evidence status (WAITING_FOR_EVIDENCE can be honest; Search later).

## 9. Copy `run.id`

Copy the UUID the Attack Service shows for **this** launch. Do not use an Investigate-specimen UUID as if it were this launch.

## 10. Starter Splunk Search

Open Search. Constrain:

```
index=agentsec_telemetry sourcetype=otel:agentic:json
"agentsec.run.id"="<paste-run-id>"
```

Use quotes around the run.id. Empty is not DENY. If empty, wait, check the id, or see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

## 11. Shutdown

```bash
./scripts/lab-down.sh
```

Volumes and indexed data persist. Next start: `./scripts/lab-up.sh`.

## 12. More help

[TROUBLESHOOTING.md](TROUBLESHOOTING.md) · [OPERATIONS.md](OPERATIONS.md) · [LIVE_VS_REPLAY.md](LIVE_VS_REPLAY.md) · [INSTRUCTOR_GUIDE.md](INSTRUCTOR_GUIDE.md)
