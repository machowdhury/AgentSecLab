# AgentSec Quickstart

A technically capable person should be able to follow this linearly. Run every command from the **repository root**.

Use the `develop` branch. That tree is the current L0–L10 release candidate (v1.0.0-rc3). `main` and annotated tag `v1.0.0-rc1` are the earlier baseline and stop before L6. Tag `v1.0.0-rc2` is the previous candidate. This candidate is not final `v1.0.0`. Clean-room installation on an empty machine has not been proven in this paragraph; these steps are the documented path. The release notes record whether a later clean-room run succeeded.

After the first lab, continue with the README academy section and [AGENTSEC_RELEASE_LAB_MATRIX.md](AGENTSEC_RELEASE_LAB_MATRIX.md). Do not treat the L5 Capstone as the end of the academy. L10 is the Advanced Capstone. Mastery Check is a separate unscored self-check.

## 1. Prerequisites

- Git
- Docker Engine + Docker Compose v2
- A browser
- This repository

Hardware minimums: **NOT BENCHMARKED**. Observed development used Docker Desktop on macOS with Splunk 10.2 (`linux/amd64`, emulated on Apple Silicon). First boot pulls container images. The Ollama container then tries to pull `llama3.2:1b`. A failed pull leaves LIVE generation degraded.

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

First Splunk initialization can take **10–20 minutes**. Output from compose/health retries can be noisy. `lab-ready` prints SERVICE READY for the academy stack. A later `MODEL ABSENT` line means LIVE generation is degraded.

The Ollama entrypoint (`scripts/ollama_init.sh`) tries `ollama pull llama3.2:1b`. If that pull fails, the API still stays up and AcmeBank `/health` reports `degraded` with `ollama_reachable: false`. That flag means the model name was not listed. It does not mean the Ollama process is down. Academy REPLAY does not need the model.

If the automatic pull fails, the usual command is:

```bash
docker exec agentsec_ollama ollama pull llama3.2:1b
```

A certificate or TLS error must be fixed at the host or image trust layer. Do not disable certificate verification. On this development host, `curl` on the host reached `registry.ollama.ai`, and the same request from inside the `ollama/ollama:latest` container failed with `x509: certificate signed by unknown authority`. That split is an external dependency of the container image, not an AgentSec authorization result.

Rebuild images from this repository after Attack Service or AcmeBank source changes:

```bash
./scripts/lab-up.sh --build
```

## 5. Readiness

```bash
./scripts/lab-ready.sh
```

READY means **service health**: Splunk Web, HEC health endpoint, published Academy views, and HTTP responses from AcmeBank and Attack Service.

READY does **not** mean a given `run.id` is searchable. HEC HTTP 200 is not indexed evidence. `MODEL ABSENT` means LIVE generation is **DEGRADED**, not pass.

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

## 12. What to do next

Return to Academy Home and follow L1 through L10. The L5 menu label **Capstone** is Lending Assistant Investigation, the last LIVE launcher. Complete **Splunk Defender Bridge** before L6. **Advanced Capstone** is L10. **Mastery Check** is optional and unscored.

Specimen ids printed on a dashboard are reference evidence. Investigate the `run.id` from the launch you just made.

## 13. More help

[TROUBLESHOOTING.md](TROUBLESHOOTING.md) · [OPERATIONS.md](OPERATIONS.md) · [LIVE_VS_REPLAY.md](LIVE_VS_REPLAY.md) · [AGENTSEC_RELEASE_LAB_MATRIX.md](AGENTSEC_RELEASE_LAB_MATRIX.md) · [INSTRUCTOR_GUIDE.md](INSTRUCTOR_GUIDE.md)
