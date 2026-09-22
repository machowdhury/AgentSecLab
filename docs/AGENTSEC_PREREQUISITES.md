# Prerequisites (v1.0)

Measured hardware floors are **NOT BENCHMARKED**. Numbers below are **observed development/test configuration**, not a guarantee.

## Required

| Item | Notes |
|------|--------|
| Operating environment | Observed: macOS (Darwin) with Docker Desktop. Linux Docker Engine is expected to work; **not separately clean-room validated** in Phase 17D. |
| Docker | Engine + Compose v2. Daemon must be running. |
| Git | To clone/update the repository. |
| Browser | For Splunk Web and Attack Service. |
| Repository | AgentSec source tree including `docker/`, `splunk_app/`, `learning/`, `src/`. |
| `.env` | Copy from `.env.example`. Required by `lab-up.sh`. |

## Observed (not a minimum)

Splunk container image `splunk/splunk:10.2`, platform `linux/amd64`. Apple Silicon uses emulation. First boot can take 10–20 minutes. Disk: Splunk + Ollama model + images are large; free space was not formally benchmarked.

## Network

Default binds are **127.0.0.1** only. Image pulls need outbound network on first start (Docker Hub, Ollama model). After images/models exist, the lab can run without further public attack-surface binds.

## Ports (host)

See [AGENTSEC_SERVICE_PORTS.md](AGENTSEC_SERVICE_PORTS.md). Conflicts with local Splunk, Flask, or Ollama on the same ports will fail preflight or startup.

## Splunk

Local path uses the compose Splunk service. External Splunk is **optional/operator-managed** and is **not** started by `lab-up.sh`. See [LOCAL_DOCKER_LAB.md](LOCAL_DOCKER_LAB.md).

## Ollama

**Required for LIVE labs that call the model** (for example Direct Prompt Injection). The compose `ollama` service is part of the canonical stack. Host port 11434 is **not** published (avoids clashing with a local Ollama). MCP authorization labs can be deterministic; PI still needs the model path.

## Scanner

Cisco mcp-scanner evidence workshops are **REPLAY**. Running a live scanner is **not** required for the published Academy path.

## Optional vs required

| Dependency | Class |
|------------|--------|
| Docker stack above | required for the documented learner path |
| `uv` / pytest | development/test-only |
| Playwright | UI review / development |
| External Splunk | optional operator path |
| Host Ollama on :11434 | not required; compose Ollama is used |

## Environment variables

See [AGENTSEC_ENVIRONMENT.md](AGENTSEC_ENVIRONMENT.md).
