# Prerequisites and installation

This is the host setup for a new learner. The linear start after the host is ready is [QUICKSTART.md](QUICKSTART.md).

Measured hardware floors are **NOT BENCHMARKED**. Where a number is absent, the requirement is **UNKNOWN**. A recommendation below is a planning label, not a measured minimum.

## Container Runtime Requirements

| Runtime | Status | Evidence |
|---------|--------|----------|
| Docker Engine + Docker Compose v2 | REQUIRED for the documented path. VALIDATED on the measured macOS clean-room hosts. | `scripts/lab-up.sh` calls `docker compose`. Clean-room notes record Docker 29.7.2 and Compose v5.5.1 on Darwin arm64. |
| Docker Desktop | The usual way to get that engine on macOS and on an unvalidated Windows path. Docker Desktop is not an AgentSec service. | Preflight tells you to start Docker Desktop or `dockerd`. |
| Podman | NOT VALIDATED. | The repository has no Podman path, script, or test. Do not treat `podman compose` as a supported substitute. |

Docker Engine is the daemon that runs containers. Docker Compose v2 is the `docker compose` plugin that starts this lab. Docker Desktop is an application that installs and runs that engine on a desktop operating system. AgentSec does not ship Docker Desktop.

## Requirement classes

| Item | Class | Why |
|------|-------|-----|
| POSIX shell that can run `scripts/lab-*.sh` | REQUIRED | Those scripts are `/bin/sh`. |
| `docker` CLI | REQUIRED | Preflight FAILs without it. |
| Running Docker daemon | REQUIRED | Preflight runs `docker info`. |
| `docker compose` v2 | REQUIRED | Preflight FAILs without `docker compose version`. |
| Git | REQUIRED to clone. WARN if missing later. | Preflight warns, and does not fail, when `git` is absent. |
| `python3` | REQUIRED once `.env` exists | Preflight and `lab-ready.sh` read `.env` with `python3`. |
| `curl` | REQUIRED for readiness | `lab-ready.sh` calls host `curl`. |
| A browser | REQUIRED to use the Academy | Splunk Web and Attack Service are browser UIs. |
| `.env` copied from `.env.example` | REQUIRED before preflight and `lab-up.sh` | Both scripts require the file. Do not commit it. |
| `uv`, pytest, Playwright | NOT REQUIRED for a learner | Test and UI-review tools. |
| External Splunk | NOT REQUIRED | `lab-up.sh` starts the compose Splunk service. |
| Host Ollama on port 11434 | NOT REQUIRED | Compose Ollama is used, and port 11434 is not published. |
| Podman | NOT VALIDATED | No repository support. |
| Windows | NOT VALIDATED | No Windows clean-room record. |
| Linux | NOT VALIDATED as a clean-room | Expected to work with Docker Engine. Not separately measured. |
| Homebrew | OPTIONAL | Not required on macOS. |

## How to check the host before AgentSec

From any directory, after Docker is installed and the engine is running:

```bash
docker --version
docker compose version
docker info
```

`docker info` must print engine details and exit 0. If it cannot connect, the daemon is not running. Start Docker Desktop, or start the Docker service on Linux, and run `docker info` again.

A daemon that answers `docker info` can still fail to start containers. Before you treat an AgentSec build error as a lab defect, run a one-container check:

```bash
docker run --rm hello-world
```

If that command fails with `runc run failed` or `open /proc/self/mountinfo: permission denied`, the failure is the host container runtime. Do not edit `docker/Dockerfile.acmebank` for that error. See [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

## macOS

**Measured host:** Darwin arm64 (Apple Silicon), Docker Desktop 29.7.2, Compose v5.5.1, recorded in the RC3 clean-room notes. Intel macOS is not a separate measurement.

The Splunk image is `splunk/splunk:10.2` with platform `linux/amd64`. On Apple Silicon, Docker emulates that architecture. That emulation is documented in `.env.example`. It is not a second product.

Install:

1. Install Docker Desktop from Docker's documentation: [https://docs.docker.com/desktop/](https://docs.docker.com/desktop/).
2. Start Docker Desktop and wait until it reports the engine is running.
3. Run the three verification commands above.
4. Install Git if `git --version` fails. Git is a separate install. Homebrew is optional, including `brew install git` or `brew install --cask docker`. Homebrew does not replace starting Docker Desktop.
5. Use Terminal. The lab scripts need `/bin/sh`, which macOS provides. `python3` and `curl` are used by the lab scripts. macOS may prompt to install command-line developer tools the first time `python3` or `git` runs.

Docker Desktop's CPU and memory sliders are Docker's settings. AgentSec does not document a required slider value. Hardware minimums are NOT BENCHMARKED.

## Windows

**Status: NOT VALIDATED.** There is no Windows clean-room record. There is no PowerShell installer.

The lab entry points are shell scripts (`./scripts/lab-up.sh` and the other `lab-*.sh` files). They do not run as PowerShell scripts.

If you choose to try Windows anyway, the plausible unvalidated path is:

1. Enable CPU virtualization in firmware if Docker Desktop says virtualization is unavailable.
2. Install WSL2 and a Linux distribution. Docker Desktop's Windows install documentation is [https://docs.docker.com/desktop/](https://docs.docker.com/desktop/).
3. Install Docker Desktop and leave the engine using the WSL2 backend.
4. Install Git inside that WSL distribution.
5. Clone and run every AgentSec command **inside the WSL shell**, from the repository root. Do not run `./scripts/lab-up.sh` from PowerShell.
6. Confirm the engine from that same shell with `docker info`.

Docker Desktop must be running before `docker info` succeeds. A stopped engine is an environment failure.

Failures that belong to the Windows host, not to an AgentSec control:

- virtualization disabled
- WSL2 missing
- Docker Desktop not running
- the shell cannot see `docker` because the command was typed in PowerShell instead of WSL
- a corporate proxy or TLS inspection appliance rejecting image or model downloads

Do not disable certificate verification to get past a proxy. Ask the network administrator to install the inspection certificate in the Docker engine and in the container trust store.

## Linux

**Status: NOT VALIDATED as an AgentSec clean-room.** The scripts call Docker Engine and Compose v2. A Linux host with those tools is the expected path. No distribution was measured, so this page does not claim Ubuntu, Debian, Fedora, or RHEL support.

Install Docker Engine and the Compose plugin from Docker's engine documentation: [https://docs.docker.com/engine/install/](https://docs.docker.com/engine/install/). Install Git, `curl`, and `python3` from your distribution if they are missing.

Start the daemon if `docker info` cannot connect. On systemd hosts that is typically:

```bash
sudo systemctl enable --now docker
docker info
```

If `docker info` says permission denied on the Docker socket, your user is not allowed to talk to the daemon. Docker's usual fix is to add the user to the `docker` group and then log out and back in:

```bash
sudo usermod -aG docker "$USER"
```

Open a new login session after that change. A new shell in the old session still has the old groups.

Do not use `chmod 777` on the Docker socket. Do not disable SELinux, AppArmor, or seccomp. The compose file does not require privileged containers.

## Hardware and network

| Requirement | Minimum / recommended | Class | Why | How to check |
|-------------|----------------------|-------|-----|----------------|
| CPU | UNKNOWN. Measured hosts were Apple Silicon. Splunk runs as `linux/amd64`. | UNKNOWN | The image platform is in `.env.example`. No CPU floor was benchmarked. | `uname -m` |
| RAM | UNKNOWN. No product minimum. | NOT BENCHMARKED | Splunk, Ollama, and the app containers run together. | Docker Desktop resource settings, or the host memory tool. No AgentSec check. |
| Free disk | UNKNOWN. Preflight prints observed free KiB and claims no minimum. | NOT BENCHMARKED | Images, the Splunk writable layer, and `ollama_models` consume disk. | `./scripts/lab-preflight.sh` INFO line |
| Docker Engine | REQUIRED | VALIDATED on the measured macOS hosts | Starts the lab. | `docker info` |
| Compose v2 | REQUIRED | VALIDATED on those hosts | `lab-up.sh` uses `docker compose`. | `docker compose version` |
| Git | REQUIRED to clone | DOCUMENTED | Preflight only warns if it is later missing. | `git --version` |
| Internet | REQUIRED for the first image pull and for the model pull | DOCUMENTED | Compose pulls images that are not local. The Ollama entrypoint contacts the model registry. | A failed pull names the registry error. |
| Ports | 5000, 5001, 8000, 8088, 4317, 4318 on `127.0.0.1` must be free or already owned by this lab | DOCUMENTED | Published in `docker-compose.yml`. | `./scripts/lab-preflight.sh` |
| Ollama model storage | Volume `ollama_models`. Size UNKNOWN. | DOCUMENTED | The model is stored in the container volume, not a published host port. | `docker volume ls` after start |
| Splunk | Image `splunk/splunk:10.2`, platform `linux/amd64` | DOCUMENTED | Local Academy and Search. | Container `agentsec_splunk` |

The first start downloads more than a later start: Splunk, the OpenTelemetry collector, Ollama, BusyBox, a curl image, and the built AcmeBank and Attack Service images. The model download is a further transfer inside the Ollama container. Corporate proxies and TLS inspection can make that transfer fail even when the lab scripts are correct.

## What the first start downloads and starts

`./scripts/lab-up.sh` runs Compose. Compose pulls images that are not already local and creates the named volumes `shared_telemetry`, `ollama_models`, and `splunk_app_agentsec`. AcmeBank and Attack Service images are built from this repository when they are missing. `--build` rebuilds them even when an older image exists.

Started containers:

| Container | Role |
|-----------|------|
| `agentsec_ollama` | Local model runtime. Entrypoint tries to pull the model. |
| `agentsec_splunk_app_init` | Copies `splunk_app/agentsec` into the app volume, then exits. |
| `agentsec_splunk` | Splunk Web and HEC. |
| `agentsec_splunk_hec_init` | Configures HEC, then exits. |
| `agentsec_otel_collector` | Sends telemetry to HEC. |
| `agentsec_acmebank` | Lab runtime. |
| `agentsec_attack_service` | Local launcher. |

`lab-up.sh` does not load a historical Splunk index. A new volume will not contain someone else's `run.id`. REPLAY pages ship in the Splunk app. Their packets are teaching records, not proof that this index already holds those events.

## Security notes for setup

- Copy `.env.example` to `.env` once. Do not commit `.env`.
- The example values are lab defaults for localhost. Do not paste production passwords, tokens, or cloud keys into `.env`.
- Leave the published ports on `127.0.0.1`. Do not publish the lab to the Internet.
- Do not disable TLS verification to download `llama3.2:1b`.
- Do not add an unrelated MCP server as part of setup.
- REPLAY workshops do not need a GitHub credential, a cloud credential, or a production identity provider.

## Related pages

- [QUICKSTART.md](QUICKSTART.md) — commands after the host is ready
- [AGENTSEC_SERVICE_PORTS.md](AGENTSEC_SERVICE_PORTS.md) — ports
- [AGENTSEC_ENVIRONMENT.md](AGENTSEC_ENVIRONMENT.md) — `.env` keys
- [OPERATIONS.md](OPERATIONS.md) — stop, restart, and reset
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — host failures versus lab failures
