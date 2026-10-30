# AgentSec installer core (RC2, in development)

`./agentsec` generates the lab's configuration, checks the machine read-only, and shows a dry-run plan. **It never pulls an image, starts a container or touches an existing lab unless you pass `--apply`**. `--apply`, `up`, `down` and `status` were exercised on a real Ubuntu 24.04 Docker host in the RC2 acceptance runs (record); the step-by-step guide is [Installation and deployment](INSTALLATION_AND_DEPLOYMENT.md). Standard library only: `python3` is enough.

```
./agentsec install                       # interactive (a terminal): one question at a time, a default in brackets
./agentsec plan                          # or: install --dry-run: prints what would be written and run; writes nothing
./agentsec install --non-interactive --config agentsec.install.json --accept-warnings all
./agentsec preflight | validate | print-config | rollback | verify-models | verify-images
```
Configuration is one JSON file (`agentsec.install.json`) plus optional `--set key=value` flags (`--set gateway.port=8000`). Unknown keys and wrong types are refused. `print-config` shows the effective configuration.

## CTF through the gateway (opt-in)
`gateway.ctf: true` (default false; needs the gateway) makes `agentsec up` add `docker-compose.gateway-ctf.yml` to the Compose files itself and run `gateway.sh ctf-enable` first (idempotent). The Attack Service then runs as the installing user, so install and `up` as the same **unprivileged** user (`CTF_AS_ROOT` / `CTF_UID_MISMATCH` / `CTF_SECRET_PERMISSIONS` refuse anything else, with the fix in the message). Not exercised on a real host since this change.

## Deployment modes (the only supported ones)
1. **`localhost` (default):** bound to loopback on the learner's own machine. A non-loopback bind is refused.
2. **`organization`:** behind **your** authentication, rate-limiting and network-access gateway. It needs an explicit acknowledgement (`--ack-external-controls`, or typing `I ACKNOWLEDGE` in the wizard) that the lab's own login has **no failed-login throttling** (known limitation M-2) and is not SSO.
Direct exposure to the public internet or an untrusted network is **unsupported**.

## What it writes
`.env` (owner-only; secrets are generated once and reused on later runs; the old example passwords are never used), `.agentsec/compose.override.yml`, `.agentsec/install.json` (the configuration and what was resolved; no generated secret, and a URL with credentials is refused). Files are created owner-only (0600, in a 0700 directory) with an exclusive temporary file and an atomic rename, and the installer refuses to write through a symbolic link. A re-run that would change nothing writes nothing. An existing `.env` that this installer did not generate is **never** overwritten without `--force-env`; it is kept as `.env.pre-agentsec` (then `.1`, `.2` ...), also owner-only. `.agentsec/` and the backups are git-ignored.
Every configuration value is checked before anything is rendered: control characters (newlines) are refused everywhere, names and hosts must match fully, URLs must be plain `https://host[:port]` without credentials, paths and values must not contain spaces, quotes, `#` or `$`, and the publish address must be an IP.
**Rollback:** the previous generated files are kept one level deep, rotated only when a write actually changes something. `./agentsec rollback` restores them (configuration only: no container, image or volume is touched) and refuses anything that is not an installer-generated configuration. After `--force-env` there is nothing to roll back to.

## Isolation and data
Containers are named `<project>-<service>` (the old `agentsec_*` names stay as network aliases so in-mesh DNS names keep working); Compose scopes networks and volumes to the project. **Two installs can coexist only when they live in separate checkouts (each has its own `.env`, `.agentsec`, `artifacts` and `.certs`) and use different host ports** (every published port is configurable; preflight reports clashes).
**An existing lab is reported, never touched by preflight, plan or a dry run.** Starting a project-named install in the *same* Compose project as a lab running under the old names would recreate every container under new names (data volumes are kept, the old container names cannot be restored by rollback): that is an error unless you set `ack_recreate_existing`. `naming: legacy` with the lab's own project name adopts it unchanged. A Splunk image that differs from the tested default over existing Splunk data needs `ack_splunk_upgrade`; **Splunk 10.6 is refused over existing data** (its KV-store migration cannot be rolled back): use a new project. No command in any plan removes a volume. Variables exported in your shell (`COMPOSE_FILE`, `AGENTSEC_BIND_ADDRESS`, ...) beat `.env`; preflight flags them. `lab-up.sh`, `lab-ready.sh`, `lab-down.sh`, `lab-preflight.sh` and `gateway-ready.sh` find containers through `scripts/lab-compose.sh` (Compose project + service labels), so they work with both naming schemes. **Not yet migrated** (they still address the fixed `agentsec_*` names, so they need `naming: legacy`): `academy-restart.sh`, `learner_ready.py`, `seed_envelope_specimens.py` (run by `lab-up.sh` after readiness), `deploy_acmebank_attack.py`, `ollama_init.sh` and the evidence/capture scripts under `scripts/`.

## Lifecycle: `agentsec up | down | status | logs`
They act on the installation recorded in `.agentsec/install.json` (project, services, Compose files and profiles); the project is always passed explicitly, so another project on the same host is never touched.
- `up` first validates everything and starts nothing if any check fails: the state and `.env` are installer-generated and unmodified (hash), owner-only permissions (`.env` 600, `.agentsec` 700), the image pins still equal `deploy/images.lock.json` (and carry digests when `require_digests` is set), the configuration re-validates (remote Ollama is refused), and the machine prerequisites (Docker, Compose, ports, an existing lab under the old names, Splunk upgrade guards, Ollama) pass. Then it runs `compose config -q`, the host preparation (receipts directory, HEC certificate, gateway init) and `compose up -d --no-recreate`: **an existing container is never recreated**; to apply a changed configuration use `agentsec install --apply`.
- `down` runs `compose down --timeout 120`: containers and the network are removed, **volumes, images and orphans are not** (`-v`, `--volumes`, `--rmi`, `--remove-orphans`, `prune`, `rm` are refused in code). It works even when generated files were edited. Deleting data stays a deliberate, separate action (`scripts/lab-down.sh --purge --yes-delete-all-lab-data`).
- `status` is read-only: per service running/healthy, the two Splunk init jobs exited 0; exit 5 when something is missing or not ready. `logs [service] [--tail N] [--follow]`: only services of this installation; known secrets are redacted (not when following: `--follow` output goes straight to the terminal, unredacted).
- All are idempotent. A failed `up` removes and rolls back nothing (running containers stay, data untouched); repeat it, run `down`, or restore the previous generated files with `agentsec rollback` (no Docker involved).
- **Remote Ollama is refused** (`OLLAMA_REMOTE_UNSUPPORTED`): Ollama has no authentication or TLS of its own and the lab's model client cannot send credentials or use a private CA yet. Use `bundled` or `host`.

## Images, models and pins
`deploy/images.lock.json` and `deploy/models.lock.json` hold the pins. Splunk defaults to the digest RC1 verified; 10.4 and 10.6 are unqualified candidates (`allow_candidate_images`), and 10.1/10.3/10.5/10.7 do not exist for Splunk Enterprise and are refused. `require_digests` refuses floating tags (today the Ollama image is one). A model outside `models.lock` needs `allow_unpinned_model`. `verify-models` compares what Ollama reports with the lock (exact names only); `verify-images` lists the read-only registry queries and runs them only with `--execute`. The Splunk compatibility matrix is `deploy/splunk_compat_matrix.json` (every row NOT_RUN).

## Exit codes
0 done, 2 usage or malformed configuration, 3 checks failed or warnings not accepted, 4 refused to overwrite, 6 `--apply` command failed.

## Not verified
A real host other than the one Ubuntu 24.04 x86-64 machine of the acceptance runs (macOS, Windows, other Linux distributions, ARM, rootless Docker, Podman); `gateway.port` 8000; an organization certificate; `backup` and `uninstall` procedures; hardware minimums (advisory only: the measured figures in the installation guide are single observations, not requirements).

---

# Reference: requirements, configuration and maintenance

The sections below were moved here from the installation guide, which now holds only the step-by-step paths. They carry their original TESTED / NOT TESTED labels.

## Requirements, measurements and platform status

### Hardware and software
| Item | What the tested host had | What this means for you |
|---|---|---|
| CPU | 8 vCPU (Intel Xeon, AVX and AVX2) | Models run on the CPU; there is no GPU support |
| RAM | 31 GiB (8 vCPU `m6i.2xlarge`) | See the measurements below. **No minimum is claimed.** Plan generously |
| Disk | 120 GiB gp3 volume | The installer's preflight reported about 20 GB needed before the install |
| OS | Ubuntu 24.04 LTS, x86-64 | The only tested platform |
| Docker | Docker Engine 29.9.2, Compose 5.6.1 | Docker with Compose v2; the user must be in the `docker` group |
| Other | `git`, `python3`, `openssl`, `curl` | `python3` alone runs the installer (standard library) |
| Network | Internet access to pull images and models | About 16 GB of images and 3.3 GB of models on first install |

### Measured figures (one tested workload each, not requirements)
| Measurement | Value | Condition |
|---|---|---|
| Disk after install | **about 25 GiB** used of the 116 GiB volume | images 16.2 GB, volumes 5.7 GB of which 3.3 GB are models |
| Peak RAM | **about 6 GiB** (6,051 MiB used on the host) | during one Loan Desk transaction with both models loaded; Ollama 4.1 GiB of that; the sample covered about 28 s |
| Peak RAM, earlier | 3.5 GiB | four consecutive live attacks with only the 1b model |
| RAM at idle | 1.8 GiB | Splunk 0.7 GiB, Ollama 1.5 GiB with a model loaded |
| Clean install | **about 9 to 10 minutes** (9 min 32 s and 9 min 35 s in two runs) | on a fast data-centre network, including about 4 minutes while Splunk loads its sample data |
| `agentsec up` after a `down` | 67 s to start, 82 s until all services were healthy | models and data already present |
| `agentsec down` | 4 to 6 minutes | Splunk stops slowly (the installer gives it up to 120 s per container plus its own shutdown) |

These are single measurements on one machine. They are **not** minimum requirements, and your network, disk and CPU will change them.

### Platforms
| Platform | Status |
|---|---|
| Ubuntu 24.04 LTS x86-64, Docker Engine, localhost, gateway on port 443, generated test certificate | **TESTED** |
| Other Linux distributions, ARM Linux, rootless Docker, Podman | **NOT TESTED** |
| macOS (Docker Desktop) | **NOT TESTED** for RC2 (the older `scripts/lab-up.sh` flow, see [Local Docker lab](LOCAL_DOCKER_LAB.md), predates RC2 and is not covered here) |
| Windows (WSL2) | **NOT TESTED** |
| Gateway on port 8000 instead of 443 | **NOT TESTED** (configuration checked only) |
| Organization-managed certificate (`ORG_CERT`), non-loopback bind, `deployment: organization` | **NOT TESTED** |
| External Splunk Enterprise or Splunk Cloud | **NOT TESTED** against a real service (the client is tested against a local stand-in server and against the bundled Splunk) |

## Cloud VM settings used in testing

The test hosts used these settings (TESTED). They are what worked, not a sizing recommendation.

| Setting | Value used |
|---|---|
| Instance | `m6i.2xlarge` (8 vCPU, 32 GiB), an official Canonical Ubuntu 24.04 LTS x86-64 image |
| Storage | 120 GiB gp3 root volume, delete on termination |
| Network | Security group allowing only SSH (22) and HTTPS (443) from **your own public IP as a /32**. Nothing else; AcmeBank and Ollama publish no host port, and Splunk Web and HEC are published to the host's loopback only |
| Metadata | IMDSv2 required |
| Safety | A scheduled `shutdown -h` as an independent expiry, and `--instance-initiated-shutdown-behavior terminate` |
| Cost seen | about $0.43 per hour for the instance (AWS list price in `ca-central-1`, checked on the day), so a 36-minute run cost about $0.27 |

After the instance is up, follow the [remote path](INSTALLATION_AND_DEPLOYMENT.md#remote-ubuntu-server-or-cloud-vm-open-it-from-your-laptop) over SSH.

## Docker Compose and the two models

The installer drives Docker Compose for you; you rarely run `docker compose` yourself. Compose files used: `docker-compose.yml`, `docker-compose.local.yml` (bundled Splunk), `docker-compose.gateway.yml`, `docker-compose.gateway-ctf.yml` (CTF), and the generated `.agentsec/compose.override.yml`. They are listed in `COMPOSE_FILE` in `.env`.

### The two Llama models (both required for the full lab)
| Model | Size | Used by | Why this one |
|---|---|---|---|
| `llama3.2:1b` (`OLLAMA_MODEL`, digest `baf6a787fdff`) | 1.3 GB | The AcmeBank pipeline labs that call a model (for example LAB-PI-001) | The validated default for the in-lab pipeline; small and fast |
| `llama3.2:latest` (`LOANDESK_MODEL`, the 3B build, digest `a80c4f17acd5`) | 2.0 GB | The Loan Desk mission (LAB-LOANDESK-001) | The Loan Desk drives a multi-step tool loop. Measured with the repository's loop benchmark (`scripts/bench_agent_loop.py`; results in final_acceptance2; small samples), `llama3.2:1b` completed **0 of 5** benign Loan Desk runs and `llama3.2:latest` completed **4 of 4**, so the Loan Desk does not reuse the 1b model |

With the **bundled** Ollama, the container's entrypoint pulls both when they are missing (TESTED: log lines `Pulling model ... Model ... pulled.` for each). The lab never swaps one model for another: if the configured model is not installed, the run is refused and the Academy shows the exact `ollama pull` command. The Ollama image (`ollama/ollama:latest`) is a floating tag, so the Ollama version can change between installs (0.40.13 was tested).

**Host Ollama** (`ollama.mode: host`, for example a native Ollama on the machine) is **NOT TESTED** on Linux; the installer then pulls nothing and lists no model download, so run `ollama pull llama3.2:1b` and `ollama pull llama3.2:latest` yourself. A **remote** Ollama is refused (`OLLAMA_REMOTE_UNSUPPORTED`).

If a pull fails with `x509: certificate signed by unknown authority`, fix certificate trust on the host or image (an organization proxy is the usual cause). Never disable certificate verification.

## Configuration keys and generated variables

### Installer configuration (`agentsec.install.json` or `--set key=value`)
Unknown keys and wrong types are refused. `./agentsec print-config` shows the effective configuration (TESTED).

| Key | Default | Meaning |
|---|---|---|
| `project` | `agentsec` | Compose project and container prefix (`<project>-<service>`) |
| `naming` | `project` | `legacy` adopts an existing lab's fixed `agentsec_*` names |
| `deployment` | `localhost` | `localhost` or `organization` (behind your own gateway; needs `ack_external_controls`) |
| `gateway.enabled` / `host` / `port` / `bind` | `true` / `localhost` / `443` / `127.0.0.1` | the HTTPS gateway; ports 443 and 8000 are the supported values |
| `gateway.ctf` | `false` | publish the CTF through the gateway; the Attack Service then runs as you |
| `ollama.mode` | `bundled` | `bundled` or `host` (`remote` is refused) |
| `models.pipeline` / `models.loan_desk` | empty = lock default | `llama3.2:1b` and `llama3.2:latest`; a model outside `deploy/models.lock.json` needs `allow_unpinned_model` |
| `splunk.mode` | `bundled` | `bundled`, `external_enterprise`, `cloud` or `none` (replay only) |
| `splunk.rest_url` / `ca_file` / `token_file` / `index` | empty / empty / empty / `agentsec_telemetry` | REST verification ([Splunk reference](SPLUNK_INTEGRATION.md#turning-on-rest-verification-verified-for-the-bundled-splunk-tested-once-on-a-disposable-host)); for the bundled Splunk both `rest_url` and `token_file` must be set |
| `ports.*` | splunk_web 8000, hec 8088, otel_grpc 4317, otel_http 4318, acmebank 5000, attack 5001 | host ports where they are published |
| `require_digests`, `allow_candidate_images`, `ack_splunk_upgrade`, `ack_recreate_existing` | `false` | safety switches described in [Installer](INSTALLER.md) |

Example file (TESTED with `print-config`):
```json
{
  "gateway": {"enabled": true, "host": "localhost", "port": 443, "ctf": true},
  "ollama": {"mode": "bundled"},
  "models": {"pipeline": "", "loan_desk": ""},
  "splunk": {"mode": "bundled"}
}
```
Do not edit the generated `.env` by hand: the installer detects it (`GENERATED_FILE_MODIFIED`) and refuses to start. Change the configuration and re-run the installer instead.

### Generated environment variables (`.env`, mode 0600, never commit it)
| Variable | Purpose |
|---|---|
| `COMPOSE_PROJECT_NAME`, `COMPOSE_FILE`, `COMPOSE_PROFILES` | which Compose files and profiles make up the lab |
| `OLLAMA_MODEL`, `LOANDESK_MODEL`, `OLLAMA_BASE_URL` | models per role; the Ollama URL (host mode only) |
| `AGENTSEC_SECURITY_PROFILE`, `AGENTSEC_LAB_ID`, `AGENTSEC_TESTBED_MODE`, `AGENTSEC_OTEL_ENABLED` | lab behaviour; the default profile is `defended` and the launcher sets the profile per run |
| `AGENTSEC_BIND_ADDRESS` | publish address for the plain ports (loopback by default) |
| `SPLUNK_PASSWORD`, `SPLUNK_HEC_TOKEN`, `SPLUNK_IMAGE`, `SPLUNK_PLATFORM` | generated secrets (random per install) and the pinned image |
| `SPLUNK_HEC_ENDPOINT`, `SPLUNK_HEC_INDEX`, `SPLUNK_HEC_SOURCETYPE`, `SPLUNK_HEC_SOURCE`, `AGENTSEC_HEC_TLS_MODE` | telemetry path to Splunk |
| `AGENTSEC_PUBLIC_HOST`, `AGENTSEC_PUBLIC_PORT`, `AGENTSEC_GATEWAY_BIND`, `AGENTSEC_TLS_MODE`, `AGENTSEC_ATTACK_TIER` | the gateway |
| `AGENTSEC_SPLUNK_LOCAL_PORT` | where Splunk Web is published on loopback (18000) |
| `AGENTSEC_SPLUNK_MODE`, `AGENTSEC_SPLUNK_REST_URL`, `AGENTSEC_SPLUNK_CA_BUNDLE_FILE`, `AGENTSEC_SPLUNK_SEARCH_TOKEN_FILE`, `AGENTSEC_SPLUNK_INDEX` | REST verification (only when configured) |
| `AGENTSEC_CTF_GATEWAY`, `AGENTSEC_CTF_SECRET_FILE`, `AGENTSEC_CTF_STATE_HOST`, `AGENTSEC_CTF_UID`, `AGENTSEC_CTF_GID` | the CTF overlay (only with `gateway.ctf`) |

## Upgrade, backup, recovery and uninstall

### Upgrade (partly tested)
```bash
git fetch && git checkout <new commit>      # review the change first
./agentsec preflight
./agentsec <your same options> --apply install     # TESTED: re-running over a running install updates configuration only
./agentsec status
```
Changing the Splunk image over existing data needs `ack_splunk_upgrade`; Splunk 10.6 is never allowed over existing data. Upgrading across RC2 builds beyond a re-run is **NOT TESTED**.

### Backup (NOT TESTED)
Stop the lab first so the files are consistent: `./agentsec down`. Then copy what is not reproducible: `.env`, `.gateway/` (credentials, TLS, CTF ledger and key), `.agentsec/`, `artifacts/`, and the Docker volumes `agentsec_splunk_etc`, `agentsec_splunk_var`, `agentsec_shared_telemetry`, `agentsec_splunk_app_agentsec` and (to avoid the re-download) `agentsec_ollama_models`. For a volume:
```bash
mkdir -p backup
docker run --rm -v agentsec_splunk_var:/v:ro -v "$PWD/backup":/b alpine tar czf /b/splunk_var.tgz -C /v .
```
Restoring is the reverse into empty volumes before the first `up`. The CTF ledger rolls back silently if you restore an older consistent pair of `ledger.jsonl` and `ledger.head`, or delete both.

### Recovery
- **A failed `up`** removes and rolls back nothing. Repeat it, or run `./agentsec down` and `./agentsec up`.
- **A damaged configuration:** `./agentsec rollback` restores the previous generated files (TESTED in the installer's own test suite, not on a host).
- **Splunk will not start after a crash:** read `./agentsec logs splunk --tail 200`; do not delete volumes as a first step.

### Uninstall (NOT TESTED)
```bash
./agentsec down
docker volume ls --filter name=agentsec_          # review the list, then remove only these:
docker volume rm agentsec_splunk_etc agentsec_splunk_var agentsec_shared_telemetry agentsec_splunk_app_agentsec agentsec_ollama_models
docker image ls | grep -E 'splunk/splunk|ollama/ollama|otel/opentelemetry|nginx'
cd .. && rm -rf AgentSecLab                      # removes .env, .gateway (credentials, CA, CTF state) and artifacts
```
Check the names with `docker volume ls` first; this removes your Splunk data and models.
