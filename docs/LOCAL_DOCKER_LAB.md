# Local Docker lab vs external Splunk

**Status:** LOCAL path is Docker-managed. EXTERNAL Splunk is operator-managed.  
**Schema / SPL / lab behavior:** unchanged.

## ROOT CAUSE of the old manual copy

The official `splunk/splunk` image runs Ansible at first boot and **recursively `chown`s `/opt/splunk`**.

A **read-only** bind of `splunk_app/agentsec` onto `/opt/splunk/etc/apps/agentsec` fails with **EROFS**. That is why Phase 2B parked the repo at `/tmp/agentsec-app:ro` and copied by hand.

A **read-write** bind of the repo onto `/opt/splunk/etc/apps/agentsec` would let `chown` succeed **and would change ownership of files in the git tree**. That is not acceptable.

## Chosen design (pattern A)

1. `splunk_app_init` copies `splunk_app/agentsec/` (repo, `:ro`) into named volume `splunk_app_agentsec` (writable).
2. Splunk mounts that volume at `/opt/splunk/etc/apps/agentsec` **without `:ro`**.
3. Ansible may `chown` the **volume copy only**.
4. `splunk_hec_init` still creates/binds `agentsec_telemetry` and HEC after Splunk is healthy.
5. `./scripts/lab-ready.sh` declares READY only when app, view, index, HEC, mesh HEC, AcmeBank, and Attack UI check out.

Not chosen: custom Splunk image (slow rebuilds), `SPLUNK_APPS_URL` (first-boot only; poor inner-loop for XML edits), `:ro` apps bind.

## LOCAL DOCKER LAB

```bash
cp .env.example .env   # once; do not commit .env
./scripts/lab-up.sh
```

Equivalent compose (`.env` already sets `COMPOSE_FILE` / `COMPOSE_PROFILES=local` if copied from example):

```bash
docker compose -f docker-compose.yml -f docker-compose.local.yml --profile local up -d
./scripts/lab-ready.sh
```

| URL | Role |
|-----|------|
| http://127.0.0.1:5000 | AcmeBank |
| http://127.0.0.1:5001 | Attack UI |
| http://127.0.0.1:8000 | Splunk (app **AgentSec**, view `ws_lab_pi_001`) |
| http://127.0.0.1:11434 | Host Ollama, if you run one. Docker Ollama is in-mesh only (`http://ollama:11434`). |

If Docker Ollama cannot pull a model (TLS/registry), the API still stays up. Point AcmeBank at host Ollama with `OLLAMA_BASE_URL=http://host.docker.internal:11434` in `.env`.

### After `docker compose down`

`up` recreates `splunk_app_init`, so the volume is restaged from the repo. Splunk data volumes persist unless you used `-v`.

### After `docker compose down -v`

Clean first boot: new Splunk Ansible, new app volume, new Ollama model volume.

### When you change `splunk_app/agentsec/`

Do **not** `docker cp`. While the stack is running:

```bash
./scripts/lab-up.sh --refresh-app
```

That restages the named volume and restarts Splunk so `default/` views reload.

Rebuild AcmeBank / Attack UI images:

```bash
./scripts/lab-up.sh --build
```

### What READY means

`lab-ready.sh` requires:

- Splunk container **healthy** (login page **and** app files including `ws_lab_pi_001.xml`)
- `splunk_app_init` and `splunk_hec_init` exited 0
- index `agentsec_telemetry` exists
- HEC health HTTP 200 on the host and from the compose mesh
- REST `data/ui/views/ws_lab_pi_001` HTTP 200
- AcmeBank and Attack UI `/health` HTTP 200

A running `splunkd` process alone is **not** READY.

## EXTERNAL SPLUNK

Do not run `splunk_app_init` against an external instance. Package or copy `splunk_app/agentsec` with the Splunk deployment mechanism you already use (install app, cluster bundle, Splunk Cloud app install).

Set collector env to the external HEC:

- `SPLUNK_HEC_ENDPOINT`
- `SPLUNK_HEC_TOKEN`
- `SPLUNK_HEC_INDEX`

Do not start compose profile `local` if you are not running the lab Splunk container. AcmeBank can still emit OTLP to a collector that points at external HEC.

## Troubleshooting (not the normal workflow)

Manual `cp` / `chown` inside the Splunk container is a **break-glass** leftover from Phase 2B. If staging failed, inspect:

```text
docker logs agentsec_splunk_app_init
docker inspect agentsec_splunk_app_init --format '{{.State.Status}} {{.State.ExitCode}}'
```

## Clean-boot note (OBSERVED 2026-09-12)

`docker compose down -v` then compose up staged the app automatically (`splunk_app_init` exit 0; `ws_lab_pi_001.xml` present; Splunk `chown` on the **volume** copy). `./scripts/lab-ready.sh` then returned READY.

Docker Ollama model pull failed TLS (`x509: certificate signed by unknown authority`) in this environment. The init script keeps the API up; host Ollama on 11434 remains the fallback via `OLLAMA_BASE_URL=http://host.docker.internal:11434`.
