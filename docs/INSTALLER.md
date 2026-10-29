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
