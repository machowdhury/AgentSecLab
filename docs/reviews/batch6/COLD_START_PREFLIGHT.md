# Disposable cold-start: written preflight (written BEFORE anything was started)

Authorization: Batch 6 Priority 2 allows a cold start only in an isolated disposable copy after this preflight.
Harness: `scripts/cold_start_disposable.sh` (`preflight` changes nothing and passed on 2026-10-22; its output is in
`COLD_START_RESULTS.md`). Isolation is proven by construction *and* checked by the harness before and after it renders the config.

## 1. Isolation matrix

| Concern | Running lab (untouched) | Disposable copy |
|---|---|---|
| Compose project | `agentseclab` | `agentseclab_cold` (`-p` and `name:`) |
| Container names | `agentsec_splunk`, `agentsec_acmebank`, `agentsec_attack_service`, `agentsec_otel_collector`, `agentsec_ollama` | all `agentsec_cold_*` (override file) |
| Host ports | 5000, 5001, 8000, 8088, 4317, 4318 | 15000, 15001, 18000, 18088, 14317, 14318 (all verified free; all `127.0.0.1`) |
| Network | `agentseclab_agentsec_mesh` | `agentseclab_cold_agentsec_mesh`. The Splunk service gets the in-network aliases `agentsec_splunk` and `splunk` there only, so the HEC certificate names still match without sharing a name with the real container |
| Volumes | `agentseclab_ollama_models`, `agentseclab_shared_telemetry`, `agentseclab_splunk_app_agentsec` | project-scoped fresh volumes `agentseclab_cold_*`. No volume is named or mounted from the running lab |
| Source tree | the develop tree and this worktree | a fresh `git clone` of this branch into scratch space (`$COLD_ROOT/repo`); the develop tree is never read or written |
| Mutable artifacts | develop tree `artifacts/` | the clone's own `artifacts/` |
| Credentials | the lab's `.env` | a new `.env` generated in the clone with random Splunk password and HEC token, mode 0600, never printed; the lab's `.env` is not read |
| HEC certificates | `.certs/` of the lab | newly generated in the clone by `scripts/hec-certs.sh` |
| Verifier | pid, key and state under the lab's directories | `AGENTSEC_VERIFIER_STATE_DIR` in scratch; `AGENTSEC_ARTIFACTS_HOST_DIR` = the clone's artifacts; `AGENTSEC_SPLUNK_CONTAINER=agentsec_cold_splunk`, so its `docker exec` can only ever reach the disposable Splunk |
| Docker socket | not mounted | not mounted (asserted from the rendered config) |

New code needed for this: `AGENTSEC_SPLUNK_CONTAINER` in `reconcile.py` (validated against a strict container-name pattern, default unchanged).
Without it the disposable verifier would have searched the REAL Splunk.

## 2. Resources
- Docker VM: 12 GB RAM, 18 CPUs; running lab uses about 3 GB (Splunk 2.7 GB). A second Splunk needs about 4 GB. Free disk 507 GB.
- Images: `splunk/splunk:10.2`, `otel/opentelemetry-collector-contrib:0.96.0`, `curlimages/curl:8.5.0`, `busybox:1.36` already local (the harness refuses to pull). AcmeBank and Attack Service are built from the clone; this reuses cached layers and may fetch Python packages from the configured index. No model is fetched.
- Time: Splunk (amd64 under emulation on Apple Silicon) first boot is 10 to 20 minutes.
- Expected disposable footprint: about 5 GB of volumes and images beyond the base images.

## 3. Model requirements and the model-readiness test
- The disposable `ollama` service is assigned a never-used profile: its entrypoint would pull a model. It is never started.
- Phase A: AcmeBank points at the (absent) in-project Ollama, so the first-run check must show "Ollama is not reachable" with `ollama serve` as the manual fix and no download.
- Phase B: AcmeBank is re-pointed to the host Ollama (`OLLAMA_BASE_URL=http://host.docker.internal:11434`, which `docker-compose.local.yml` maps). The host already has `llama3.2:latest`. The host Ollama is a shared read-only dependency: no model is added, removed or pulled.
- Corporate trust: no TLS setting, certificate store or `-k` flag is changed or used.

## 4. What will NOT happen
No `docker compose` command without `-p agentseclab_cold`; no `docker system prune`, `volume prune`, `rm -rf` outside `$COLD_ROOT`; no stop, restart or recreate of any running container (including Splunk); no write to the develop tree, this worktree's tracked files or the lab's `artifacts/`; no use of the lab `.env`.

## 5. Cleanup, limited to the disposable environment
`cold_start_disposable.sh down` removes, in order: containers labelled `com.docker.compose.project=agentseclab_cold`, volumes with that label, the `agentseclab_cold_agentsec_mesh` network, images tagged `agentseclab_cold-*`, then `$COLD_ROOT/repo` and the override file. It refuses to run with any other project name. Afterwards the harness's own `status` and `docker ps`/`volume ls` comparison with the pre-run list show the running lab unchanged.

## 6. Stop conditions
If the rendered config contains a name, port or bind mount outside the disposable set, a port is busy, a resource of the project already exists, or any of the four images is missing, the harness stops and this document is the request for an alternative approval. None occurred at preflight.
