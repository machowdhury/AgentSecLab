# Operations: start, stop, reset, diagnostics

Canonical start: `./scripts/lab-up.sh` from the repository root (`.env` required). There is no separate clean-room script. A fresh volume start is the destructive Compose command below, used only when you mean to delete lab data.

## Learner commands

| Intent | Command | Data |
|--------|---------|------|
| Stop | `./scripts/lab-down.sh` | Containers stop. The script says indexed Splunk data and named volumes remain. |
| Start again | `./scripts/lab-up.sh` | Uses existing volumes. |
| Rebuild app images | `./scripts/lab-up.sh --build` | Rebuilds AcmeBank and Attack Service, then starts. |
| Restage Splunk app | `./scripts/lab-up.sh --refresh-app` | Copies `splunk_app/agentsec` into `splunk_app_agentsec`, restarts Splunk, and runs HEC init again. |
| Status | `./scripts/lab-preflight.sh` and `./scripts/lab-ready.sh` | Preflight does not start the lab. `lab-ready` checks the running lab. |
| Which containers exist | `docker ps --filter name=agentsec_` | Names only. |
| Logs | `docker compose -f docker-compose.yml -f docker-compose.local.yml --profile local --env-file .env logs --tail=80 attack_service acmebank otel_collector splunk ollama` | Does not print `.env`. |

## What READY means

`./scripts/lab-ready.sh` prints `SERVICE READY` and exits 0 when service health passes. It can still print `MODEL ABSENT` and then exit 0. That pair means the Academy stack answered and LIVE generation is degraded. It does not prove a `run.id` is searchable. `DEGRADED` is not a pass.

## Warning before a destructive reset

`docker compose … down -v` deletes lab volumes. That includes `splunk_app_agentsec`, `ollama_models`, and `shared_telemetry`, and anonymous volumes attached to the containers. Indexed Splunk events and a downloaded model on those volumes are removed. It does not delete the git checkout. Run it only when that loss is acceptable.

## Shutdown (soft)

```bash
./scripts/lab-down.sh
```

Stops containers. `scripts/lab-down.sh` says indexed Splunk data and named volumes remain. Those named volumes include `splunk_app_agentsec`, `ollama_models`, and `shared_telemetry`. Host `artifacts/` is not removed. Images are not deleted.

**Next start:** `./scripts/lab-up.sh` (no `--build` unless source/images must rebuild).

Splunk app XML in the named volume is **not** deleted. Images are **not** deleted.

## Reset levels

| Level | What it does | Command |
|-------|----------------|---------|
| SOFT RESET | Restart without destroying evidence | `./scripts/lab-down.sh` then `./scripts/lab-up.sh` |
| IMAGE SYNC | Rebuild AcmeBank + Attack Service from git | `./scripts/lab-up.sh --build` |
| APP RESTAGE | Copy `splunk_app/agentsec` into volume + restart Splunk + HEC init | `./scripts/lab-up.sh --refresh-app` |
| LAB RESET (runtime memory) | In-process memory is lost on AcmeBank recreate | restart/recreate `acmebank` via compose / `--build` |
| FULL RESET | Destroy compose volumes (Splunk index, models, app volume) | **explicit** `docker compose -f docker-compose.yml -f docker-compose.local.yml --profile local --env-file .env down -v` then `./scripts/lab-up.sh` |

FULL RESET is destructive. It is never the default. It does **not** delete git history or `docs/` official run.ids.

Host `artifacts/` and `docs/screenshots/` are **not** removed by `lab-down.sh`.

## Diagnostics

```bash
./scripts/lab-preflight.sh
./scripts/lab-ready.sh
docker ps --filter name=agentsec_
curl -sS -o /dev/null -w "%{http_code}\n" http://127.0.0.1:5001/health
curl -sS -o /dev/null -w "%{http_code}\n" http://127.0.0.1:5000/health
curl -sS -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8000/en-US/account/login
curl -sS -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8088/services/collector/health/1.0
```

Schema on events: field `agentsec.schema.version` = `1.9.0`. Product version ≠ schema.

Logs: `docker compose -f docker-compose.yml -f docker-compose.local.yml --profile local --env-file .env logs --tail=80 attack_service acmebank otel_collector splunk`

run.id lookup: Splunk Search with quoted `agentsec.run.id`. Attack Service GET `/api/launches/<run_id>` is operator/debug, not the learner syllabus.
