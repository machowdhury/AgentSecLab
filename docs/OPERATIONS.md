# Operations: start, stop, reset, diagnostics

Canonical start: `./scripts/lab-up.sh` from the repository root (`.env` required).

## What READY means

`./scripts/lab-ready.sh` exit 0 = **SERVICE HEALTH**. It does not prove evidence searchability.

## Shutdown (soft)

```bash
./scripts/lab-down.sh
```

Stops containers. **Persists:** Docker volumes (`splunk_app_agentsec`, Splunk indexed data inside the Splunk volume if compose defines one — Splunk data lives in the container/volume set compose uses), `ollama_models`, `shared_telemetry`, named app volume, host `artifacts/`.

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
