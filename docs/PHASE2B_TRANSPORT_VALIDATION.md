# Phase 2B transport validation

**Date:** 2026-09-11  
**AgentSec version:** 0.3.0  
**Schema:** `agentsec.security_event` 1.0.0 — **unchanged**  
**Scope:** OTLP → collector → HEC → Splunk indexed representation. No dashboards. No detections. No CTRL-INPUT-001 or pipeline semantic changes.

## Test results (executed)

```text
.venv/bin/python -m pytest tests/unit tests/integration tests/security tests/telemetry tests/splunk -q --tb=line
```

**Result (after live transport):** **53 passed, 1 skipped, 0 failed**

Phase 2A security tests did not regress. Live Splunk pytest remains opt-in (`AGENTSEC_LIVE_SPLUNK=1`) and was skipped.

## New live runs (do not reuse Phase 2A IDs)

| Experiment | `run.id` | Local events | Terminal | LLM calls |
|------------|----------|--------------|----------|-----------|
| BASELINE | `b3611d56-0d3f-4b2e-9a51-75ae36628155` | **22** | `completed_allowed` | 4 (OBSERVED live Ollama) |
| Defended ATK-002 | `78f05d1b-728e-4e70-8993-f5e365871f87` | **6** | `completed_denied` | 0 |

Phase 2A packs `3367455f-…` and `9bdb542c-…` were never exported and were not reused.

## Layer status

| Layer | Status | Evidence class |
|-------|--------|----------------|
| Runtime | Authoritative. BASELINE ALLOW×4 with LLM; ATK-002 DENY before invoke | OBSERVED (`result.json`, spy not used on live HTTP) |
| Local `events.jsonl` | 22 / 6 complete sequences | MEASURED |
| OTLP SDK | `otlp.attempted=true`, `otlp.flush_ok=true`, `otlp.ok=true` for both runs | OBSERVED in each `export.json` |
| Collector | Debug exporter logged 22 then 6 log records | OBSERVED in collector logs |
| Collector file archive | Failed (`/var/log/agentsec` then `/tmp` not writable in this image) | OBSERVED error; **not** used as proof |
| HEC | Indexed `source=agentsec-otel-collector` `sourcetype=otel:agentic:json` | OBSERVED via Splunk `tstats` / `eventcount` |
| Splunk verified by runtime | `splunk.verified=false` in `export.json` | OBSERVED (honest). Verification below is a **separate** search |

`otlp.ok` was **not** treated as Splunk success. Splunk verification is this document’s independent search.

## Observed `_raw` example (BASELINE control.decision sequence 3)

**OBSERVED** Splunk CLI CSV/JSON export (`index=agentsec_telemetry`):

| Field | Value |
|-------|--------|
| `index` | `agentsec_telemetry` |
| `sourcetype` | `otel:agentic:json` |
| `source` | `agentsec-otel-collector` |
| `_time` | `2026-09-11 20:24:59.951 GMT` |

`_raw` is a **JSON object** (not a quoted JSON string). `json.loads(_raw)` succeeded:

```json
{"timestamp":"2026-09-11T20:24:59Z","service.name":"acmebank","service.version":"0.3.0","deployment.environment":"lab","user.id":"applicant-web","trace_id":"cf50c4d243ad188b8613ead0e17d5f26","span_id":"6a1fcad76e3ffec6","agentsec.schema.name":"agentsec.security_event","agentsec.schema.version":"1.0.0","agentsec.run.id":"b3611d56-0d3f-4b2e-9a51-75ae36628155","agentsec.incident.id":"b3611d56-0d3f-4b2e-9a51-75ae36628155","agentsec.lab.id":"agentsec-local","agentsec.security.profile":"defended","agentsec.testbed.mode":"BASELINE","agentsec.execution.mode":"LIVE","agentsec.telemetry.fidelity":"OBSERVED","agentsec.sequence":3,"event.name":"agentsec.control.decision","agentsec.control.id":"CTRL-INPUT-001","agentsec.control.decision":"ALLOW","agentsec.invariant.id":["INV-004","INV-007"],"agentsec.operation.attempted":false,"agentsec.operation.executed":false,"gen_ai.agent.id":"acme-agent-intake-001"}
```

(Full `_raw` also includes content preview/hash and hop identity; truncated here only in this summary paragraph’s display of selected keys. The stored Splunk event is one JSON object.)

**Carrier was not changed.** The JSON-string OTLP body arrived as extractable JSON in Splunk.

## Completeness (BASELINE) — MEASURED

Local `artifacts/b3611d56-0d3f-4b2e-9a51-75ae36628155/events.jsonl` vs Splunk `_raw` parsed as JSON:

| Check | Result |
|-------|--------|
| same `run.id` | MATCH |
| schema `1.0.0` | MATCH |
| event count 22 = 22 | MATCH |
| sequences 1..22, no duplicate, no missing | MATCH |
| event names by sequence | MATCH |
| terminal `agentsec.run.completed` / `completed_allowed` | MATCH |
| single `trace_id` | MATCH `cf50c4d243ad188b8613ead0e17d5f26` |
| four `control.decision=ALLOW` (seq 3,8,13,18) | MATCH |
| four `llm.started` + four `llm.completed` | MATCH |
| ALLOW control omits `operation.outcome`; llm.completed has `success` | MATCH |

Event count alone was not used as proof.

## Defended ATK-002 — runtime authoritative, Splunk corroborates

Local (authoritative):

- CTRL-INPUT-001 `DENY`
- `operation.attempted=false`, `executed=false`, `outcome=prevented`
- `llm_call_count=0`, zero `llm.*` events
- `testbed.mode=ATTACK` (auto classification; not an env `RETEST` override)

Splunk for `78f05d1b-728e-4e70-8993-f5e365871f87` (MEASURED, 6 events, sequence match):

- `event.name=agentsec.control.decision`, `agentsec.control.id=CTRL-INPUT-001`, `decision=DENY`
- attempted/executed false, outcome `prevented`
- **no** `llm.*` in the complete exported set
- terminal `run.completed` / `completed_denied`

Splunk missing `llm.*` is **corroboration of a complete copy**, not independent prevention proof. Prevention is the runtime hop + local `events.jsonl`.

## Field validation

See `docs/SPLUNK_DATA_VALIDATION.md`. Required security fields were present as first-class Splunk fields. `agentsec.invariant.id` is a JSON **array** in `_raw` and a Splunk **multivalue** field (`agentsec.invariant.id{}` in `fieldsummary`). Not a stringified list.

## Stop conditions

| Condition | Result |
|-----------|--------|
| 1. `_raw` not extractable JSON | **did not trigger** — `_raw` is a JSON object |
| 2. required security fields lost | **did not trigger** |
| 3. sequence lost/duplicated | **did not trigger** |
| 4. arrays change semantics | **did not trigger** for `invariant.id` (array → mv) |
| 5. timestamps change event ordering | `_time` follows envelope/index time; names-by-sequence still matched. See limitations |
| 6. OTLP success indistinguishable from Splunk | **did not trigger** — `export.json` keeps Splunk false |
| 7. schema change necessary | **no** |
| 8. Phase 2A tests regress | **no** (53 passed) |

## Known limitations

- Official `splunk/splunk:10.2` is amd64-only. This lab used `platform: linux/amd64` (Rosetta).
- Read-only bind-mount of the app onto `/opt/splunk/etc/apps` makes ansible `chown` fail (EROFS). **Later local compose** stages a writable named volume instead of a manual copy (`docs/LOCAL_DOCKER_LAB.md`).
- Host Python 3.14 cannot import OTel 1.24/protobuf 4 (`Metaclasses with custom tp_new`). Live export used OpenTelemetry **1.44.0**.
- Collector **file** exporter could not write a logfile in this image. Debug + HEC still received the batches. File archive is not proof.
- Splunk `fieldsummary` shows some fields with extra copies (body JSON + OTLP attributes). `agentsec.run.id` appeared more than once per event.
- JSON booleans in `_raw` are native `true`/`false`; Splunk field values are the strings `true`/`false`.
- ATK-002 `export.json` `otlp.emit_count=28` is process-lifetime (22+6) from the long-running Flask process. Local event count for that run is **6**. Code now resets per-flush counters.
- Envelope `LogRecord` timestamp is emit-time, not necessarily `event["timestamp"]`. `_time` matched the live window (20:24–20:25 GMT).
- No dashboards, detections, or validated SPL beyond the investigative CLI used here.

## Deviations

- `SPLUNK_PLATFORM=linux/amd64`
- Splunk app installed via copy from `/tmp/agentsec-app` rather than `:ro` apps bind-mount (superseded for local compose by named volume `splunk_app_agentsec`)
- OpenTelemetry packages 1.24.0 → 1.44.0 (Python 3.14)
- Collector logs pipeline: HEC + debug (file exporter dropped after it failed)
- Splunk healthcheck `start_period` 600s (slow amd64 emulation first boot)
- ATK-002 `testbed.mode=ATTACK` (auto), not `RETEST`
