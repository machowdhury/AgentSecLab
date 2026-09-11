# Splunk data validation

**Date:** 2026-09-11  
**Schema:** `agentsec.security_event` 1.0.0 — **unchanged**  
**Index:** `agentsec_telemetry`  
**Sourcetype:** `otel:agentic:json`  
**Source:** `agentsec-otel-collector`  
**Companion:** `docs/PHASE2B_TRANSPORT_VALIDATION.md`  
**Validated runs:** BASELINE `b3611d56-0d3f-4b2e-9a51-75ae36628155` (22 events); defended ATK-002 `78f05d1b-728e-4e70-8993-f5e365871f87` (6 events)

This document records **observed** Splunk representations. It does not contain Dashboard Studio or detection SPL. Runtime `export.json` still has `splunk.verified=false`; this file is the independent search record.

## Evidence classes

| Class | Use here |
|-------|----------|
| OBSERVED | Splunk CLI export of `_raw` / `fieldsummary` / indexed metadata |
| MEASURED | Local `events.jsonl` compared to parsed Splunk `_raw` |
| DOCUMENTED | Schema / `OtlpSink` / collector config |
| INFERRED | Not used for ingest success |
| SIMULATED / REPLAYED | Not used |

## Live `_raw`

**OBSERVED:** `_raw` is a single-line **JSON object**. `json.loads(_raw)` returns a `dict`. It is not a quoted/stringified JSON string. Indexed extractions (`KV_MODE=json` / `INDEXED_EXTRACTIONS=json` on `otel:agentic:json`) produced first-class fields.

Example envelope (BASELINE sequence 3 control.decision):

- `_time` = `2026-09-11 20:24:59.951 GMT`
- `index` = `agentsec_telemetry`
- `sourcetype` = `otel:agentic:json`
- `source` = `agentsec-otel-collector`

The OTLP body remains `json.dumps(entire event)` (JSON string on the wire). Splunk’s indexed `_raw` is the event object. **Carrier was not changed** because extraction succeeded.

## Field validation

Runtime field `event.name` is **not** named `agentsec.event.name`. Splunk has `event.name` only.

OTLP (DOCUMENTED, unchanged):

- Body: entire schema event as one JSON string
- Log attributes: `sourcetype`, `event.name`, `agentsec.run.id`, `agentsec.testbed.mode`, optional `agentsec.control.decision`, optional `gen_ai.agent.id`
- Resource: `service.name`, `service.version`, `deployment.environment` (collector also upserts `service.namespace=agentsec`)

| Field name | Runtime source | Event types | Native type | OTLP representation | Observed Splunk representation | Example | Nullable/optional | Validation status | Limitations |
|------------|----------------|-------------|-------------|---------------------|--------------------------------|---------|-------------------|-------------------|-------------|
| `agentsec.run.id` | server-minted UUID | all | string | body + log attribute | first-class field; 22/22 and 6/6 | `b3611d56-0d3f-4b2e-9a51-75ae36628155` | required | OBSERVED | fieldsummary count can exceed event count (body + attribute copies) |
| `event.name` | emitter | all | string | body + log attribute | first-class; 7 names on BASELINE | `agentsec.control.decision` | required | OBSERVED | there is no `agentsec.event.name` field |
| `agentsec.sequence` | monotonic int | all | int | body JSON number | first-class; 22 distinct values | `3` | required | OBSERVED / MEASURED 1..N | Splunk displays numeric tokens as strings in `fieldsummary` |
| `agentsec.schema.version` | constant | all | string | body | first-class `1.0.0` on all events | `1.0.0` | required | OBSERVED | |
| `agentsec.control.decision` | CTRL-INPUT-001 | `control.decision` | string | body; attribute when present | first-class ALLOW×4 / DENY×1 | `DENY` | omitted off control events | OBSERVED | |
| `agentsec.operation.attempted` | emitter | control + llm.* | bool | body JSON boolean | `_raw` boolean; Splunk field token `true`/`false` | `false` | those events | OBSERVED | Splunk does not keep a separate boolean type |
| `agentsec.operation.executed` | emitter | control + llm.* | bool | body JSON boolean | same as attempted | `false` | those events | OBSERVED | `true` means governed LLM call began |
| `agentsec.operation.outcome` | emitter | DENY/ERROR control; llm.completed/failed | string | body; **omitted on ALLOW control** | present `prevented` (DENY) / `success` (llm.completed); empty on ALLOW control | `prevented` | optional on ALLOW | OBSERVED | omission on ALLOW is correct |
| `gen_ai.agent.id` | hop identity | hop-scoped | string | body; attribute when present | first-class on hop events | `acme-agent-intake-001` | omitted on run-level | OBSERVED | |
| `trace_id` | run hex | all | string | body + OTLP trace_id | first-class; one value per run | `cf50c4d243ad188b8613ead0e17d5f26` | required | OBSERVED / MEASURED | |
| `span_id` | per event hex | all | string | body + OTLP span_id | first-class | `6a1fcad76e3ffec6` | required | OBSERVED | |
| `parent_span_id` | emitter | child events | string | body only | first-class when present | `da3ef8139eff053b` | omitted on `run.started` | OBSERVED | |
| `agentsec.invariant.id` | control emitter | `control.decision` | `list[str]` | JSON array in body | `_raw` JSON array; Splunk mv field `agentsec.invariant.id{}` | `["INV-004","INV-007"]` | required on control.decision | OBSERVED | **not** a stringified list. Search the mv field, not a single concatenated string |

## Completeness

MEASURED for both new runs against local `events.jsonl`. Same `run.id`, schema 1.0.0, counts, sequences, names-by-sequence, terminal event, `trace_id`, control decisions, llm started/completed presence/absence, operation flags.

## HEC / collector

- HEC **OBSERVED**: indexed events carry `source=agentsec-otel-collector`.
- Collector **OBSERVED**: debug `LogsExporter` record counts matched 22 and 6.
- File exporter **FAILED** (permission). Not used as completeness evidence. Removed from the logs pipeline afterward so a failed file write cannot fail the batch.

## Known limitations

- Runtime still must not set `splunk.verified`.
- Duplicate field copies from overlapping body JSON and OTLP attributes.
- `_time` is index/envelope time; sequence remains the ordering key for completeness.
- No production detection or dashboard validation.
