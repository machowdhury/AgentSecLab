# Why `agentsec.sequence` is duplicated in Splunk (investigation)

**Finding.** Nothing is duplicated at the producer. One event is one JSON document, indexed once (`dc(_raw)` equals the local event count, see `gate1/reconcile.json`). Splunk then exposes each field more than once, from three independent mechanisms:

| Copies | Fields (Loan Desk `control.decision` event, 64 fields) | Source of each copy |
|---|---|---|
| 2 | 37 body fields, including `agentsec.sequence` | (1) index-time `INDEXED_EXTRACTIONS = json` + (2) search-time `KV_MODE = json`, both set on `[otel:agentic:json]` in `splunk_app/agentsec/default/props.conf` |
| 3 | `agentsec.run.id`, `event.name`, `agentsec.control.decision`, `agentsec.testbed.mode`, `gen_ai.agent.id`, `trace_id`, `span_id`, `service.name`, `service.version`, `deployment.environment` | the two above + (3) OTLP log attributes, resource attributes and trace/span ids that the collector's `splunk_hec` exporter sends as HEC `fields` (index-time) |
| 1 | Splunk metadata (`host`, `source`, `index`, ...) and OTel SDK attributes | single source |

**Producer** (`OtlpSink` in `src/agentsec/telemetry.py`): body = the whole event as a JSON string; attributes = `event.name`, `agentsec.run.id`, `agentsec.testbed.mode`, `agentsec.control.decision`, `gen_ai.agent.id`, `sourcetype`. **Collector** (`config/otel-collector-config.yaml`): `resource` + `attributes` processors then `splunk_hec`; attributes/resource become HEC `fields`. **Splunk**: props as above. `tstats ... by agentsec.sequence` returns rows, which proves an index-time copy exists.

**Evidence** (`props_compat/`): `field_copies.json` (per-field copies for one event); `before.json`; with a temporary admin-user override `KV_MODE = none`, `agentsec.sequence` dropped from 2 copies to 1 while `run.id`/`span_id` dropped from 3 to 2, exactly as predicted. All 92 run-bound hunt executions (the repo's 23 run-bound `.spl` files x 4 runs) returned identical rows and normalized content before and after (`after_kvmode_none.json`, `summary.json`), 0 errors. The override was removed and the original behaviour verified restored.

**Why existing content is already safe.** The repo's hunts wrap fields in `mvindex(mvdedup(...),0)` (674 uses) because this duplication was documented earlier (`docs/SPLUNK_DATA_VALIDATION.md`, "Classification B"). Those wrappers are no-ops on single values.

**Decision: no telemetry or props change in this batch.** The run-bound hunts are compatible with `KV_MODE = none`, but 49 unbound hunts, the dashboards' own panels and the home/arena views were not exercised. Recommended follow-up, in this order, each with the same before/after harness (`scripts/spl_compat_check.py`):
1. `KV_MODE = none` on `[otel:agentic:json]` (removes copy 2; matches the scanner and external-evaluation stanzas that already do this).
2. Stop sending the six attributes that duplicate body fields (producer/collector change; removes copy 3). This changes the telemetry format and needs its own review.

**What a careless query gets wrong.** `count(agentsec.sequence)` counts values, so it returns exactly twice the events (68 for 34). The reconciliation counts events and de-duplicates values (`mvdedup`). New Loan Desk searches follow the same rule.
