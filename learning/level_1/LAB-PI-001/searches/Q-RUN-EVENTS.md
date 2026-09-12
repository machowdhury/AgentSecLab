# Q-RUN-EVENTS

| Item | Value |
|------|--------|
| Query ID | `Q-RUN-EVENTS` |
| Security question | What happened during one AgentSec run? |
| Validation status | **VALIDATED** |
| Validation date | 2026-09-11 |
| SPL file | `Q-RUN-EVENTS.spl` |
| Token | Replace `__RUN_ID__` with a concrete `agentsec.run.id` |

## Required fields (indexed names)

`event.name`, `agentsec.run.id`, `agentsec.incident.id`, `agentsec.sequence`, `agentsec.schema.version`, `agentsec.security.profile`, `agentsec.testbed.mode`, `agentsec.execution.mode`, `agentsec.telemetry.fidelity`, `agentsec.outcome`, `gen_ai.agent.id`, `trace_id`, `span_id`, `parent_span_id`

Do not use `agentsec.event.name`, `agentsec.profile`, or `agentsec.pipeline.outcome`.

## SPL

See `Q-RUN-EVENTS.spl`. Executed form used a concrete UUID in place of `__RUN_ID__`.

## Line-by-line explanation

1. Restrict to `index=agentsec_telemetry sourcetype=otel:agentic:json` (the Phase 2B indexed path).
2. Filter one run with `"agentsec.run.id"=…` (quoted dotted field).
3. `mvindex(mvdedup(…),0)` collapses duplicate JSON-body + OTLP-attribute copies of scalar fields. Without this, `stats count by` those fields inflates.
4. Rename `agentsec.outcome` to `pipeline_outcome` in the table only. That is the hop/run outcome field, not a schema field named `agentsec.pipeline.outcome`.
5. `sort sequence` uses the runtime sequence, not `_time`, as the event order.

## Expected result

- BASELINE: 22 rows, sequences 1–22, `incident_id=run_id`, `schema_version=1.0.0`, `testbed_mode=BASELINE`, `profile=defended`, four hops then `event_name=agentsec.run.completed` with `pipeline_outcome=completed_allowed`.
- Defended ATK-002: 6 rows, hop 0 DENY path, `pipeline.stopped`, `hop_denied`, `completed_denied`, no `llm.*`.

## Actual result

**VALIDATED** against Splunk CLI `-output csv` on 2026-09-11.

BASELINE `b3611d56-0d3f-4b2e-9a51-75ae36628155`: **22 rows**, sequences 1–22, names:

`run.started` → hop0 started/control/llm.started/llm.completed/hop.completed → hops 1–3 same → `run.completed` `completed_allowed`. `incident_id` equaled `run_id`. One `trace_id`.

Defended ATK-002 `78f05d1b-728e-4e70-8993-f5e365871f87`: **6 rows** — started, hop.started, control.decision, pipeline.stopped, hop.completed `hop_denied`, run.completed `completed_denied`.

## Validated run.id / test data

Phase 2B live ingest, completeness already MEASURED vs `events.jsonl`.

## False-positive / false-negative considerations

- FP: another run’s events if the UUID filter is omitted.
- FN: `stats count by "agentsec.run.id"` without `mvdedup` inflates (re-executed: 66 vs 22 BASELINE events). Use event rows or `dc(_raw)`.
- FN: searching `agentsec.event.name` returns nothing.

## Performance notes

Single-run UUID filter over `earliest=0` on a lab index. Cheap. Do not run unscoped `index=*` in workshops.

## Known limitations

`earliest=0` is a lab convenience. Production searches should bound time. Duplicate OTLP/JSON fields are a transport artifact, not extra events.
