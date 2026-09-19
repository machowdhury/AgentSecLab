# Phase 2C.1 SPL validation

**Date:** 2026-09-11  
**Checkpoint:** `phase-2b-splunk-transport-complete` (`4e03ced`)  
**Lab:** LAB-PI-001 Direct Prompt Injection  
**Schema:** `agentsec.security_event` 1.0.0 — unchanged  
**Scope:** Four investigation searches, actually executed against live Splunk. No dashboards. No detections. No schema changes.

Evidence class: **OBSERVED** (Splunk CLI). Completeness of these two run IDs vs local `events.jsonl` was **MEASURED** in Phase 2B. These searches were not a new attack experiment.

## Splunk environment

| Item | Value |
|------|--------|
| Index | `agentsec_telemetry` |
| Sourcetype | `otel:agentic:json` |
| Source | `agentsec-otel-collector` |
| Splunk | `splunk/splunk:10.2` container `agentsec_splunk` |
| Execution | `splunk search` CLI inside the container as user `splunk`, `-output csv` |
| App macro | `` `agentsec_index` `` exists; validated SPL uses explicit index/sourcetype so CLI works without app context |
| CLI note | hostname validation warning on `cliVerifyServerName`; searches still returned CSV |

Replace `__RUN_ID__` with a concrete UUID before running stored `.spl` files.

## Tested run IDs

| Role | run.id | Local events | Splunk `stats count` | Splunk `dc(_raw)` |
|------|--------|--------------|----------------------|-------------------|
| BASELINE | `b3611d56-0d3f-4b2e-9a51-75ae36628155` | 22 | 22 | 22 |
| Defended ATK-002 | `78f05d1b-728e-4e70-8993-f5e365871f87` | 6 | 6 | 6 |

Phase 2B live transport runs. Completeness already MEASURED. Not replayed as new experiments. Not Phase 2A packs (`3367455f-…`, `9bdb542c-…`).

BASELINE runtime (authoritative): 4 ALLOW, 4 real LLM invocations, terminal `completed_allowed`.  
Defended ATK-002 runtime (authoritative): CTRL-INPUT-001 DENY, `attempted=false`, `executed=false`, `outcome=prevented`, zero `llm.*` locally.

## Field discovery (OBSERVED)

`fieldsummary maxvals=8` on both run IDs, filtered to the contract names plus conceptual aliases.

### Present (indexed)

`event.name`, `agentsec.run.id`, `agentsec.incident.id`, `agentsec.sequence`, `agentsec.schema.version`, `agentsec.security.profile`, `agentsec.testbed.mode`, `agentsec.execution.mode`, `agentsec.telemetry.fidelity`, `agentsec.control.id`, `agentsec.control.decision`, `agentsec.operation.attempted`, `agentsec.operation.executed`, `agentsec.operation.outcome`, `agentsec.outcome`, `gen_ai.agent.id`, `gen_ai.agent.name`, `gen_ai.operation.name`, `trace_id`, `span_id`, `parent_span_id`, `agentsec.invariant.id{}`.

Sample values (BASELINE unless noted):

| Field | Sample |
|-------|--------|
| `event.name` | `agentsec.control.decision`, `agentsec.llm.started`, `agentsec.run.completed`, … |
| `agentsec.security.profile` | `defended` |
| `agentsec.testbed.mode` | `BASELINE` / ATK `ATTACK` |
| `agentsec.execution.mode` | `LIVE` |
| `agentsec.telemetry.fidelity` | `OBSERVED` |
| `agentsec.schema.version` | `1.0.0` |
| `agentsec.control.id` | `CTRL-INPUT-001` |
| `agentsec.control.decision` | `ALLOW` / ATK `DENY` |
| `agentsec.operation.outcome` | BASELINE llm `success`; ATK control `prevented` |
| `agentsec.outcome` | `hop_allowed`, `completed_allowed` / ATK `hop_denied`, `completed_denied` |
| `gen_ai.operation.name` | BASELINE `chat`; ATK field present in summary with count 0 |
| `agentsec.invariant.id{}` | BASELINE `INV-004`,`INV-007`,`INV-002`; ATK `INV-008`,`INV-007` |

Booleans in `_raw` are JSON `true`/`false`. Splunk field tokens are the strings `"true"` / `"false"`.

### Discrepancies vs a conceptual field list

`fieldsummary` did **not** return these names on either run:

| Conceptual / requested | Indexed? | Use this instead |
|------------------------|----------|------------------|
| `agentsec.event.name` | **no** | `event.name` |
| `agentsec.profile` | **no** | `agentsec.security.profile` |
| `agentsec.pipeline.outcome` | **no** | `agentsec.outcome` |
| `agentsec.invariant.id` (scalar) | **no** as a scalar Splunk field | mv field `agentsec.invariant.id{}` (JSON array in `_raw`) |

### Count inflation: 22→66 and 6→18 (OBSERVED)

This is **not** duplicate indexed events. Phase 2B completeness stands.

Classification: **B** (one event, repeated identical multivalue field copies), produced by **C** (overlapping Splunk extraction paths). **A** (physical duplicate events) is ruled out.

| Run | `stats count` | `dc(_raw)` | `dc(sequence)` | `mvcount('agentsec.run.id')` | `mvcount(mvdedup('agentsec.run.id'))` | `stats count by "agentsec.run.id"` | after `eval run_id=mvindex(mvdedup('agentsec.run.id'),0)` |
|-----|---------------|------------|----------------|------------------------------|---------------------------------------|--------------------------------------|----------------------------------------------------------|
| BASELINE | 22 | 22 | 22 | **3** on every event | **1** | 66 | **22** |
| ATK-002 | 6 | 6 | 6 | **3** on every event | **1** | 18 | **6** |

`rex` on `_raw` found the JSON key `agentsec.run.id` **once** per event. The extracted field is three identical UUID strings (newline-separated in CSV). `_raw` is not a JSON array of three run IDs.

`stats count by` explodes each multivalue copy into a row: 22×3=66, 6×3=18.

Cause of the three copies (measured by comparing fields):

| Field | In JSON `_raw` | Also OTLP log attribute (`telemetry.py`) | Observed `mvcount` | `stats count by` on BASELINE |
|-------|----------------|------------------------------------------|--------------------|------------------------------|
| `agentsec.sequence` | yes | no | 2 | 44 |
| `agentsec.schema.version` | yes | no | 2 | 44 |
| `agentsec.incident.id` | yes | no | 2 | (not required) |
| `agentsec.security.profile` | yes | no | 2 | 44 |
| `agentsec.run.id` | yes | yes | 3 | 66 |
| `agentsec.testbed.mode` | yes | yes | 3 | 66 |
| `event.name` | yes | yes | 3 | (not required) |

Two copies exist on **every** JSON scalar because `props.conf` for `otel:agentic:json` sets both `INDEXED_EXTRACTIONS = json` and `KV_MODE = json` (indexed JSON plus search-time JSON from the same `_raw`). A **third** copy appears only on keys that the OTLP sink also sends as log attributes (`agentsec.run.id`, `agentsec.testbed.mode`, `event.name`, and optionally control/agent fields).

Validated SPL still collapses scalars with `mvindex(mvdedup('field.name'),0)` so investigation tables count events, not field copies. Keep `agentsec.invariant.id{}` as the true schema multivalue array.

Do not treat 66/18 as a completeness failure. Unique `_raw` and unique `agentsec.sequence` remain 22 and 6.

## Query IDs and results

Stored under `learning/level_1/LAB-PI-001/searches/`. Re-executed 2026-09-11 against live Splunk (CLI CSV). Empty CSV = zero result rows, not a CLI failure.

| Query ID | Expected | Actual | Status |
|----------|----------|--------|--------|
| Q-RUN-EVENTS | BASE 22 ordered events, terminal `completed_allowed`; ATK 6 DENY path, terminal `completed_denied` | 22 rows seq 1–22; 6 rows seq 1–6 | **VALIDATED** |
| Q-CONTROL-DECISION | 4 ALLOW; 1 DENY prevented | 4 ALLOW hops 0–3; 1 DENY hop 0 `prevented` | **VALIDATED** |
| Q-LLM-EXECUTED | 8 llm rows on BASE; 0 on ATK | 8 rows; table 0 rows and `llm_events=0` | **VALIDATED** |
| Q-LLM-AFTER-DENY | 0 violations on both honest runs | empty CSV both | **VALIDATED** |

### Q-LLM-AFTER-DENY interpretation

Zero rows on the defended run means: in this **complete Splunk copy**, no pre-invocation DENY was followed by `llm.started` / `llm.completed` / `llm.failed` on the same hop. That is a telemetry-contract check.

It does **not** independently prove runtime non-execution. Runtime `events.jsonl` / LLM client evidence remains authoritative. Splunk `llm.*` absence alone is not prevention proof.

BASELINE also returned zero rows because it has no DENY (nothing to violate).

### Q-LLM-AFTER-DENY positive control (SIMULATED)

Test source: `learning/level_1/LAB-PI-001/searches/Q-LLM-AFTER-DENY-POSITIVE-CONTROL.spl` — Splunk `| makeresults` only. Not indexed. Not written to `artifacts/`. Not an AcmeBank run.

Two synthetic events, same `run.id` `simulated-q-llm-after-deny-0001`, same `hop.index=0`: DENY at sequence 3, then `agentsec.llm.started` at sequence 4. Then the same violation block as `Q-LLM-AFTER-DENY.spl`.

| | |
|--|--|
| Expected | exactly one violation row |
| Actual | one row: `deny_seq=3`, `sequence=4`, `event_name=agentsec.llm.started`, `evidence_class=SIMULATED` |
| Index leak check | `stats count` for that synthetic `run.id` in `index=agentsec_telemetry` = **0** |
| Evidence class | **SIMULATED** |
| Status | **VALIDATED** |

This is not OBSERVED runtime behavior. It only proves the violation logic can return a row when the invalid sequence is present.

## Pytest (search-file contracts only)

Command:

```text
.venv/bin/python -m pytest tests/unit tests/integration tests/security tests/telemetry tests/splunk -q --tb=line
```

**Result:** **60 passed, 1 skipped, 0 failed**. Skip is opt-in live Splunk ingest (`AGENTSEC_LIVE_SPLUNK=1`), not these searches. These tests do **not** execute SPL; live Splunk execution is this document.

## Known limitations

- Q-LLM-AFTER-DENY positive control is SIMULATED (`makeresults`); it is not a runtime DENY-then-invoke failure.
- `earliest=0` is lab-only.
- Collector file exporter is not part of proof (Phase 2B).
- `INDEXED_EXTRACTIONS=json` plus `KV_MODE=json` plus overlapping OTLP attributes make scalar fields multivalue. Investigation SPL must collapse copies. This slice did not change `props.conf`.
- Unit tests check search files only.
- Splunk CLI prints a certificate hostname-validation warning; it did not prevent CSV output.

## Files

- `learning/level_1/LAB-PI-001/searches/*.spl`
- `learning/level_1/LAB-PI-001/searches/*.md`
- `learning/level_1/LAB-PI-001/searches/catalog.json`
- `docs/learning-notes/spl-validation.md`
- `tests/splunk/test_lab_pi_001_search_contracts.py`
