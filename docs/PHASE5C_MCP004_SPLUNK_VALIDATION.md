# Phase 5C — MCP-004 Splunk transport and resource authorization validation

**Date:** 2026-09-12  
**Schema:** `agentsec.security_event` **1.2.0**  
**Lab:** LAB-MCP-004 specimens; reuse LAB-MCP-001 Q-MCP / DET-MCP-001; one new hunt `Q-MCP-RESOURCE-AUTHZ`  
**Scope:** Fresh LIVE OTLP → collector → HEC → Splunk; field discovery; existing Q-MCP revalidation; resource hunt; DET-MCP-001 compatibility. **No** Dashboard Studio. **No** DET-MCP-004. **No** MCP-005. Authorization model and schema 1.2.0 **unchanged** in this phase.

Evidence class: **OBSERVED** (runtime + Splunk CLI). Completeness vs local `events.jsonl`: **MEASURED**. Resource teaching fixture: **SIMULATED**. Phase 5B local-only run IDs are **not** Splunk proof.

Runtime remains authoritative for handler invocation. Splunk is corroboration.

---

## Schema 1.2.0 SPL compatibility

Inspected all `learning/level_1/LAB-MCP-001/searches/Q-MCP-*.spl` and `DET-MCP-001.spl`.

**None** hardcode `schema.version=1.1.0` or otherwise exclude 1.2.0. Searches filter `index`, `sourcetype`, `agentsec.run.id`, and `event.name`.

`learning/level_1/LAB-MCP-001/searches/catalog.json` has `"schema.version": "1.1.0"`. That is **documentation metadata** for previously validated LAB-MCP-001 Splunk runs. It is **not** an SPL predicate. Left unchanged. Do not confuse catalog labels with search filters.

Existing Q-MCP files were **not rewritten**.

---

## Splunk environment

| Item | Value |
|------|--------|
| Index | `agentsec_telemetry` |
| Sourcetype | `otel:agentic:json` |
| Source | `agentsec-otel-collector` |
| Splunk | container `agentsec_splunk` |
| Execution | `splunk search` CLI as user `splunk`, `-output csv` |
| Auth | password stays inside the container (`admin:${SPLUNK_PASSWORD}`). Not passed on the host argv. |
| Lab | `./scripts/lab-up.sh --build` READY; AcmeBank image rebuilt with 5B runtime |

Specimens ran in-container Python with OTEL on (`scripts/run_lab_mcp_004_live_specimens.py` copied to `/tmp`; image does not copy `scripts/`). Profile switched in-process (`AGENTSEC_SECURITY_PROFILE`) so the HTTP container stayed defended. `export.json` has `otlp.ok=true` and `splunk.verified=false` (honest). Splunk proof is this document’s independent CLI.

---

## Fresh run IDs

Do not reuse Phase 5B local-only IDs.

| Spec | Profile | Mode | policy_id | Runtime (authoritative) | Handler | `run.id` |
|------|---------|------|-----------|-------------------------|--------:|----------|
| **A BASELINE** | defended | BASELINE | `lending-basics` | ALLOW `tool_granted`; `mcp.completed` | **1** | `fb50dcaf-8e84-4a3f-a55b-997c72edbd04` |
| **B ATTACK** | vulnerable | ATTACK | `executive-restricted` | ALLOW `vulnerable_profile_fail_open:resource_not_granted`; `mcp.completed` | **1** | `5ab59fc7-303e-4eea-84e7-ae0b2f405146` |
| **C RETEST** | defended | RETEST | `executive-restricted` | DENY `resource_not_granted`; no `mcp.started` | **0** | `0726a0ff-a551-41a8-bfbb-ab2ceca4c0dd` |
| **D unknown resource** | defended | ATTACK | `does-not-exist` | ERROR `unknown_resource`; no `mcp.started` | **0** | `0e4e0051-528d-4bf3-8773-d1fb55a5864f` |
| **E malformed args** | defended | ATTACK | *(missing)* | ERROR `malformed_arguments`; no `mcp.started` | **0** | `9ea63448-bf6a-4619-b313-b152f4d94bb6` |
| **F handler fail** | defended | BASELINE | `lending-basics` | ALLOW then `mcp.failed` | **1** | `ccd13a5f-0c4f-4447-84da-e0bbb1184585` |
| **G duplicate JSON keys** | defended | ATTACK | n/a | schema ERROR `duplicate_json_keys`; **no control event** | **0** | `ffafb62e-a6c6-42c0-837d-094cbfb3f795` |

Tool: `lookup_policy`. Scope: `policy:read` (constant). Method: `tools/call`. `agentsec.attack.id=MCP-004`. Schema **1.2.0**. Coded grant `allowed_resource.ids=lending-basics` on every control event that performed a resource check (including E, which has no `resource.id`).

---

## Transport completeness

| Layer | Status | Class |
|-------|--------|--------|
| Runtime in-container invoke | Decisions and handler counts as table above | OBSERVED in `manifest.json` |
| Local `events.jsonl` | 7 / 7 / 6 / 6 / 6 / 8 / 2 | MEASURED |
| OTLP SDK | `otlp.ok=true` all seven packs | OBSERVED in `export.json` |
| HEC → index | `lab-ready.sh` READY; HEC health HTTP 200 | OBSERVED |
| Splunk `dc(_raw)` | equals local count for every run.id | MEASURED |

| Spec | Local | Splunk | Sequences / names | Terminal | Control | MCP exec | Class |
|------|------:|-------:|-------------------|----------|---------|----------|--------|
| A | 7 | 7 | 1–7 match | `run.completed` | ALLOW seq 3 | started 4, completed 5 | **COMPLETE** |
| B | 7 | 7 | 1–7 match | `run.completed` | fail-open ALLOW seq 3 | started 4, completed 5 | **COMPLETE** |
| C | 6 | 6 | 1–6 match | `run.completed` (`completed_denied`) | DENY seq 3 | **none** | **COMPLETE** |
| D | 6 | 6 | 1–6 match | `run.failed` | ERROR seq 3 | none | **COMPLETE** |
| E | 6 | 6 | 1–6 match | `run.failed` | ERROR seq 3 | none | **COMPLETE** |
| F | 8 | 8 | 1–8 match | `run.failed` | ALLOW seq 3 | started 4, **failed** 5 | **COMPLETE** |
| G | 2 | 2 | 1–2 match | `run.failed` | **none** | none | **COMPLETE** |

No specimen is PARTIAL / FAILED / NOT VERIFIED for this transport. Missing `mcp.started` on C/D/E/G is **not** inferred solely from Splunk; local handler counts are 0.

Traces (OBSERVED, one per run): A `11fdb2c85d9635413df04ce9f9b35acb`; B `a43a68be1a2c8a87f30afa80c4e250a0`; C `8c26ae71caad0358e825f4b138d85769`; D `537067cb5a997999293293b3f3f488f4`; E `4f36d6e9a11dccc2664fbb2ac00ddad8`; F `bd8c7747c90e9ebbb2c654e686c34637`; G `7adc8a0ef886d9b4ab66f2abbdb0d59d`.

---

## Field discovery

See `docs/MCP004_SPLUNK_FIELD_VALIDATION.md`. Same 2C.1 / 3C / 4C multivalue duplication. Collapse with `mvindex(mvdedup('field'),0)`. Completeness uses `dc(_raw)`. **Do not change `props.conf`.**

`agentsec.mcp.allowed_resource.ids` is a **comma-sorted scalar string** (`lending-basics`) that appears as Multivalue only because of duplicate extraction (`mvcount=2`, `mvdedup=1`). It is **not** a JSON array of grants. Do not treat `mvcount=2` as two allowed resources.

---

## Q-MCP-RESOURCE-AUTHZ decision

**Created.** One search. Existing searches cannot answer “requested resource vs coded grant vs decision” using structured fields:

- Q-MCP-SCOPE on B is `granted` (scope still `policy:read`).
- Q-MCP-PARAMS shows preview/hash of the argument blob; that is provenance, not the authorization object.

File: `learning/level_1/LAB-MCP-004/searches/Q-MCP-RESOURCE-AUTHZ.spl`.

`resource_relation` (display helper):

| Label | Rule |
|-------|------|
| `not_a_grant` | `decision=ERROR` (unknown_resource **or** malformed) |
| `known_but_ungranted` | reason contains `resource_not_granted` (DENY **or** fail-open ALLOW) |
| `granted` | `ALLOW` and collapsed `resource.id` equals collapsed `allowed_resource.ids` |

ERROR is evaluated first so `does-not-exist` is not `known_but_ungranted`. Grant comparison alone cannot distinguish unknown vs ungranted.

---

## Reused Q-MCP results (schema 1.2.0)

All seven existing searches **VALIDATED** against A–F (and G where applicable). Files unchanged.

### Q-MCP-WHO

**VALIDATED.** A/C/E/F defended; B vulnerable; D defended ATTACK. Principal `applicant-web`, agent `acme-agent-mcp-001`, tool `lookup_policy`, method `tools/call`. G: **0 rows** (no control event).

### Q-MCP-AUTHZ

**VALIDATED.** DENY and ERROR stay distinct tokens.

| Spec | decision | reason |
|------|----------|--------|
| A | ALLOW | `tool_granted` |
| B | ALLOW | `vulnerable_profile_fail_open:resource_not_granted` |
| C | DENY | `resource_not_granted` |
| D | ERROR | `unknown_resource` |
| E | ERROR | `malformed_arguments` |
| F | ALLOW | `tool_granted` |
| G | *(no row)* | schema `duplicate_json_keys` on `run.failed` |

Control `executed=false` on ALLOW is expected.

### Q-MCP-SCOPE

**VALIDATED** and **not sufficient for MCP-004**. A/B/F: `granted`. C: `denied_without_scope_mismatch` (scope still matches; DENY is **resource**). D/E: `not_a_grant`. This is why a resource hunt exists.

### Q-MCP-PARAMS

**VALIDATED.** Preview + hash only. Full `gen_ai.tool.call.arguments` **absent** (`has_args=0` on A control). Preview is **not** the resource-authorization hunt.

### Q-MCP-TOOL

| Spec | Rows |
|------|------|
| A / B / F | 1 `mcp.started` seq 4 `executed=true` |
| C / D / E / G | **0** |

Zero TOOL rows does not prove DENY.

### Q-MCP-EXECUTED

| Spec | execution_state |
|------|-----------------|
| A | `mcp.completed` |
| B | `mcp.completed` |
| C / D / E | `no_mcp_execution_event` |
| F | `mcp.failed` |
| G | no control row |

Preserve: ALLOW ≠ execution; `mcp.started` ≠ success; `mcp.failed` ≠ prevention.

### Q-MCP-AFTER-DENY

**VALIDATED:** 0 rows on A–G. RETEST C is DENY without later MCP events.

---

## Q-MCP-RESOURCE-AUTHZ result

**VALIDATED** (live CLI on the files above).

| Spec | resource_id | allowed_resource.ids | relation |
|------|-------------|----------------------|----------|
| A | `lending-basics` | `lending-basics` | `granted` |
| B | `executive-restricted` | `lending-basics` | `known_but_ungranted` |
| C | `executive-restricted` | `lending-basics` | `known_but_ungranted` |
| D | `does-not-exist` | `lending-basics` | `not_a_grant` |
| E | *(empty)* | `lending-basics` | `not_a_grant` |
| F | `lending-basics` | `lending-basics` | `granted` |
| G | — | — | 0 rows |

B must not be reported as resource granted. Grant stayed `lending-basics`.

---

## DET-MCP-001 live reuse

Existing `DET-MCP-001.spl` **not modified**. Saved search **not modified**. No DET-MCP-004.

Live CLI scoped with `"agentsec.run.id"=…` (AND at the CLI, file unchanged):

| Spec | Rows |
|------|-----:|
| A BASELINE | 0 |
| B ATTACK | 0 |
| C RETEST | 0 |
| D UNKNOWN | 0 |
| E MALFORMED | 0 |
| F HANDLER FAILURE | 0 |
| G duplicate keys | 0 |

RETEST contains DENY but no later `mcp.started`. ATTACK is ALLOW fail-open, so it is not a DENY→execution invariant.

---

## SIMULATED resource positive control

File: `DET-MCP-001-RESOURCE-POSITIVE-CONTROL.spl`. `makeresults` only. Not indexed.

Teaching shape: DENY `resource_not_granted`, `resource.id=executive-restricted`, `allowed_resource.ids=lending-basics`, then later `mcp.started`, same run/tool. Violation block shares DET-MCP-001 core.

Live CLI: **1** row, `deny_sequence=3`, `mcp_start_sequence=4`, `evidence_class=SIMULATED`. Indexed count for `simulated-det-mcp-001-resource-0001` = **0**.

---

## Duplicate-key telemetry

G uses the same `run_mcp_schema_failure(error_reason=duplicate_json_keys)` path as `POST /mcp/invoke` HTTP parse. Indexed: `run.started` + `run.failed` (`error.type=duplicate_json_keys`). **No** `agentsec.control.decision`. Do not fabricate CTRL-MCP-001 evidence. Q-MCP-WHO / AUTHZ / RESOURCE-AUTHZ return 0 rows. Handler count 0 at runtime.

---

## Detector correlation limitation

DET-MCP-001 correlates `run_id` + `tool`. Canonical MCP-004 issues **one** `lookup_policy` per run, so live 0-row results are valid.

A future flow with two `lookup_policy` calls in one run (e.g. `lending-basics` then `executive-restricted`) could mis-correlate. Future options: `invocation.id`, `tool_call.id`, or another per-invocation key. **Not invented in 5C.**

---

## No-data semantics

These no-data rules are unchanged from Phase 3C / 4C.

| Observation | Means | Does not mean |
|-------------|-------|----------------|
| 0 `mcp.started` rows | No indexed start | Handler never ran (runtime count is authoritative) |
| 0 DET-MCP-001 rows | No indexed DENY→execution violation | All resource authorization succeeded; handler never ran; system is secure |
| 0 Q-MCP-RESOURCE-AUTHZ rows | No indexed control event | Authorization outcome (could be G / loss / wrong id) |
| 0 Q-MCP-TOOL rows | No indexed start | DENY |

---

## Performance notes

Index, sourcetype, run.id, event.name, `eval`, `stats`/`eventstats`, `table`, `mvindex(mvdedup(…),0)`. No `join`, `transaction`, `map`, `append`. `earliest=0` is lab-only.

An earlier RESOURCE-AUTHZ draft used `split(..., ",")` / `mvfilter`; the CLI quoting of `","` produced empty CSV. Membership uses collapsed-string equality, which matches the **observed** single-grant indexed shape.

---

## Pytest (search-file contracts only)

Command:

```text
.venv/bin/python -m pytest tests -q --tb=line -m "not live_ollama and not live_splunk"
```

These tests do **not** execute SPL. Live Splunk execution is this document.

**Result:** **227 passed**, 2 deselected (`live_ollama`, `live_splunk`).

---

## Files changed

- `learning/level_1/LAB-MCP-004/searches/Q-MCP-RESOURCE-AUTHZ.spl` / `.md` / `catalog.json`
- `learning/level_1/LAB-MCP-004/searches/DET-MCP-001-RESOURCE-POSITIVE-CONTROL.spl` / `.md`
- `scripts/run_lab_mcp_004_live_specimens.py`
- `tests/splunk/test_lab_mcp_004_splunk.py`
- `docs/PHASE5C_MCP004_SPLUNK_VALIDATION.md`
- `docs/MCP004_SPLUNK_FIELD_VALIDATION.md`
- `docs/learning-notes/mcp-resource-splunk.md`
- `docs/IMPLEMENTATION_STATUS.md`
- `docs/MCP004_EVENT_MODEL_REVIEW.md`
- `docs/MCP_SEARCH_CONTRACT.md`

Unchanged: `DET-MCP-001.spl`, `savedsearches.conf`, schema 1.2.0, authorization code, Dashboard Studio XML, Q-MCP-*.spl.

---

## Limitations

- In-process JSON-RPC, not remote MCP transport.
- `export.json` still records `splunk.verified=false`. Independent CLI is the proof.
- In-container invoke (image does not copy `scripts/`).
- Resource teaching fixture is SIMULATED.
- No Dashboard Studio for MCP-004. No DET-MCP-004. No MCP-005.
- Q-MCP-SCOPE on resource DENY shows `denied_without_scope_mismatch` by design.

---

## Phase 5C verdict

**VALIDATED** for fresh LIVE MCP-004 transport completeness, schema 1.2.0 compatibility of existing Q-MCP / DET-MCP-001 searches, and one new hunt `Q-MCP-RESOURCE-AUTHZ`. Dashboard Studio **NOT ATTEMPTED**. DET-MCP-004 **not created**. MCP-005 **not started**.
