# Phase 3C — LAB-MCP-001 Splunk transport and SPL validation

**Date:** 2026-09-12  
**Schema:** `agentsec.security_event` **1.1.0**  
**Lab:** LAB-MCP-001  
**Scope:** Fresh LIVE OTLP → collector → HEC → Splunk; field discovery; Q-MCP investigation searches executed. **No** Dashboard Studio. **No** detections. **No** MCP-003+. **No** Cisco. Authorization model unchanged.

Evidence class: **OBSERVED** (HTTP/runtime + Splunk CLI). Completeness vs local `events.jsonl`: **MEASURED**. Positive control: **SIMULATED**.

Runtime remains authoritative. Splunk is corroboration.

---

## Splunk environment

| Item | Value |
|------|--------|
| Index | `agentsec_telemetry` |
| Sourcetype | `otel:agentic:json` |
| Source | `agentsec-otel-collector` |
| Splunk | `splunk/splunk:10.2` container `agentsec_splunk` |
| Execution | `splunk search` CLI as user `splunk`, `-output csv` |
| CLI note | hostname validation warning on `cliVerifyServerName`; searches still returned CSV |

AcmeBank image was rebuilt so `POST /mcp/invoke` existed on `:5000`. Profile/mode switches used compose recreate (`AGENTSEC_SECURITY_PROFILE`, `AGENTSEC_TESTBED_MODE`). Handler-failure specimen F ran in-container with OTEL enabled (HTTP has no boom handler).

---

## Fresh run IDs

| ID | Profile | Mode | Tool | Runtime (authoritative) | `run.id` |
|----|---------|------|------|-------------------------|----------|
| **A BASELINE** | defended | BASELINE | `lookup_policy` | ALLOW, handler=1, `mcp.completed` | `163d11e2-e751-4282-9406-19b490542ed4` |
| **B ATTACK** | vulnerable | ATTACK | `lookup_customer_tier` | labeled fail-open ALLOW, handler=1, `mcp.completed` | `5e8f55f3-eb46-47ee-b979-b72d9c9b1f49` |
| **C RETEST** | defended | RETEST | `lookup_customer_tier` | DENY `tool_not_granted`, handler=**0**, no `mcp.started` | `7a1d37b5-d589-4dfd-8322-25ebd0152dbc` |
| **D** | defended | ATTACK | `unknown_tool_xyz` | ERROR `unknown_tool`, handler=0 | `2e804c0d-eb86-405a-ab8d-360616df0ef9` |
| **E** | defended | BASELINE | `lookup_policy` extra arg | ERROR `malformed_arguments`, handler=0 | `f2ef017e-d66c-4712-bacd-07138a30d2e6` |
| **E-HTTP** | defended | BASELINE | arguments not an object | schema ERROR, **no hops / no control event** | `a701403a-d146-4473-b7cf-881c1fa92229` |
| **F** | defended | BASELINE | `lookup_policy` boom handler | ALLOW then `mcp.failed`, handler=1, `executed=true`, `outcome=error` | `5b83b6e4-f8c4-4989-8ef5-b76614b49ca5` |

Old loan run IDs were **not** reused. Each `export.json` has `otlp.ok=true` and `splunk.verified=false` (honest). Splunk proof is this document’s independent search.

---

## Transport result

| Layer | Status | Class |
|-------|--------|--------|
| Runtime HTTP / in-container invoke | Decisions and handler counts as table above | OBSERVED |
| Local `events.jsonl` | Sequences complete (7 / 7 / 6 / 6 / 6 / 2 / 8) | MEASURED |
| OTLP SDK | `otlp.ok=true` all seven packs | OBSERVED in `export.json` |
| HEC → index | `source=agentsec-otel-collector` | OBSERVED via Splunk |
| Splunk `dc(_raw)` | equals local count for every run.id | MEASURED |

`otlp.ok` was not treated as Splunk success.

---

## Field discovery

See `docs/MCP_SPLUNK_FIELD_CONTRACT.md`.

Summary: use `event.name` (not `agentsec.event.name`); `trace_id` (not a namespaced alias); `agentsec.run.id` = `agentsec.incident.id`; `gen_ai.tool.name`; `mcp.method.name=tools/call`; `gen_ai.operation.name=execute_tool`; scopes on **control** events; `agentsec.delegator.agent.id` **absent** on hop 0; booleans as strings `"true"`/`"false"`.

Multivalue duplication **OBSERVED** (`mvcount=3` on `agentsec.run.id`, `event.name`, `service.name`, `trace_id`). Same 2C.1 mechanism. SPL collapses copies. Completeness uses `dc(_raw)`, not `stats count by field`.

---

## Count / correlation

Compared: local count, Splunk `dc(_raw)`, sequences 1..N, event names, single `trace_id`, terminal event, control decision, MCP execution events. RETEST non-execution: runtime handler count = 0 (authoritative); Splunk has no `mcp.*` on a **complete** copy.

| Spec | Local | Splunk | Sequences / names | Terminal | Control | MCP exec | Class |
|------|------:|-------:|-------------------|----------|---------|----------|--------|
| A | 7 | 7 | 1–7 match | `run.completed` `completed_allowed` | ALLOW seq 3 | started 4, completed 5 | **COMPLETE** |
| B | 7 | 7 | 1–7 match | `completed_allowed` | fail-open ALLOW seq 3 | started 4, completed 5 | **COMPLETE** |
| C | 6 | 6 | 1–6 match | `completed_denied` | DENY seq 3 | **none** | **COMPLETE** |
| D | 6 | 6 | 1–6 match | `run.failed` | ERROR seq 3 | none | **COMPLETE** |
| E | 6 | 6 | 1–6 match | `run.failed` | ERROR seq 3 | none | **COMPLETE** |
| E-HTTP | 2 | 2 | started + failed | `run.failed` | **none** | none | **COMPLETE** |
| F | 8 | 8 | 1–8 match | `run.failed` | ALLOW seq 3 | started 4, **failed** 5 | **COMPLETE** |

No specimen is PARTIAL / FAILED / NOT VERIFIED for this transport. Missing `mcp.started` on C is **not** inferred solely from Splunk; local handler count is 0.

Traces (OBSERVED): A `a8e1943cabd647ec083905b5970d8eae`; B `ad5657f7f4ce7438dd1600066150fcc6`; C `34c886049d50f569963b31c12550ea11`; D `89954cc0f8f8d8186c3ade0fff987ac9`; E `0b2b885c631f32a06a703b915c4c38ef`; E-HTTP `5e78fb81b1a9e99a82f41b21be4fee59`; F `96e0c936b51f93265601e9caeed0fbd3`.

---

## Q-MCP results (live Splunk CLI)

Empty CSV = zero result rows, not a CLI failure. Full line-by-line docs: `learning/level_1/LAB-MCP-001/searches/`.

| Query ID | Expected | Actual | Status |
|----------|----------|--------|--------|
| **Q-MCP-WHO** | A/B/C identity + tool + `tools/call` | A `lookup_policy` defended BASELINE; B `lookup_customer_tier` vulnerable ATTACK; C same tool defended RETEST | **VALIDATED** |
| **Q-MCP-AUTHZ** | Distinguish ALLOW / DENY / ERROR | A ALLOW; B labeled ALLOW; C DENY; D ERROR `unknown_tool`; E ERROR `malformed_arguments`; F ALLOW | **VALIDATED** |
| **Q-MCP-TOOL** | `mcp.started` only when handler began | A/B/F 1 row seq 4 `executed=true`; C/D/E 0 rows | **VALIDATED** |
| **Q-MCP-SCOPE** | granted vs known-ungranted | A `granted`; B/C requested `customer:read` allowed `policy:read` `known_but_ungranted` | **VALIDATED** |
| **Q-MCP-PARAMS** | preview+hash, not `gen_ai.tool.call.arguments` | Control-event preview/hash present; HTTP malformed 0 rows | **VALIDATED** |
| **Q-MCP-EXECUTED** | completed vs failed vs none | A/B `mcp.completed`; F `mcp.failed`; C/D/E `no_mcp_execution_event` | **VALIDATED** |
| **Q-MCP-AFTER-DENY** | 0 on real specimens | empty CSV on A–F | **VALIDATED** |
| **Q-MCP-AFTER-DENY-POSITIVE-CONTROL** | 1 SIMULATED row | 1 row seq 4 `mcp.started`; index count for synthetic id = 0 | **VALIDATED** (SIMULATED) |
| **Q-MCP-RESULT** | completed metadata; failed has no result body | A/B preview+`untrusted_data`; F `mcp.failed` empty result cols | **VALIDATED** |
| **Q-MCP-RESULT-TRUST** | `untrusted_data` on completed | A/B one row; F/C/D/E empty | **VALIDATED** |

HTTP schema malformed (`a701403a-…`): WHO/AUTHZ/SCOPE/PARAMS/EXECUTED = 0 because authorize never ran. That is schema-before-control, not DENY.

---

## SPL performance notes

All live queries: index + sourcetype + quoted `agentsec.run.id` + `event.name` filters. Collapse with `mvindex(mvdedup(…),0)`. EXECUTED and AFTER-DENY use `eventstats` over one run. No `join`, `transaction`, `map`, `append`, or subsearch. `earliest=0` is lab-only.

---

## No-data semantics

| Query = 0 | Means | Does not mean |
|-----------|-------|----------------|
| Q-MCP-AFTER-DENY | No indexed DENY-then-mcp sequence | Handler never ran (need runtime spy / complete local copy) |
| Q-MCP-TOOL | No indexed `mcp.started` | Automatically DENY (could be ERROR, schema fail, or loss) |
| Q-MCP-WHO / AUTHZ | No control event | DENY |
| Q-MCP-RESULT-TRUST | No completed result | Content was trusted |

---

## Pytest (search-file contracts only)

Command:

```text
.venv/bin/python -m pytest tests -q --tb=line -m "not live_ollama and not live_splunk"
```

**Result:** **115 passed**, 2 deselected (`live_ollama`, `live_splunk`). These tests do **not** execute SPL. Live Splunk execution is this document.

---

## Known limitations

- Positive control is SIMULATED (`makeresults`).
- `agentsec.delegator.agent.id` is not indexed on this lab’s hop 0.
- Arguments/results are preview (200 chars) + hash, not dedicated structured maps.
- `Q-MCP-EXECUTED` `executed` column is the **control** flag (`false`); use `execution_state`.
- Unknown-tool `error_stage` in the HTTP body can read `schema_validation` (authorize labels unknown tools that way). Decision remains ERROR, not DENY. Not treated as an authorization-model defect.
- F was generated in-process inside AcmeBank (same OTEL path), not via HTTP.
- No Dashboard Studio, detections, MCP-003, or Cisco.

---

## Files

- `learning/level_1/LAB-MCP-001/searches/*`
- `docs/MCP_SPLUNK_FIELD_CONTRACT.md`
- `docs/MCP_SEARCH_CONTRACT.md`
- `docs/learning-notes/mcp-splunk-investigation.md`
- `tests/splunk/test_lab_mcp_001_search_contracts.py`
- `docs/IMPLEMENTATION_STATUS.md`

## Phase 3C verdict

**VALIDATED** for transport completeness and Q-MCP investigation SPL on these fresh LIVE specimens. Dashboard Studio **NOT ATTEMPTED**. Detections **NOT ATTEMPTED**. MCP-003 **NOT STARTED**.
