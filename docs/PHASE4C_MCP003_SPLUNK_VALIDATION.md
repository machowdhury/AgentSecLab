# Phase 4C — MCP-003 Splunk transport and SPL validation

**Date:** 2026-09-12  
**Schema:** `agentsec.security_event` **1.1.0** — unchanged  
**Lab:** LAB-MCP-003 specimens on the LAB-MCP-001 Q-MCP / DET-MCP-001 contract  
**Scope:** Fresh LIVE OTLP → collector → HEC → Splunk; field discovery; reuse of existing Q-MCP searches. **No** new MCP-003 Dashboard Studio. **No** DET-MCP-003. **No** MCP-004. Authorization model unchanged.

Evidence class: **OBSERVED** (runtime + Splunk CLI). Completeness vs local `events.jsonl`: **MEASURED**. Scope teaching fixture: **SIMULATED**. Phase 4B local-only run IDs are **not** Splunk proof.

Runtime remains authoritative for handler invocation. Splunk is corroboration.

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
| CLI note | hostname validation warning on `cliVerifyServerName`; searches still returned CSV |

AcmeBank was rebuilt so MCP-003 runtime was in the image. An earlier LIVE batch reached collector debug but **did not index** (HEC connection reset / refused). Splunk was restarted, `splunk_hec_init` recreated, collector restarted, `lab-ready.sh` READY, HEC health HTTP 200. Pre-restore run IDs were discarded. These specimens were generated **after** HEC restore.

Profile/mode switches used compose recreate (`AGENTSEC_SECURITY_PROFILE`, `AGENTSEC_TESTBED_MODE`). Specimens ran in-container Python with OTEL on (`scripts/run_lab_mcp_003_live_specimens.py` copied to `/tmp`; image does not copy `scripts/`). AcmeBank restored to defended / auto after the batch.

---

## Fresh run IDs

Do not reuse Phase 4B local-only IDs. `export.json` has `otlp.ok=true` and `splunk.verified=false` (honest). Splunk proof is this document’s independent CLI.

| Spec | Profile | Mode | requested_scope | Runtime (authoritative) | Handler | `run.id` |
|------|---------|------|-----------------|-------------------------|--------:|----------|
| **A BASELINE** | defended | BASELINE | `policy:read` | ALLOW `tool_granted`; `mcp.completed` | **1** | `5b089682-1d5a-49a7-ac43-967265fd6bc6` |
| **B ATTACK** | vulnerable | ATTACK | `policy:restricted:read` | ALLOW `vulnerable_profile_fail_open:scope_not_granted`; `mcp.completed` | **1** | `b466ad12-72ec-44b7-be28-aacfaf2c25b1` |
| **C RETEST** | defended | RETEST | `policy:restricted:read` | DENY `scope_not_granted`; no `mcp.started` | **0** | `f638fd4f-1c4f-4ab6-8d42-4d03a4f3afd5` |
| **D unknown_scope** | defended | ATTACK | `policy:write` | ERROR `unknown_scope`; no `mcp.started` | **0** | `6ce19813-6cb5-4aae-a3a0-aa59386a82dd` |
| **E missing scope** | defended | ATTACK | `"   "` → indexed `unspecified` | ERROR `missing_requested_scope`; no `mcp.started` | **0** | `3b8b3ac4-227d-4aa9-9d6f-4245a300bf57` |
| **F handler fail** | defended | BASELINE | `policy:read` | ALLOW then `mcp.failed` | **1** | `c19a4f15-7e94-44f6-b498-238234b0b082` |

Allowed scope on every control event: coded `policy:read` (not rewritten). Tool: `lookup_policy`. Method: `tools/call`. `agentsec.attack.id=MCP-003`. Schema 1.1.0.

---

## Transport result

| Layer | Status | Class |
|-------|--------|--------|
| Runtime in-container invoke | Decisions and handler counts as table above | OBSERVED in `manifest.json` |
| Local `events.jsonl` | 7 / 7 / 6 / 6 / 6 / 8 | MEASURED |
| OTLP SDK | `otlp.ok=true` all six packs | OBSERVED in `export.json` |
| HEC → index | after restore; `lab-ready.sh` READY | OBSERVED |
| Splunk `dc(_raw)` | equals local count for every run.id | MEASURED |

| Spec | Local | Splunk | Sequences / names | Terminal | Control | MCP exec | Class |
|------|------:|-------:|-------------------|----------|---------|----------|--------|
| A | 7 | 7 | 1–7 match | `run.completed` `completed_allowed` | ALLOW seq 3 | started 4, completed 5 | **COMPLETE** |
| B | 7 | 7 | 1–7 match | `completed_allowed` | fail-open ALLOW seq 3 | started 4, completed 5 | **COMPLETE** |
| C | 6 | 6 | 1–6 match | `completed_denied` | DENY seq 3 | **none** | **COMPLETE** |
| D | 6 | 6 | 1–6 match | `run.failed` | ERROR seq 3 | none | **COMPLETE** |
| E | 6 | 6 | 1–6 match | `run.failed` | ERROR seq 3 | none | **COMPLETE** |
| F | 8 | 8 | 1–8 match | `run.failed` | ALLOW seq 3 | started 4, **failed** 5 | **COMPLETE** |

No specimen is PARTIAL / FAILED / NOT VERIFIED for this transport. Missing `mcp.started` on C/D/E is **not** inferred solely from Splunk; local handler counts are 0 / 0 / 0.

Traces (OBSERVED, one per run): A `2e897dd47d72254bf8e9095b5d26ba1f`; B `f2a6895448f622b394f634b92f644fea`; C `039d2a2ecab277f0f9e1c450f06100db`; D `0338a9c32defeed6ee28af220351b6b7`; E `7a4ea6c7eb09e9f96fa259a5841dab7c`; F `9b063deb22d5db70a9af6664ce196b97`.

---

## Field discovery

See `docs/MCP003_SPLUNK_FIELD_VALIDATION.md`. Same 2C.1 / 3C multivalue duplication. Collapse with `mvindex(mvdedup('field'),0)`. Completeness uses `dc(_raw)`.

---

## Count / correlation result

Compared: local count, Splunk `dc(_raw)`, sequence numbers, event names, `trace_id`, terminal event, control decision, `requested_scope`, `allowed_scope`, MCP execution events. Runtime `mcp.handler.invoked.count` remains authoritative for non-execution.

---

## Reuse of existing Q-MCP searches

These existing searches already answer MCP-003. **No new duplicate Q-MCP IDs.**

| Query | Reuse | Doc files |
|-------|-------|-----------|
| Q-MCP-WHO | reused unchanged | `Q-MCP-WHO.md` unchanged |
| Q-MCP-AUTHZ | reused unchanged | `Q-MCP-AUTHZ.md` unchanged |
| Q-MCP-TOOL | reused unchanged | `Q-MCP-TOOL.md` unchanged |
| Q-MCP-EXECUTED | reused unchanged | `Q-MCP-EXECUTED.md` unchanged |
| Q-MCP-AFTER-DENY | reused unchanged | `Q-MCP-AFTER-DENY.md` unchanged |
| Q-MCP-SCOPE | **same query ID**; helper `case()` order corrected after documenting a contract gap | `Q-MCP-SCOPE.md` updated |

Q-MCP-PARAMS / RESULT / RESULT-TRUST were not required for this phase and were not re-executed as MCP-003 proof.

Existing LAB-MCP-001 dashboard `ds_q_scope` was kept in lockstep with `Q-MCP-SCOPE.spl` so the Studio binding test does not drift. That is **not** an MCP-003 Dashboard Studio build.

---

## Q-MCP-WHO

**VALIDATED.** A defended BASELINE `lookup_policy` `tools/call`. B vulnerable ATTACK. C defended RETEST. D/E defended ATTACK (edge). F defended BASELINE. Principal `applicant-web`, agent `acme-agent-mcp-001`.

---

## Q-MCP-AUTHZ

**VALIDATED.** DENY and ERROR stay distinct tokens.

| Spec | decision | reason | requested | allowed | executed (control) |
|------|----------|--------|-----------|---------|--------------------|
| A | ALLOW | `tool_granted` | `policy:read` | `policy:read` | false |
| B | ALLOW | `vulnerable_profile_fail_open:scope_not_granted` | `policy:restricted:read` | `policy:read` | false |
| C | DENY | `scope_not_granted` | `policy:restricted:read` | `policy:read` | false (`prevented`) |
| D | ERROR | `unknown_scope` | `policy:write` | `policy:read` | false (`prevented`) |
| E | ERROR | `missing_requested_scope` | `unspecified` | `policy:read` | false (`prevented`) |
| F | ALLOW | `tool_granted` | `policy:read` | `policy:read` | false |

Control `executed=false` on ALLOW is expected. Use Q-MCP-EXECUTED / runtime handler count for execution.

---

## Q-MCP-SCOPE

This is the key MCP-003 hunt. Same security question: requested vs coded allowed.

### Contract gap (MEASURED before SPL change)

Previous `case()` order:

`granted` (ALLOW+match) → `known_but_ungranted` (any mismatch) → `not_a_grant` (ERROR) → …

Live D (`policy:write` ERROR `unknown_scope`) and E (`unspecified` ERROR `missing_requested_scope`) therefore displayed `known_but_ungranted`. That silently treated ERROR as a grant-mismatch story. `Q-MCP-SCOPE.md` already said ERROR is `not_a_grant`.

### Correction

Same query ID. Evaluate `decision="ERROR"` → `not_a_grant` **first**. Not a new search. Not a reinterpretation of ERROR as DENY.

### After correction (MEASURED on the same indexed data)

| Spec | requested | allowed | decision | scope_relation |
|------|-----------|---------|----------|----------------|
| A | `policy:read` | `policy:read` | ALLOW | `granted` |
| B | `policy:restricted:read` | `policy:read` | ALLOW | `known_but_ungranted` |
| C | `policy:restricted:read` | `policy:read` | DENY | `known_but_ungranted` |
| D | `policy:write` | `policy:read` | ERROR | `not_a_grant` |
| E | `unspecified` | `policy:read` | ERROR | `not_a_grant` |
| F | `policy:read` | `policy:read` | ALLOW | `granted` |

A/B/C/F labels were unchanged by the helper-order fix.

Displayed relation for unknown catalog tokens: **`not_a_grant`**, with decision **ERROR**. Do not call this authorization DENY.

---

## Q-MCP-TOOL

**VALIDATED.**

| Spec | Rows |
|------|------|
| A | 1 `mcp.started` seq 4 `executed=true` |
| B | 1 `mcp.started` seq 4 `executed=true` |
| C | **0** |
| D | **0** |
| E | **0** |
| F | 1 `mcp.started` seq 4 `executed=true` |

Zero TOOL rows does not prove DENY (C is DENY; D/E are ERROR).

---

## Q-MCP-EXECUTED

**VALIDATED.** Preserve: ALLOW ≠ execution; `mcp.started` ≠ success; `mcp.failed` ≠ prevention.

| Spec | execution_state | has_started | has_completed | has_failed |
|------|-----------------|-------------|---------------|------------|
| A | `mcp.completed` | 1 | 1 | 0 |
| B | `mcp.completed` | 1 | 1 | 0 |
| C | `no_mcp_execution_event` | 0 | 0 | 0 |
| D | `no_mcp_execution_event` | 0 | 0 | 0 |
| E | `no_mcp_execution_event` | 0 | 0 | 0 |
| F | `mcp.failed` | 1 | 0 | 1 |

Control `executed` stays `false` on ALLOW rows. Use `execution_state`.

---

## Q-MCP-AFTER-DENY

Search **unchanged**. **VALIDATED:** 0 indexed invariant violations on A–F.

- RETEST C: DENY `scope_not_granted`, no later `mcp.started`.
- ATTACK B: ALLOW fail-open, therefore not a DET-MCP-001 condition.

---

## UNKNOWN_SCOPE result

Indexed control: tool `lookup_policy` granted, requested `policy:write` **not** in `valid_scopes`, `decision=ERROR`, `reason=unknown_scope`. Runtime handler **0**. Complete Splunk copy has **no** `mcp.started`. Q-MCP-AUTHZ shows ERROR, not DENY. Q-MCP-SCOPE shows `not_a_grant`.

---

## DET-MCP-001 reuse result

Existing `DET-MCP-001.spl` **not modified**. Saved search **not modified**.

Live CLI scoped with `"agentsec.run.id"=…` (AND at the CLI, file unchanged):

| Spec | Rows |
|------|-----:|
| A BASELINE | 0 |
| B ATTACK | 0 |
| C RETEST | 0 |
| D UNKNOWN SCOPE | 0 |
| E missing scope | 0 |
| F handler failure | 0 |

Reason: no DENY is followed by later `mcp.started`. MCP-003 does **not** require a redundant detector. Do not create DET-MCP-003.

---

## SIMULATED scope positive control

File: `DET-MCP-001-SCOPE-POSITIVE-CONTROL.spl`. `makeresults` only. Not indexed.

Teaching shape: DENY `scope_not_granted`, requested `policy:restricted:read`, allowed `policy:read`, then later `mcp.started`, same run/tool. Violation block shares DET-MCP-001 core.

Live CLI: **1** row, `deny_sequence=3`, `mcp_start_sequence=4`, `evidence_class=SIMULATED`. Indexed count for `simulated-det-mcp-001-scope-0001` = **0**.

---

## No-data semantics

These no-data rules are unchanged from Phase 3C.

| Observation | Means | Does not mean |
|-------------|-------|----------------|
| 0 Q-MCP-TOOL rows | No indexed `mcp.started` | DENY (could be ERROR, loss, or prevention) |
| 0 Q-MCP-AFTER-DENY rows | No indexed DENY-then-mcp sequence | Handler never ran |
| 0 DET-MCP-001 rows | No indexed invariant violation | Handler never ran |
| 0 Q-MCP-WHO / AUTHZ | No indexed control event | DENY |

Runtime invocation count remains authoritative.

---

## Performance notes

Existing efficient contract kept: index, sourcetype, `agentsec.run.id`, `event.name`, `stats` / `eventstats`, `fields` / `table`, `mvindex(mvdedup(…),0)`. No `join`, `transaction`, or `map`. Q-MCP-SCOPE helper-order change does not add commands. `earliest=0` is lab-only.

---

## Pytest (search-file contracts only)

Command:

```text
.venv/bin/python -m pytest tests -q --tb=line -m "not live_ollama and not live_splunk"
```

**Result:** **177 passed**, 2 deselected (`live_ollama`, `live_splunk`). These tests do **not** execute SPL. Live Splunk execution is this document.

---

## Files changed

- `learning/level_1/LAB-MCP-001/searches/Q-MCP-SCOPE.spl` (ERROR-first `scope_relation`)
- `learning/level_1/LAB-MCP-001/searches/Q-MCP-SCOPE.md`
- `learning/level_1/LAB-MCP-001/searches/DET-MCP-001-SCOPE-POSITIVE-CONTROL.spl` / `.md`
- `learning/level_1/LAB-MCP-001/searches/catalog.json` (`scope_teaching_fixture` only; query ID list unchanged)
- `learning/level_1/LAB-MCP-001/dashboard.definition.json` and `ws_lab_mcp_001.xml` (SCOPE helper string lockstep only)
- `tests/splunk/test_lab_mcp_003_splunk_reuse.py`
- `docs/PHASE4C_MCP003_SPLUNK_VALIDATION.md`
- `docs/MCP003_SPLUNK_FIELD_VALIDATION.md`
- `docs/learning-notes/mcp-scope-splunk.md`
- `docs/IMPLEMENTATION_STATUS.md`
- `docs/MCP003_EVENT_MODEL_REVIEW.md`
- `docs/MCP_SEARCH_CONTRACT.md` (MCP-003 reuse note)
- `scripts/splunk_cli_csv.py` (CLI helper; auth in container)
- `scripts/run_lab_mcp_003_live_specimens.py`

Unchanged: `DET-MCP-001.spl`, `savedsearches.conf`, schema 1.1.0, authorization code.

---

## Limitations

- First LIVE OTLP batch before HEC restore did not index. Those run IDs are not Splunk proof.
- `export.json` still records `splunk.verified=false`. Independent CLI is the proof.
- In-container invoke (image does not copy `scripts/`).
- Q-MCP-SCOPE helper correction changes ERROR labels only when requested ≠ allowed.
- Scope teaching fixture is SIMULATED.
- No Dashboard Studio for MCP-003. No DET-MCP-003. No MCP-004.
- `agentsec.delegator.agent.id` remains absent on hop 0.

---

## Phase 4C verdict

**VALIDATED** for fresh LIVE MCP-003 transport completeness and reuse of existing Q-MCP / DET-MCP-001 searches. One documented Q-MCP-SCOPE helper-order correction. No new detector. Dashboard Studio **NOT ATTEMPTED**. MCP-004 **NOT STARTED**.
