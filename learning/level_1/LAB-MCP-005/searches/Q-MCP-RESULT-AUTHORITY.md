# Q-MCP-RESULT-AUTHORITY

| Item | Value |
|------|--------|
| Query ID | `Q-MCP-RESULT-AUTHORITY` |
| Security question | Did result-derived data influence authorization state, and what follow-on decision and execution were indexed? |
| Validation status | **VALIDATED** (live Splunk CLI, 2026-09-13, schema 1.3.0 MCP-005 specimens) |
| Validation date | 2026-09-13 |
| SPL file | `Q-MCP-RESULT-AUTHORITY.spl` |
| Lab | LAB-MCP-005 |

Existing Q-MCP-RESULT-TRUST answers **classification** (`untrusted_data` on `mcp.completed`). It does **not** ask whether a result became authority. Q-MCP-AUTHZ shows RESULT-001 and follow-on CTRL-MCP-001 rows, but does not collapse one run into server-owned vs derived vs follow-on execution.

This hunt is the MCP-005 INV-002 reconstruction. It is **not** a detector.

## Required fields (indexed names)

`event.name`, `agentsec.run.id`, `gen_ai.tool.name`, `agentsec.control.id`, `agentsec.control.decision`, `agentsec.control.reason`, `agentsec.mcp.requested_scope`, `agentsec.mcp.allowed_scope`, `agentsec.hop.index`, `agentsec.security.profile`, `agentsec.testbed.mode`, `agentsec.content.preview`

There is **no** indexed `agentsec.mcp.allowed_tools`. Server-owned tools appear only in the hop-1 CTRL-MCP-001 bounded preview (`server_owned_allowed_tools`).

## SPL

See `Q-MCP-RESULT-AUTHORITY.spl`. Bind `__RUN_ID__`.

## Line-by-line explanation

1. Scope `index=agentsec_telemetry sourcetype=otel:agentic:json` and one `agentsec.run.id`. Include control, `mcp.started`, `mcp.completed`, and `mcp.failed`.
2. Collapse INDEXED_EXTRACTIONS+KV_MODE duplicate copies with `mvindex(mvdedup(…),0)`.
3. Identify RESULT-001 (`control.id=CTRL-MCP-RESULT-001`) for result-trust decision/reason.
4. Identify hop `0` CTRL-MCP-001 as the initial grant check (`allowed_scope` is the coded server-owned **scope**).
5. Identify hop `1` CTRL-MCP-001 as the follow-on: tool, requested vs coded allowed scope, decision, reason, bounded preview.
6. Observe hop `1` `mcp.started` / `mcp.completed` without claiming the handler never ran.
7. `derived_authority=present` only when RESULT-001 reason contains `result_derived_grant`. OBSERVE `result_is_data` is **absent**. Do not infer presence from follow-on ALLOW alone.
8. Keep one row per `run.id`. Runs without RESULT-001 (for example initial handler failure) return **zero rows**.

## Expected result

| Specimen | derived_authority | RESULT-001 | follow-on | execution observation |
|----------|-------------------|------------|-----------|------------------------|
| A BASELINE | absent | OBSERVE `result_is_data` | none | `no_followon` |
| B ATTACK | present | ALLOW `…:result_derived_grant` | `lookup_customer_tier` ALLOW same reason | `mcp.completed_observed` |
| C RETEST | absent | OBSERVE `result_is_data` | `lookup_customer_tier` DENY `tool_not_granted` | `no_indexed_followon_execution_event` |
| F handler fail | *(no row)* | no RESULT-001 | — | hunt 0 rows |

ATTACK must **not** look like server policy granted `lookup_customer_tier`. Coded `allowed_scope` stays `policy:read`. Preview still contains `server_owned_allowed_tools": "lookup_policy"`.

## Actual result

**VALIDATED** (Splunk CLI CSV). See `docs/MCP005_SPLUNK_VALIDATION.md`.

| Spec | derived_authority | Notes |
|------|-------------------|-------|
| A | `absent` | `no_followon`; OBSERVE is not DENY |
| B | `present` | follow-on ALLOW + `mcp.completed_observed`; coded allowed_scope still `policy:read`; preview includes `server_owned_allowed_tools": "lookup_policy"` (tool name truncated at 200 chars) |
| C | `absent` | follow-on DENY `tool_not_granted`; `no_indexed_followon_execution_event`; preview `authority_source": "server-owned"` |
| F | 0 rows | initial `mcp.failed`; RESULT-001 never emitted |
| MCP-004 A (still indexed) | 0 rows | no RESULT-001; hunt does not classify old labs as result-derived failures |

## Validated run.id / test data

A `3013aa39-fe08-4b58-9898-f3abb092ac06`, B `f3f48182-df57-4b38-b069-17a199dc4939`, C `0ab10594-a7fc-48b6-81bf-4cbca54a64c6`, F `6fe7370c-a288-4634-91a5-d6c78b52bd01`.

## Performance notes

Index + sourcetype + run.id + four event names + `eventstats` by `run_id` + `dedup`. No `join`, `transaction`, `map`, `append`, or subsearch. `earliest=0` is lab-only.

## Known limitations

- No first-class `allowed_tools` field. Server-owned **tools** are corroborated by hop-1 preview, not by a grant array.
- `server_owned_allowed_scope` is coded **scope** (`policy:read`), not the tool allow-list.
- ATTACK hop-1 preview is bounded at 200 characters; `lookup_customer_tier` may be truncated while `server_owned_allowed_tools": "lookup_policy"` remains visible.
- `derived_authority` is a **display helper** from RESULT-001 reason, not a detector.
- Zero rows means this copy has no RESULT-001 for that `run.id`. That is not “safe,” not DENY, and not proof the handler never ran.
- `followon_execution_observation=no_indexed_followon_execution_event` is Splunk corroboration. Authoritative non-execution remains the runtime handler count.

## No-data semantics

Zero rows: no indexed `CTRL-MCP-RESULT-001` for this `run.id` (wrong id, export loss, or a run that never completed the first tool). That is **not** blocked, **not** “no attack,” and **not** proof derived authority was refused.

On RETEST, missing hop-1 `mcp.started` is corroborating evidence only. Do not write “handler definitely never ran” from Splunk alone.
