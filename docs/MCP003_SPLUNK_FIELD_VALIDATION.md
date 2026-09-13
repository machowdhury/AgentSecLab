# MCP-003 Splunk field validation

**Lab:** LAB-MCP-003 live specimens (Phase 4C)  
**Schema:** `agentsec.security_event` **1.1.0**  
**Date:** 2026-09-12  
**Evidence class:** **OBSERVED** (`mvcount` + collapsed `mvindex(mvdedup(…),0)` values on live `index=agentsec_telemetry`, `sourcetype=otel:agentic:json`)  
**Control-event specimen:** BASELINE A `5b089682-1d5a-49a7-ac43-967265fd6bc6` sequence 3; values confirmed on B–F control events.

Do not assume extraction shape. Collapse scalars before `stats count by`. Completeness uses `dc(_raw)`, not `stats count` on a duplicated field.

Phase 2C.1 / 3C multivalue duplication is **OBSERVED** again. Classification: **B** (one event, repeated identical copies) from **C** (INDEXED_EXTRACTIONS=json + KV_MODE=json, plus OTLP log attributes on some keys). **A** (physical duplicate events) ruled out: `dc(_raw)` equals local `events.jsonl` count.

---

## Indexed representation (actual names)

Measured on the BASELINE control event unless noted. `mvcount` is **before** any `eval` that overwrites the same field name.

| Field | Present | Collapsed value (A control) | `mvcount` | Notes |
|-------|---------|-----------------------------|----------:|-------|
| `agentsec.run.id` | yes | `5b089682-1d5a-49a7-ac43-967265fd6bc6` | 3 | hunt key |
| `agentsec.incident.id` | yes | same UUID as run.id | 2 | |
| `trace_id` | yes | `2e897dd47d72254bf8e9095b5d26ba1f` | 3 | not `agentsec.trace_id` |
| `agentsec.sequence` | yes | `3` | 2 | |
| `event.name` | yes | `agentsec.control.decision` | 3 | **not** `agentsec.event.name` |
| `gen_ai.agent.id` | yes | `acme-agent-mcp-001` | 3 | |
| `gen_ai.tool.name` | yes | `lookup_policy` | 2 | |
| `mcp.method.name` | yes | `tools/call` | 2 | |
| `agentsec.security.profile` | yes | `defended` | 2 | B: `vulnerable` |
| `agentsec.testbed.mode` | yes | `BASELINE` | 3 | B ATTACK; C RETEST |
| `agentsec.attack.id` | yes | `MCP-003` | 2 | additive 1.1.0 enum |
| `agentsec.control.id` | yes | `CTRL-MCP-001` | 2 | |
| `agentsec.control.decision` | yes | `ALLOW` | 3 | C `DENY`; D/E `ERROR` |
| `agentsec.control.reason` | yes | `tool_granted` | 2 | |
| `agentsec.mcp.requested_scope` | yes | `policy:read` | 2 | control event |
| `agentsec.mcp.allowed_scope` | yes | `policy:read` | 2 | coded grant; not rewritten |
| `agentsec.operation.attempted` | yes | `"false"` | 2 | JSON boolean → Splunk string |
| `agentsec.operation.executed` | yes | `"false"` | 2 | control row; mcp.started is `"true"` |
| `agentsec.operation.outcome` | omitted on ALLOW | empty | (absent) | C/D/E: `prevented` `mvcount=2` |
| `agentsec.schema.version` | yes | `1.1.0` | 2 | not bumped |

B control (collapsed): decision `ALLOW`, reason `vulnerable_profile_fail_open:scope_not_granted`, requested `policy:restricted:read`, allowed `policy:read`, profile `vulnerable`, mode `ATTACK`.

C control: `DENY` / `scope_not_granted` / requested `policy:restricted:read` / allowed `policy:read` / outcome `prevented`.

D control: `ERROR` / `unknown_scope` / requested `policy:write` / allowed `policy:read`.

E control: `ERROR` / `missing_requested_scope` / requested `unspecified` / allowed `policy:read`.

F control: ALLOW `tool_granted` matching scopes (handler later `mcp.failed`).

---

## What is not a new indexed field

| Name | Status |
|------|--------|
| `effective_scope` | not emitted (by design) |
| `scope_relation` | SPL display helper only |
| `agentsec.event.name` | not a field; use `event.name` |
| `session.id` | not emitted |

---

## Eval overwrite pitfall

If SPL does `eval trace_id=mvindex(mvdedup('trace_id'),0)` and then `mvcount('trace_id')`, the count becomes 1. That is not evidence the indexed field was a scalar. Measure `mvcount` on the original extracted field.

---

## Schema version

Indexed `agentsec.schema.version=1.1.0` on these MCP-003 runs. No 1.2.0.
