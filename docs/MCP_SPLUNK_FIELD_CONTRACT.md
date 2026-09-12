# MCP Splunk field contract

**Lab:** LAB-MCP-001  
**Schema:** `agentsec.security_event` **1.1.0**  
**Date:** 2026-09-12  
**Evidence class:** **OBSERVED** (`fieldsummary` + `mvcount` on live `index=agentsec_telemetry`, `sourcetype=otel:agentic:json`)  
**Specimen:** BASELINE `163d11e2-e751-4282-9406-19b490542ed4` (7 events); confirmed on ATTACK/RETEST/ERROR/fail paths.

Do not assume field extraction shape. Collapse scalars with `mvindex(mvdedup('field'),0)` before `stats count by`.

---

## Indexed representation (actual names)

| Conceptual | Indexed Splunk field | On BASELINE MCP | Notes |
|------------|----------------------|-----------------|-------|
| run.id | `agentsec.run.id` | yes | `mvcount=3`; same UUID as incident |
| incident.id | `agentsec.incident.id` | yes | equals `agentsec.run.id` |
| trace_id | `trace_id` | yes | `mvcount=3`; not `agentsec.trace_id` |
| sequence | `agentsec.sequence` | yes | `mvcount=2` (JSON+KV, not OTLP attr) |
| event.name | `event.name` | yes | **not** `agentsec.event.name`; `mvcount=3` |
| gen_ai.agent.id | `gen_ai.agent.id` | yes | `acme-agent-mcp-001` on hop events |
| gen_ai.tool.name | `gen_ai.tool.name` | yes | control + mcp.* ; absent on run.started |
| gen_ai.operation.name | `gen_ai.operation.name` | yes | `execute_tool` on mcp.* |
| mcp.method.name | `mcp.method.name` | yes | `tools/call` on control + mcp.* |
| service.name | `service.name` | yes | `acmebank`; `mvcount=3` |
| agentsec.security.profile | `agentsec.security.profile` | yes | |
| agentsec.testbed.mode | `agentsec.testbed.mode` | yes | `mvcount=3` |
| agentsec.control.id | `agentsec.control.id` | yes | `CTRL-MCP-001` on control only |
| agentsec.control.decision | `agentsec.control.decision` | yes | ALLOW / DENY / ERROR |
| agentsec.control.reason | `agentsec.control.reason` | yes | |
| agentsec.operation.attempted | `agentsec.operation.attempted` | yes | strings `"true"`/`"false"` |
| agentsec.operation.executed | `agentsec.operation.executed` | yes | control `false`; mcp.* `true` |
| agentsec.operation.outcome | `agentsec.operation.outcome` | yes | omitted on ALLOW control and mcp.started |
| agentsec.mcp.requested_scope | `agentsec.mcp.requested_scope` | yes | control only |
| agentsec.mcp.allowed_scope | `agentsec.mcp.allowed_scope` | yes | coded `policy:read`; control only |
| agentsec.principal.id | `agentsec.principal.id` | yes | also `user.id` |
| agentsec.delegator.agent.id | **absent** | no | omitted on MCP hop 0; `fieldsummary` did not return the name |

Also present when emitted: `agentsec.mcp.result.trust=untrusted_data`, `agentsec.mcp.result.provenance=mcp.tool.handler` on `mcp.completed` only; `agentsec.content.preview` / `agentsec.content.hash` on control (request) and `mcp.completed` (result).

Booleans in `_raw` are JSON `true`/`false`. Splunk tokens are the strings `"true"` / `"false"`.

---

## Not indexed / not used

| Name | Status |
|------|--------|
| `agentsec.event.name` | not a field; use `event.name` |
| `session.id` / `mcp.session.id` | not emitted |
| `gen_ai.tool.call.arguments` | not emitted; use preview/hash |
| `mcp.protocol.version` | not emitted |
| `agentsec.mcp.server.id` | not emitted; use `service.name` |
| `agentsec.mcp.tool.name` | not emitted; use `gen_ai.tool.name` |

---

## Multivalue duplication (same as Phase 2C.1)

Classification: **B** (one event, repeated identical copies) from **C** (INDEXED_EXTRACTIONS=json + KV_MODE=json, plus OTLP log attributes on some keys). **A** (physical duplicate events) ruled out: `dc(_raw)` equals local `events.jsonl` count.

On BASELINE MCP, every event had `mvcount('agentsec.run.id')=3`, `mvcount('event.name')=3`, `mvcount('service.name')=3`, `mvcount('trace_id')=3`. `fieldsummary` `values[].count` for `agentsec.run.id` was 21 on 7 events (7×3).

Normalize with `mvindex(mvdedup('field'),0)`. Keep `agentsec.invariant.id{}` as the true array. This slice did not change `props.conf`.

---

## Schema version

Indexed `agentsec.schema.version=1.1.0` on these MCP runs. Loan historical catalogs remain 1.0.0 against previously validated loan runs.
