# MCP-004 Splunk field validation

**Lab:** LAB-MCP-004 live specimens (Phase 5C)  
**Schema:** `agentsec.security_event` **1.2.0**  
**Date:** 2026-09-12  
**Evidence class:** **OBSERVED** (`mvcount` + collapsed `mvindex(mvdedup(…),0)` values on live `index=agentsec_telemetry`, `sourcetype=otel:agentic:json`)  
**Control-event specimen:** BASELINE A `fb50dcaf-8e84-4a3f-a55b-997c72edbd04` sequence 3; values confirmed on B–F control events.

Do not assume extraction shape. Collapse scalars before `stats count by`. Completeness uses `dc(_raw)`, not `stats count` on a duplicated field.

Phase 2C.1 / 3C / 4C multivalue duplication is **OBSERVED** again. Classification: **B** (one event, repeated identical copies) from **C** (INDEXED_EXTRACTIONS=json + KV_MODE=json, plus OTLP log attributes on some keys). **A** (physical duplicate events) ruled out: `dc(_raw)` equals local `events.jsonl` count.

**Do not change `props.conf` in this phase.**

---

## Indexed representation (actual names)

Measured on the BASELINE A control event unless noted. `mvcount` is **before** any `eval` that overwrites the same field name.

| Field | Present | Collapsed value (A control) | `mvcount` | Notes |
|-------|---------|-----------------------------|----------:|-------|
| `agentsec.run.id` | yes | `fb50dcaf-8e84-4a3f-a55b-997c72edbd04` | 3 | hunt key |
| `agentsec.incident.id` | yes | same UUID as run.id | 2 | |
| `trace_id` | yes | `11fdb2c85d9635413df04ce9f9b35acb` | 3 | not `agentsec.trace_id` |
| `agentsec.sequence` | yes | `3` | 2 | |
| `event.name` | yes | `agentsec.control.decision` | 3 | **not** `agentsec.event.name` |
| `gen_ai.agent.id` | yes | `acme-agent-mcp-001` | 3 | |
| `gen_ai.tool.name` | yes | `lookup_policy` | 2 | |
| `gen_ai.operation.name` | omitted on control | — | — | On `mcp.started`: `execute_tool` `mvcount=2` |
| `mcp.method.name` | yes | `tools/call` | 2 | |
| `agentsec.security.profile` | yes | `defended` | 2 | B: `vulnerable` |
| `agentsec.testbed.mode` | yes | `BASELINE` | 3 | B ATTACK; C RETEST |
| `agentsec.attack.id` | yes | `MCP-004` | 2 | additive 1.2.0 enum |
| `agentsec.control.id` | yes | `CTRL-MCP-001` | 2 | |
| `agentsec.control.decision` | yes | `ALLOW` | 3 | C `DENY`; D/E `ERROR` |
| `agentsec.control.reason` | yes | `tool_granted` | 2 | |
| `agentsec.mcp.requested_scope` | yes | `policy:read` | 2 | constant in this lab |
| `agentsec.mcp.allowed_scope` | yes | `policy:read` | 2 | coded grant; not rewritten |
| `agentsec.mcp.resource.id` | yes | `lending-basics` | 2 | B/C: `executive-restricted`; D: `does-not-exist`; **E: absent** |
| `agentsec.mcp.allowed_resource.ids` | yes | `lending-basics` | 2 | coded grant; never rewritten |
| `agentsec.operation.attempted` | yes | `"false"` | 2 | JSON boolean → Splunk string |
| `agentsec.operation.executed` | yes | `"false"` | 2 | control row; mcp.started is `"true"` |
| `agentsec.operation.outcome` | omitted on ALLOW | empty | (absent) | C/D/E: `prevented` `mvcount=2` |
| `agentsec.schema.version` | yes | `1.2.0` | 2 | bumped |

B control (collapsed): decision `ALLOW`, reason `vulnerable_profile_fail_open:resource_not_granted`, `resource.id=executive-restricted`, `allowed_resource.ids=lending-basics`, profile `vulnerable`, mode `ATTACK`.

C control: `DENY` / `resource_not_granted` / resource `executive-restricted` / allowed `lending-basics` / outcome `prevented`.

D control: `ERROR` / `unknown_resource` / resource `does-not-exist` / allowed `lending-basics`.

E control: `ERROR` / `malformed_arguments` / **no** `resource.id` / allowed `lending-basics`. Do not fabricate resource identity.

F control: ALLOW `tool_granted` matching resource (handler later `mcp.failed`).

G: no control event. `run.failed` `error.type=duplicate_json_keys`.

---

## `allowed_resource.ids` indexed shape

Conceptually a set. This lab’s grant is one id: `lending-basics`.

| Check | Observed on A control |
|-------|------------------------|
| Collapsed value | `lending-basics` (string) |
| `mvcount` (raw) | **2** |
| `mvcount(mvdedup(…))` | **1** |
| `typeof` | Multivalue |
| `mvcount(split(collapsed, ","))` | **1** |
| JSON array extraction | **no** |

Interpretation: a **comma-sorted scalar** duplicated by INDEXED_EXTRACTIONS=json + KV_MODE=json (+ OTLP attributes). Same class as `allowed_scope`. **Not** two grants. **Not** a JSON array.

Q-MCP-RESOURCE-AUTHZ membership therefore uses **exact equality of collapsed strings**, which is correct for the current single grant.

---

## What is not a new indexed field

| Name | Status |
|------|--------|
| `effective_resource` | not emitted (by design) |
| `resource.authorized` | not emitted |
| `resource_relation` | SPL display helper only |
| `gen_ai.tool.call.arguments` | unused; not present on A control |
| `agentsec.event.name` | not a field; use `event.name` |
| `session.id` | not emitted |

---

## Eval overwrite pitfall

If SPL does `eval trace_id=mvindex(mvdedup('trace_id'),0)` and then `mvcount('trace_id')`, the count becomes 1. That is not evidence the indexed field was a scalar. Measure `mvcount` on the original extracted field.

---

## Schema version

Indexed `agentsec.schema.version=1.2.0` on these MCP-004 runs. Existing Q-MCP SPL does not filter version; LAB-MCP-001 `catalog.json` still labels historical searches `1.1.0` as **metadata**.
