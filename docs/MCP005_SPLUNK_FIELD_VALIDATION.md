# MCP-005 Splunk field validation

**Lab:** LAB-MCP-005 live specimens (Phase 6C)  
**Schema:** `agentsec.security_event` **1.3.0**  
**Date:** 2026-09-13  
**Evidence class:** **OBSERVED** (`mvcount` + collapsed `mvindex(mvdedup(…),0)` values on live `index=agentsec_telemetry`, `sourcetype=otel:agentic:json`)  
**Primary specimen:** ATTACK B `f3f48182-df57-4b38-b069-17a199dc4939`

Do not assume extraction shape from design docs. Collapse scalars before `stats count by`. Completeness uses `dc(_raw)`, not `stats count` on a duplicated field.

Phase 2C.1 / 3C / 4C / 5C multivalue duplication is **OBSERVED** again. Classification: **B** (one event, repeated identical copies) from **C** (INDEXED_EXTRACTIONS=json + KV_MODE=json, plus OTLP log attributes on some keys). **A** (physical duplicate events) ruled out: `dc(_raw)` equals local `events.jsonl` count.

**Do not change `props.conf` in this phase.** Normalization reused: `mvindex(mvdedup('field'),0)`.

---

## Schema version finding

Every indexed event on A/B/C/F collapsed to `agentsec.schema.version=1.3.0` (`mvcount=2`). Q-MCP / DET-MCP-001 SPL do **not** filter schema.version. Catalog labels on LAB-MCP-001 (`1.1.0`) and LAB-MCP-004 (`1.2.0`) remain historical metadata.

Additive 1.3.0 values **OBSERVED** in Splunk:

| Field | Indexed value |
|-------|----------------|
| `agentsec.control.decision` | `OBSERVE` (A/C RESULT-001) |
| `agentsec.control.type` | `mcp_result_trust` |
| `agentsec.control.id` | `CTRL-MCP-RESULT-001` |
| `agentsec.attack.id` | `MCP-005` |

---

## Indexed representation (actual names)

Measured on ATTACK B unless noted. `mvcount` is **before** any overwrite `eval`.

| Field | Present | Example collapsed value | `mvcount` | Notes |
|-------|---------|-------------------------|----------:|-------|
| `event.name` | yes | `agentsec.control.decision` | 3 | **not** `agentsec.event.name` |
| `agentsec.run.id` | yes | `f3f48182-df57-4b38-b069-17a199dc4939` | 3 | hunt key |
| `trace_id` | yes | `a79c8386fce957413c8de3720b754e25` | 3 | one per run |
| `span_id` | yes | per event | 3 | |
| `parent_span_id` | yes | hop span | 2 | omitted on `run.started` |
| `agentsec.sequence` | yes | `1`…`13` | 2 | ordering key |
| `agentsec.schema.version` | yes | `1.3.0` | 2 | bumped |
| `agentsec.security.profile` | yes | `vulnerable` | 2 | A/C `defended` |
| `agentsec.testbed.mode` | yes | `ATTACK` | 3 | A BASELINE; C RETEST |
| `agentsec.attack.id` | yes | `MCP-005` | 2 | |
| `agentsec.control.id` | on control | `CTRL-MCP-001` / `CTRL-MCP-RESULT-001` | 2 | |
| `agentsec.control.type` | on control | `mcp_allowlist` / `mcp_result_trust` | 2 | |
| `agentsec.control.decision` | on control | ALLOW / OBSERVE / DENY | 3 | |
| `agentsec.control.reason` | on control | `tool_granted` / `result_is_data` / `…:result_derived_grant` / `tool_not_granted` | 2 | |
| `gen_ai.tool.name` | hop-scoped | `lookup_policy` or `lookup_customer_tier` | 2 | |
| `agentsec.mcp.requested_scope` | CTRL-MCP-001 | hop0 `policy:read`; hop1 `customer:read` | 2 | **absent** on RESULT-001 |
| `agentsec.mcp.allowed_scope` | CTRL-MCP-001 | `policy:read` on **both** hops | 2 | coded; never rewritten |
| `agentsec.mcp.resource.id` | lookup_policy control/RESULT-001 | `lending-basics` | 2 | **absent** on follow-on CTRL-MCP-001 |
| `agentsec.mcp.allowed_resource.ids` | same | `lending-basics` | 2 | |
| `agentsec.operation.attempted` | control / mcp.* | control `"false"`; mcp.* `"true"` | 2 | JSON boolean → Splunk string |
| `agentsec.operation.executed` | control / mcp.* | control `"false"`; mcp.* `"true"` | 2 | |
| `agentsec.operation.outcome` | DENY control; mcp.completed/failed | C hop1 `prevented`; completed `success` | 2 | omitted on ALLOW/OBSERVE control |
| `agentsec.mcp.result.trust` | mcp.completed | `untrusted_data` | 2 | classification, **not** authority |
| `agentsec.mcp.result.provenance` | mcp.completed | `mcp.tool.handler` | 2 | source, **not** authority |
| `agentsec.content.hash` | control / completed | `sha256:<64 hex>` | 2 | content identity |
| `agentsec.content.preview` | control / completed | ≤200 chars | 2 | bounded |
| `agentsec.hop.index` | hop-scoped | `0` or `1` | 2 | initial vs follow-on |
| `agentsec.delegator.agent.id` | hop ≥ 1 | `acme-agent-mcp-001` | 2 | |
| `agentsec.trust_boundary` | control / mcp.* | `acmebank.mcp.authorize` / `mcp.tool.result` / `mcp.tool.execute` | 2 | |
| `mcp.method.name` | CTRL-MCP-001 / mcp.* | `tools/call` | 2 | **absent** on RESULT-001 |
| `gen_ai.agent.id` | hop-scoped | `acme-agent-mcp-001` | 3 | |
| `agentsec.principal.id` | hop-scoped | `applicant-web` | 2 | |

---

## Fields that are **not** indexed

| Expected by some readers | Finding |
|--------------------------|---------|
| `agentsec.mcp.allowed_tools` | **absent** |
| `gen_ai.tool.call.id` | **absent** |
| `agentsec.mcp.result.derived_authority` | **absent** |
| `agentsec.result.derived_authority` | **absent** |
| `agentsec.event.name` | **absent** (use `event.name`) |
| Full result body | **absent** (preview ≤200) |

Server-owned tools are visible only inside hop-1 CTRL-MCP-001 `agentsec.content.preview` as `server_owned_allowed_tools": "lookup_policy"`. ATTACK preview is truncated at 200 characters (`"tool": "lookup_customer_tie`). RETEST preview is complete (193 chars) and includes `authority_source": "server-owned"`.

---

## Duplicate extraction vs duplicate events

| Check | B ATTACK |
|-------|----------|
| Local `events.jsonl` | 13 |
| Splunk `dc(_raw)` | 13 |
| Typical `mvcount('agentsec.run.id')` | 3 |
| `mvcount(mvdedup('agentsec.run.id'))` | 1 |

Do not mistake `mvcount=2` or `3` for two grants, two tools, or two runs.

---

## Correlation model (actual)

Reliable:

- `agentsec.run.id` isolates a specimen
- `agentsec.sequence` orders events
- `agentsec.hop.index` distinguishes initial (`0`) from follow-on (`1`)
- `gen_ai.tool.name` distinguishes `lookup_policy` from `lookup_customer_tier`
- `agentsec.control.id` distinguishes CTRL-MCP-001 from CTRL-MCP-RESULT-001
- `parent_span_id` groups events inside one hop

Not available:

- `gen_ai.tool.call.id` — same-tool twice would be sequence-only. This lab uses two different names, so tool + hop is enough.

Honest limit: Splunk reconstructs **this lab's** two-hop story. It does not invent per-invocation IDs the runtime never emitted.
