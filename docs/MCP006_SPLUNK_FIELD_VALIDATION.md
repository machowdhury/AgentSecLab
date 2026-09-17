# MCP-006 Splunk field validation

**Lab:** LAB-MCP-006 live specimens (Phase 7C)  
**Schema:** `agentsec.security_event` **1.4.0**  
**Date:** 2026-09-14  
**Evidence class:** **OBSERVED** (`mvcount` + collapsed `mvindex(mvdedup(…),0)` values on live `index=agentsec_telemetry`, `sourcetype=otel:agentic:json`)  
**Primary specimen:** ATTACK B `d7524a4e-8da6-4171-8867-d2a2168128ac`

Do not assume extraction shape from design docs. Collapse scalars before `stats count by`. Completeness uses `dc(_raw)`, not `stats count` on a duplicated field.

Phase 2C.1 / 3C / 4C / 5C / 6C multivalue duplication is **OBSERVED** again. Classification: **B** (one event, repeated identical copies) from **C** (INDEXED_EXTRACTIONS=json + KV_MODE=json, plus OTLP log attributes on some keys). **A** (physical duplicate events) ruled out: `dc(_raw)` equals local `events.jsonl` count.

**Do not change `props.conf` in this phase.** Normalization reused: `mvindex(mvdedup('field'),0)`.

---

## Schema version finding

Every indexed control event on A/B/C collapsed to `agentsec.schema.version=1.4.0`. Q-MCP / DET-MCP-001 SPL do **not** filter schema.version. Catalog labels on earlier labs remain historical metadata.

Additive 1.4.0 values **OBSERVED** in Splunk:

| Field | Indexed value |
|-------|----------------|
| `agentsec.control.type` | `mcp_delegation` (hop 0) / `mcp_allowlist` (hop 1) |
| `agentsec.control.id` | `CTRL-DELEGATION-001` / `CTRL-MCP-001` |
| `agentsec.attack.id` | `MCP-006` |
| `agentsec.delegation.authority.source` | `delegated` or `ambient_deputy` on hop-0 control; **absent** on hop-1 CTRL-MCP-001 |

---

## Field truth table

| Security concept | Runtime field | Indexed field | BASELINE | ATTACK | RETEST | Extraction notes | Status |
|------------------|---------------|---------------|----------|--------|--------|------------------|--------|
| Caller | hop 0 `gen_ai.agent.id` | `gen_ai.agent.id` (hop 0) | `acme-agent-credit-002` | same | same | mvcount=3; collapse | **authoritative** |
| Deputy | hop 1 `gen_ai.agent.id` | `gen_ai.agent.id` (hop 1) | `acme-agent-compliance-004` | same | **absent** (no hop 1) | first-class only if hop 1 indexed | hop 1 **authoritative**; RETEST **observational gap** |
| Delegator | hop 1 `agentsec.delegator.agent.id` | `agentsec.delegator.agent.id` | credit-002 | credit-002 | absent | omitted on hop 0 | hop 1 **authoritative** |
| Principal | `agentsec.principal.id` | `agentsec.principal.id` | `applicant-web` | same | same | | **authoritative** |
| Requested tool | `gen_ai.tool.name` | `gen_ai.tool.name` | `lookup_policy` | `lookup_customer_tier` | `lookup_customer_tier` | | **authoritative** |
| Requested scope | `agentsec.mcp.requested_scope` | same | `policy:read` | `customer:read` | `customer:read` | | **authoritative** |
| Resource | `agentsec.mcp.resource.id` | same | `lending-basics` | hop0 `cust-001`; hop1 empty | `cust-001` | hop-1 ATTACK resource not on CTRL-MCP-001 | hop 0 **authoritative** |
| Delegated scope wire | hop 0 `allowed_scope` | `agentsec.mcp.allowed_scope` hop 0 | `policy:read` | `policy:read` | `policy:read` | **not** a tool list | **authoritative** for coded delegated **scope** |
| Downstream allowed scope | hop 1 `allowed_scope` | hop 1 `agentsec.mcp.allowed_scope` | `policy:read` | `customer:read,policy:read` | none | ambient policy object on ATTACK | **authoritative** for selected MCP policy wire |
| Authority source | `agentsec.delegation.authority.source` | same | `delegated` | `ambient_deputy` | `delegated` | hop 0 only; mvcount=2 | **authoritative** for what the control consulted |
| Delegation decision | CTRL-DELEGATION-001 | `agentsec.control.decision` hop 0 | ALLOW | ALLOW | DENY | | **authoritative** |
| Delegation reason | `agentsec.control.reason` hop 0 | same | `delegation_granted` | `vulnerable_profile_fail_open:ambient_deputy_authority` | `delegated_authority_not_granted` | stable lab contract | **authoritative** lab reason |
| MCP decision | CTRL-MCP-001 | hop 1 decision | ALLOW `tool_granted` | ALLOW `tool_granted` | none | do not collapse into delegation | **authoritative** when present |
| Execution | `mcp.started` / handler count | `event.name=agentsec.mcp.started` | indexed 1 | indexed 1 | indexed 0 | Splunk absence is corroboration | start **observational**; handler **runtime authoritative** |
| Outcome | `agentsec.outcome` / operation.outcome | `agentsec.outcome` on run.completed; `operation.outcome` on DENY/completed | `completed_allowed` / success | same | `completed_denied` / `prevented` | | **authoritative** |
| Schema | `agentsec.schema.version` | same | `1.4.0` | `1.4.0` | `1.4.0` | mvcount=2 | **authoritative** |
| Profile / mode | security.profile / testbed.mode | same | defended / BASELINE | vulnerable / ATTACK | defended / RETEST | | **authoritative** |

Hop-0 control preview contains JSON `caller`, `deputy`, `delegated_tools`, `authority_source`. Preview is bounded at 200 characters (ATTACK/RETEST tool name truncated). **Do not** parse preview as grant proof. Status: **observational**.

---

## Indexed representation (actual names)

Measured on ATTACK B hop-0 control unless noted.

| Field | Present | Example collapsed value | `mvcount` | Notes |
|-------|---------|-------------------------|----------:|-------|
| `event.name` | yes | `agentsec.control.decision` | 3 | **not** `agentsec.event.name` |
| `agentsec.run.id` | yes | `d7524a4e-8da6-4171-8867-d2a2168128ac` | 3 | hunt key |
| `trace_id` | yes | `a85a87e441f5e8fef72bb7f62ba5f4a1` | (same pattern as prior labs) | one per run |
| `agentsec.sequence` | yes | `3` on hop-0 control | | |
| `agentsec.schema.version` | yes | `1.4.0` | | |
| `agentsec.security.profile` | yes | `vulnerable` | | A/C `defended` |
| `agentsec.testbed.mode` | yes | `ATTACK` | | |
| `agentsec.attack.id` | yes | `MCP-006` | | |
| `agentsec.control.id` | on control | `CTRL-DELEGATION-001` | 2 | hop 1 `CTRL-MCP-001` |
| `agentsec.control.type` | on control | `mcp_delegation` | | hop 1 `mcp_allowlist` |
| `agentsec.control.decision` | on control | ALLOW | 3 | C hop 0 DENY |
| `agentsec.control.reason` | on control | `vulnerable_profile_fail_open:ambient_deputy_authority` | | |
| `agentsec.delegation.authority.source` | hop 0 control | `ambient_deputy` | 2 | A/C `delegated`; **empty** hop 1 |
| `gen_ai.agent.id` | hop-scoped | hop 0 credit-002; hop 1 compliance-004 | 3 | |
| `gen_ai.agent.name` | hop-scoped | Credit Agent / Compliance Agent | | |
| `agentsec.principal.id` | hop-scoped | `applicant-web` | | |
| `agentsec.delegator.agent.id` | hop ≥ 1 | `acme-agent-credit-002` | | **absent** hop 0 |
| `gen_ai.tool.name` | hop-scoped | `lookup_customer_tier` | | A `lookup_policy` |
| `agentsec.mcp.requested_scope` | control | hop 0 `customer:read` | | A `policy:read` |
| `agentsec.mcp.allowed_scope` | control | hop 0 `policy:read`; hop 1 `customer:read,policy:read` | | hop 0 always delegated wire |
| `agentsec.mcp.resource.id` | hop 0 | `cust-001` | | hop 1 ATTACK empty |
| `agentsec.mcp.allowed_resource.ids` | hop 0 | `lending-basics` | | delegated policy ids wire |
| `agentsec.operation.attempted` | control | `"false"` | | JSON boolean → Splunk string |
| `agentsec.operation.executed` | control / mcp.started | control `"false"`; mcp.started `"true"` | | |
| `agentsec.operation.outcome` | DENY control; mcp.completed | C `prevented`; completed `success` | | omitted on ALLOW control |
| `agentsec.hop.index` | hop-scoped | `0` or `1` | | |
| `agentsec.trust_boundary` | control | `acmebank.mcp.authorize` | | |
| `mcp.method.name` | control / mcp.* | `tools/call` | | |
| `agentsec.content.preview` | control / completed | ≤200 chars | | observational |

---

## Fields that are **not** indexed

| Expected by some readers | Finding |
|--------------------------|---------|
| `agentsec.mcp.allowed_tools` | **absent** (`mvcount` empty) |
| `gen_ai.tool.call.id` | **absent** |
| `agentsec.deputy.agent.id` | **absent** |
| `agentsec.caller.agent.id` | **absent** |
| `agentsec.delegation.caller.id` | **absent** (exists on **manifest**, not events) |
| `agentsec.delegation.deputy.id` | **absent** on events |
| `agentsec.delegated.tools` | **absent** as a first-class field |
| `agentsec.mcp.ambient.tools` | **absent** |

---

## Authority source validation

`agentsec.delegation.authority.source` is indexed, structured, and stable (`delegated` | `ambient_deputy`). It is server-derived (HTTP JSON cannot set it). Duplicate copies are identical (`mvcount=2`).

It answers **which grant object the control consulted**. It does **not** index the delegated tool set or the ambient tool set. Do not infer ambient **possession** from `profile=vulnerable` or from ALLOW alone. Do not infer “tool not in delegated grant” from this field without runtime/manifest.

---

## Correlation limitations

No `gen_ai.tool.call.id`. This controlled lab is **one operation per run**. Correlation by `run.id` + `hop.index` + `sequence` + tool is sufficient here.

The model will fail when the same tool is invoked twice in one run: sequence still orders events, but there is no per-invocation id. Future repeated/same-tool calls cannot use this hunt as a general detector key.
