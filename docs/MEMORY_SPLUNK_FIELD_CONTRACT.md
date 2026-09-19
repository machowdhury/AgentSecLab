# LAB-MEMORY-001 Splunk field contract

**Lab:** LAB-MEMORY-001 live specimens (Phase 11C)  
**Schema:** `agentsec.security_event` **1.7.0**  
**Date:** 2026-09-17  
**Evidence class:** **OBSERVED** (`fieldsummary` + `mvcount` + collapsed `mvindex(mvdedup(…),0)` on live `index=agentsec_telemetry`, `sourcetype=otel:agentic:json`)  
**Primary specimens:** A write `a8407246-7992-4ad8-bd02-cb701e150f30` / recall `914c41ce-5123-49eb-892c-c948295dbc46`; B write `05f1d8d0-28b7-40ac-bbb9-1dc64b4ba464` / recall `b8737cd9-9b6b-48f2-acfa-178ae1446ddc`; C write `060a0a72-ceb5-4b99-8330-98de81d8ae5e` / recall `5d5b9d1b-092d-4ddb-8422-4092d289cd49`

Do not assume extraction shape from design docs. Collapse scalars before `stats count by`. Completeness uses `dc(_raw)`, not `stats count` on a duplicated field.

Phase 2C.1 multivalue duplication is **OBSERVED** again. Classification: **B** (one event, repeated identical copies) from **C** (INDEXED_EXTRACTIONS=json + KV_MODE=json, plus OTLP log attributes on some keys). **A** (physical duplicate events) ruled out: `dc(_raw)` equals local `events.jsonl` count.

**Do not change `props.conf` in this phase.** Normalization reused: `mvindex(mvdedup('field'),0)`.

If Splunk guidance conflicted with AgentSec evidence semantics, AgentSec semantics were preserved: OBSERVE ≠ ALLOW; ALLOW ≠ execution; missing `mcp.started` ≠ independent non-execution proof; stored ≠ trusted.

---

## Schema version finding

Every indexed event on the six run IDs collapsed to `agentsec.schema.version=1.7.0`. Q-MCP / DET-MCP-001 SPL do **not** filter schema.version.

Additive 1.7.0 values **OBSERVED** in Splunk:

| Field | Indexed value |
|-------|----------------|
| `agentsec.control.type` | `memory_context_trust` (CONTEXT-001) / `mcp_allowlist` (CTRL-MCP-001) |
| `agentsec.control.id` | `CTRL-MEMORY-CONTEXT-001` / `CTRL-MCP-001` |
| `agentsec.attack.id` | `MEMORY-001` |
| `agentsec.trust_boundary` | `agent.memory.store` on write/recall/CONTEXT-001 |
| `agentsec.memory.id` | `mem.lending-preference.normal` / `mem.lending-preference.malicious` |
| `agentsec.memory.provenance` | `agentsec.memory.fixture` |
| `agentsec.memory.trust` | `untrusted_data` on recall and CONTEXT-001; **empty on write** |
| `agentsec.memory.source_run_id` | writer `run.id` |
| `event.name` | `agentsec.memory.written` / `agentsec.memory.recalled` |
| `gen_ai.workflow.name` | `memory_lab` |
| `agentsec.workflow.entry` | `/memory/write` or `/memory/recall` |
| `agentsec.content.influence.kind` | `recalled_memory` on recall/CONTEXT-001; `tool_request` on hop-1 |

Do **not** overload `agentsec.rag.context.*` or `agentsec.mcp.result.trust` for persisted memory.

---

## Field truth table

| Security concept | Runtime field | Indexed field | BASELINE | ATTACK | RETEST | Extraction notes | Status |
|------------------|---------------|---------------|----------|--------|--------|------------------|--------|
| Memory fingerprint | `agentsec.content.hash` on written/recalled/CONTEXT-001 | same | NORMAL sha256:ee41…340b | MALICIOUS sha256:1dc7…d1b9 | **same as ATTACK** | mvcount=2; collapse | **authoritative** fingerprint |
| Memory preview | `agentsec.content.preview` | same | short NORMAL text | bounded MALICIOUS preview | same as ATTACK | ≤200 chars; not `_raw` | **observational**; hash is the fingerprint |
| Memory trust | `agentsec.memory.trust` | same | `untrusted_data` at recall | `untrusted_data` | `untrusted_data` | empty on write; CONTEXT-001/recall only | **authoritative** classification at recall |
| Memory provenance | `agentsec.memory.provenance` | same | `agentsec.memory.fixture` | same | same | not the same as trust | **authoritative** |
| Memory id | `agentsec.memory.id` | same | `mem.lending-preference.normal` | `mem.lending-preference.malicious` | same as ATTACK | fixture identity; **not** unique specimen key | **authoritative** identity |
| Writer run | `agentsec.run.id` on `memory.written` | same | A write UUID | B write UUID | C write UUID | current run is the writer | **authoritative** writer |
| Destination run | `agentsec.run.id` on `memory.recalled` | same | A recall UUID | B recall UUID | C recall UUID | current run is recall | **authoritative** destination |
| Source run | `agentsec.memory.source_run_id` | same | equals A write | equals B write | equals C write | on write equals self; on recall equals writer | **authoritative** cross-run link |
| Memory decision | CTRL-MEMORY-CONTEXT-001 | `agentsec.control.decision` | OBSERVE | OBSERVE | OBSERVE | never ALLOW on these specimens | **authoritative**; OBSERVE ≠ ALLOW |
| Memory reason | `agentsec.control.reason` | same | `memory_context_is_data` | same | same | | **authoritative** |
| Follow-on grant | hop 1 CTRL-MCP-001 | same | absent | ALLOW overlay | DENY `tool_not_granted` | lab reason string | **authoritative** for this lab |
| Follow-on execution | hop 1 `mcp.started` | `event.name` | none | seq 8 | **none** on COMPLETE copy | Splunk absence is corroboration | start **observational**; handler **runtime authoritative** |
| Coded allowed scope | `agentsec.mcp.allowed_scope` hop 1 | same | n/a | `policy:read` | `policy:read` | not a tool list | **authoritative** for coded **scope** |
| Schema | `agentsec.schema.version` | same | `1.7.0` | `1.7.0` | `1.7.0` | | **authoritative** |

Hop-1 `agentsec.content.hash` is the **tool-request** fingerprint, not the memory. Do not use it for ATTACK/RETEST memory equality. B hop-1 hash `sha256:cd15…3ce6` ≠ C hop-1 hash `sha256:1b56…a317`.

---

## Indexed representation (actual names)

Measured on BASELINE write/recall and ATTACK recall unless noted.

| Field | Present | Example collapsed value | `mvcount` | Notes |
|-------|---------|-------------------------|----------:|-------|
| `event.name` | yes | `agentsec.memory.written` / `recalled` / `control.decision` | 3 | **not** `agentsec.event.name` |
| `agentsec.run.id` | yes | UUID | 3 | write vs recall are different values |
| `agentsec.sequence` | yes | 1–5 write; 1–11 ATTACK recall | 2 | |
| `agentsec.schema.version` | yes | `1.7.0` | 2 | |
| `service.name` | yes | `acmebank` | 3 | |
| `gen_ai.agent.id` | hop events | `acme-agent-memory-001` | 3 | |
| `gen_ai.tool.name` | follow-on only | `lookup_customer_tier` | 2 | **empty** on write/recall/CONTEXT-001 |
| `mcp.method.name` | follow-on | `tools/call` | | **empty** on CONTEXT-001 |
| `agentsec.security.profile` | yes | write always `defended`; B recall `vulnerable` | | overlay is recall-only |
| `agentsec.testbed.mode` | yes | BASELINE / ATTACK / RETEST | | |
| `agentsec.control.id` | control | `CTRL-MEMORY-CONTEXT-001` | 2 | |
| `agentsec.control.type` | control | `memory_context_trust` | 2 | |
| `agentsec.control.decision` | control | OBSERVE / ALLOW / DENY | 3 | |
| `agentsec.control.reason` | control | `memory_context_is_data` | 2 | |
| `agentsec.memory.id` | write/recall/CONTEXT-001 | fixture id | 2 | empty on hop-1 CTRL-MCP-001 |
| `agentsec.memory.trust` | recall + CONTEXT-001 | `untrusted_data` | 2 | **NOT APPLICABLE** on write (`mvcount` empty) |
| `agentsec.memory.provenance` | write/recall/CONTEXT-001 | `agentsec.memory.fixture` | 2 | |
| `agentsec.memory.source_run_id` | write/recall/CONTEXT-001 | writer UUID | 2 | 3 distinct values across A/B/C writers |
| `agentsec.content.hash` | write/recall/CONTEXT-001, hop-1 request | memory sha256 on memory events | 2 | |
| `agentsec.content.preview` | same | bounded | 2 | do not dump `_raw` |
| `agentsec.trust_boundary` | memory events | `agent.memory.store` | | hop-1 is `acmebank.mcp.authorize` |
| `agentsec.operation.attempted` | control / mcp | `"true"` / `"false"` strings | | |
| `agentsec.mcp.requested_scope` | hop-1 | `customer:read` | | **empty** on CONTEXT-001 |
| `agentsec.mcp.allowed_scope` | hop-1 | `policy:read` | | **empty** on CONTEXT-001 |

`fieldsummary` value counts exceed `dc(_raw)` (e.g. `service.name` 126 copies across 42 events). That is extraction duplication, not extra events.

### NOT INDEXED / NOT EXTRACTED

`trusted_memory`, `memory_authorized`, `full_memory`, `agentsec.memory.text`, `agentsec.mcp.allowed_tools`, `gen_ai.tool.call.id`, `agentsec.event.name`, `session.id`, `mcp.session.id`, `invocation.id`.

No eval alias was invented for missing fields.
