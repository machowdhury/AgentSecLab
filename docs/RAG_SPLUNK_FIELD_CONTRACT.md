# LAB-RAG-001 Splunk field contract

**Lab:** LAB-RAG-001 live specimens (Phase 10C)  
**Schema:** `agentsec.security_event` **1.6.0**  
**Date:** 2026-09-16  
**Evidence class:** **OBSERVED** (`fieldsummary` + `mvcount` + collapsed `mvindex(mvdedup(…),0)` on live `index=agentsec_telemetry`, `sourcetype=otel:agentic:json`)  
**Primary specimens:** A `51f70fb9-994e-4dd4-9b36-cac6fb1e8232`; B `3a43d24f-9281-42f6-8375-1fb2efaa80ac`; C `bea97bae-491b-4b36-b52f-1417d2bad01b`

Do not assume extraction shape from design docs. Collapse scalars before `stats count by`. Completeness uses `dc(_raw)`, not `stats count` on a duplicated field.

Phase 2C.1 multivalue duplication is **OBSERVED** again. Classification: **B** (one event, repeated identical copies) from **C** (INDEXED_EXTRACTIONS=json + KV_MODE=json, plus OTLP log attributes on some keys). **A** (physical duplicate events) ruled out: `dc(_raw)` equals local `events.jsonl` count.

**Do not change `props.conf` in this phase.** Normalization reused: `mvindex(mvdedup('field'),0)`.

If Splunk guidance conflicted with AgentSec evidence semantics, AgentSec semantics were preserved: OBSERVE ≠ ALLOW; ALLOW ≠ execution; missing `mcp.started` ≠ independent non-execution proof.

---

## Schema version finding

Every indexed event on A/B/C collapsed to `agentsec.schema.version=1.6.0`. Q-MCP / DET-MCP-001 SPL do **not** filter schema.version.

Additive 1.6.0 values **OBSERVED** in Splunk:

| Field | Indexed value |
|-------|----------------|
| `agentsec.control.type` | `rag_context_trust` (CONTEXT-001) / `mcp_allowlist` (CTRL-MCP-001) |
| `agentsec.control.id` | `CTRL-RAG-CONTEXT-001` / `CTRL-MCP-001` |
| `agentsec.attack.id` | `RAG-001` |
| `agentsec.trust_boundary` | `rag.retrieved.context` on CONTEXT-001 |
| `agentsec.rag.context.trust` | `untrusted_data` on CONTEXT-001 |
| `agentsec.rag.context.provenance` | `rag.local.fixture` on CONTEXT-001 |
| `agentsec.rag.context.document.id` | `doc.lending-policy.normal` / `doc.lending-policy.malicious` |
| `gen_ai.workflow.name` | `rag_context_lab` |
| `agentsec.workflow.entry` | `/rag/retrieve` |
| `agentsec.content.influence.kind` | `retrieved_context` on CONTEXT-001 |

Do **not** overload `agentsec.mcp.result.trust` or `agentsec.mcp.metadata.trust` for retrieved documents.

---

## Field truth table

| Security concept | Runtime field | Indexed field | BASELINE | ATTACK | RETEST | Extraction notes | Status |
|------------------|---------------|---------------|----------|--------|--------|------------------|--------|
| Document fingerprint | `agentsec.content.hash` on CONTEXT-001 | same | NORMAL sha256:0fc8…7f8e | MALICIOUS sha256:c565…97ef | **same as ATTACK** | mvcount=2; collapse | **authoritative** fingerprint |
| Document preview | `agentsec.content.preview` | same | short NORMAL text | bounded MALICIOUS preview | same as ATTACK | ≤200 chars; not `_raw` | **observational**; hash is the fingerprint |
| Context trust | `agentsec.rag.context.trust` | same | `untrusted_data` | `untrusted_data` | `untrusted_data` | CONTEXT-001 only; mvcount=2 | **authoritative** classification |
| Context provenance | `agentsec.rag.context.provenance` | same | `rag.local.fixture` | same | same | not the same as trust | **authoritative** |
| Document id | `agentsec.rag.context.document.id` | same | `doc.lending-policy.normal` | `doc.lending-policy.malicious` | same as ATTACK | opaque exact string | **authoritative** identity |
| Context decision | CTRL-RAG-CONTEXT-001 | `agentsec.control.decision` | OBSERVE | OBSERVE | OBSERVE | never ALLOW on these specimens | **authoritative**; OBSERVE ≠ ALLOW |
| Context reason | `agentsec.control.reason` | same | `retrieved_context_is_data` | same | same | | **authoritative** |
| Follow-on grant | hop 1 CTRL-MCP-001 | same | absent | ALLOW overlay | DENY `tool_not_granted` | lab reason string | **authoritative** for this lab |
| Follow-on execution | hop 1 `mcp.started` | `event.name` | none | seq 7 | **none** on COMPLETE copy | Splunk absence is corroboration | start **observational**; handler **runtime authoritative** |
| Coded allowed scope | `agentsec.mcp.allowed_scope` hop 1 | same | n/a | `policy:read` | `policy:read` | not a tool list | **authoritative** for coded **scope** |
| Schema | `agentsec.schema.version` | same | `1.6.0` | `1.6.0` | `1.6.0` | | **authoritative** |

Hop-1 `agentsec.content.hash` is the **tool-request** fingerprint, not the document. Do not use it for ATTACK/RETEST document equality.

---

## Indexed representation (actual names)

Measured on BASELINE A unless noted.

| Field | Present | Example collapsed value | `mvcount` | Notes |
|-------|---------|-------------------------|----------:|-------|
| `event.name` | yes | `agentsec.control.decision` | 3 | **not** `agentsec.event.name` |
| `agentsec.run.id` | yes | A UUID | 3 | hunt key |
| `agentsec.sequence` | yes | 1–5 on A | 2 | |
| `agentsec.schema.version` | yes | `1.6.0` | 2 | |
| `service.name` | yes | `acmebank` | 3 | |
| `gen_ai.agent.id` | hop events | `acme-agent-rag-001` | 3 | |
| `gen_ai.tool.name` | follow-on only | `lookup_customer_tier` | | **empty** on CONTEXT-001 |
| `mcp.method.name` | follow-on | `tools/call` | | **empty** on CONTEXT-001 |
| `agentsec.security.profile` | yes | `defended` / B `vulnerable` | | |
| `agentsec.testbed.mode` | yes | BASELINE / ATTACK / RETEST | | |
| `agentsec.control.id` | control | `CTRL-RAG-CONTEXT-001` | 2 | |
| `agentsec.control.type` | control | `rag_context_trust` | 2 | |
| `agentsec.control.decision` | control | OBSERVE / ALLOW / DENY | 3 | |
| `agentsec.control.reason` | control | `retrieved_context_is_data` | 2 | |
| `agentsec.rag.context.trust` | CONTEXT-001 | `untrusted_data` | 2 | empty on CTRL-MCP-001 |
| `agentsec.rag.context.provenance` | CONTEXT-001 | `rag.local.fixture` | 2 | |
| `agentsec.rag.context.document.id` | CONTEXT-001 | fixture id | 2 | |
| `agentsec.content.hash` | CONTEXT-001, hop-1 request | document sha256 on CONTEXT-001 | 2 | |
| `agentsec.content.preview` | same | bounded | 2 | do not dump `_raw` |
| `agentsec.trust_boundary` | CONTEXT-001 | `rag.retrieved.context` | | |
| `agentsec.operation.attempted` | control / mcp | `"true"` / `"false"` strings | | |
| `agentsec.mcp.requested_scope` | hop-1 | `customer:read` | | **empty** on CONTEXT-001 |
| `agentsec.mcp.allowed_scope` | hop-1 | `policy:read` | | **empty** on CONTEXT-001 |

### NOT INDEXED / NOT EXTRACTED

`trusted_document`, `document_authorized`, `rag_allowed_tools`, `agentsec.mcp.allowed_tools`, `full_document`, `gen_ai.tool.call.id`, `agentsec.event.name`, `session.id`, `mcp.session.id`.
