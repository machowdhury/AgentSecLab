# AgentSec telemetry roadmap

**Status:** Phase 8A DESIGN. **Schema stays 1.4.0.** No new event names shipped in this phase.

Parents: `schemas/security_event.schema.json`, `docs/SECURITY_EVENT_MODEL.md`, `docs/MCP_SPLUNK_FIELD_CONTRACT.md`.

---

## Planes (logical, not new processes)

Separate **questions**. Do not invent a microservice per plane.

| Plane | What it answers | Schema 1.4.0 today | Future work (not 8A) |
|-------|-----------------|--------------------|----------------------|
| CONTROL PLANE | What did a control decide, why, before which op? | `agentsec.control.decision` + id/type/reason | New `control.type` values only with a lab |
| AGENT EXECUTION | Which agent hop ran? | `hop.started/completed`, `gen_ai.agent.id` | A2A hops if a real protocol exists |
| LLM | Did the governed model call begin/end? | `llm.started/completed/failed` | Token usage fields if MEASURED from Ollama |
| TOOL | Did the MCP handler begin/end? | `mcp.started/completed/failed` | Description hash if catalog lab |
| DELEGATION | Which authority set was consulted? | `agentsec.delegation.authority.source`; CTRL-DELEGATION-001 | Chain depth later |
| IDENTITY | Who is the principal / agent? | `principal.id`, coded agent id | Agent Card fingerprint; **not** fake DID |
| RESULT TRUST | Is tool output data or treated as grant? | `mcp.result.trust`, `mcp.result.provenance`; CTRL-MCP-RESULT-001 | RAG chunk trust later |
| RAG | What was retrieved? | **Absent** | New events + content hash/preview; INV-002 |
| MEMORY | What was stored/recalled with which trust tag? | **Absent** (`MemorySink` ≠ agent memory) | INV-003 events |
| SECURITY SCANNER | What did an external scanner claim? | **Absent** | **Prefer a second sourcetype**, not a schema bump, for imported JSON |
| SUPPLY CHAIN | What AI BOM / package / model id? | **Absent** | Import aibom JSON; do not mint grants from it |
| SYSTEM / INFRA | Collector, HEC, index health | Lab scripts / Splunk internals | Keep out of security_event body |
| MODEL PERFORMANCE | Latency, tokens, error rate | `duration` on hops; not a metrics index | Event-derived metrics → later metrics index |
| TIME-SERIES BEHAVIOR | Rates over windows | Can be **derived in Splunk** from existing events | Dedicated metrics only if event volume justifies |

---

## Sufficient vs later schema

**Do not bump schema** to reserve A2A/RAG fields.

| Need | 1.4.0 sufficient? | If not |
|------|-------------------|--------|
| PI, MCP-001–006 hunts | Yes | — |
| DET-MCP-001 | Yes | — |
| Scanner findings | No honest fields | New sourcetype `agentsec:scanner:json` (design). Field contract first. |
| Tool description integrity | Partial (`gen_ai.tool.name` only) | Additive fields: description hash, catalog version — **future 1.5.0 proposal**, not 8A |
| A2A | No | New event names + protocol fields after a lab spec |
| RAG/memory | No | New events after a lab spec |
| Identity crypto | No | Do not add JWT theater |

Closed schema (`additionalProperties: false`) means scanner JSON **must not** be stuffed into `security_event` without a versioned proposal.

---

## Correlation keys (do not break)

| Key | Rule |
|-----|------|
| `agentsec.run.id` = `incident.id` | Server-minted. Never `session.id` |
| `trace_id` / `span_id` | W3C hex. Align with MCP OTel `_meta` if/when the Python MCP SDK path is used |
| `gen_ai.agent.id` | Coded allow-list |
| `gen_ai.tool.name` | Requested tool |
| `agentsec.sequence` | Ordering inside a run |

Scanner imports should carry `agentsec.run.id` **only** when the scan was requested in that experiment. A host-wide scan is a different investigation (no fake join).

---

## OpenTelemetry

Keep logs→collector→HEC as the evidence bus.

Future alignment (design):

- Continue GenAI attributes already used (`gen_ai.operation.name`, `gen_ai.tool.name`, `mcp.method.name`)
- MCP SDK native spans (semconv) are **optional** when AgentSec still uses a lab HTTP `/mcp/invoke` rather than the full SDK
- Do not dual-emit conflicting field names

---

## Splunk ingest paths

```text
Path A (core, exists)
  AcmeBank events → OTLP → collector → HEC → index=agentsec_telemetry sourcetype=otel:agentic:json

Path B (optional, design)
  Scanner CLI JSON → file or HEC → same index, different sourcetype
  Requires field contract + KO review before any hunt joins Path A to Path B

Path C (optional metrics, design)
  Event-derived stats → metrics index or tstats-friendly summary
  Only after a behavioral lab defines the question
```

Zero rows on Path A still ≠ safe. Missing Path B ≠ “not scanned.”
