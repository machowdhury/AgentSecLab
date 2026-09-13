# MCP Event Model (schema 1.1.0)

**Status:** Phase 3B **IMPLEMENTED**. Phase 3C indexed field names: `docs/MCP_SPLUNK_FIELD_CONTRACT.md`.  
**Parent:** `SECURITY_EVENT_MODEL.md` (1.0.0 loan semantics **unchanged**).  
**Proposal history:** `MCP_EVENT_MODEL_PROPOSAL.md` (Phase 3A; this file is the adopted subset).  
**Installed OTel:** `opentelemetry-semantic-conventions==0.65b0` (SDK 1.44.0). GenAI/MCP names below are **incubating** in that package, not stable.

---

## Migration from 1.0.0

| Rule | Detail |
|------|--------|
| Version | Every event emits `agentsec.schema.version=1.1.0` (loan and MCP). |
| Meanings | Existing 1.0.0 fields keep the same meaning. |
| Additive | New event names, operation type `mcp_tool_invoke`, MCP fields, extra enum values. |
| Loan path | Still `workflow.entry=/process`, `gen_ai.workflow.name=loan_pipeline`, `gen_ai.operation.name=chat`. |
| MCP path | `workflow.entry=/mcp/invoke`, `gen_ai.workflow.name=mcp_tool_lab`, `gen_ai.operation.name=execute_tool`. |
| Hunt key | Still `agentsec.run.id` = `incident.id`. **No `session.id`.** |

Historical LAB-PI-001 Splunk catalogs remain labeled 1.0.0 against previously validated runs. New loan events are 1.1.0-compatible.

---

## Field classification (installed SDK, not wishful naming)

Inspected: `opentelemetry.semconv._incubating.attributes.gen_ai_attributes` and `mcp_attributes`.

| Concept | Classification | Field emitted | Notes |
|---------|----------------|---------------|--------|
| Tool name | **STANDARD** (incubating) | `gen_ai.tool.name` | `GEN_AI_TOOL_NAME` |
| GenAI operation | **STANDARD** | `gen_ai.operation.name` | `chat` (LLM) or `execute_tool` (MCP) |
| MCP method | **STANDARD** (incubating) | `mcp.method.name` | `MCP_METHOD_NAME`; LAB-MCP-001 = `tools/call` |
| Service | **STANDARD** | `service.name` | In-process server; remains `acmebank` |
| Principal | **AGENTSEC** | `agentsec.principal.id` | Already required in 1.0.0 |
| Delegator | **AGENTSEC** | `agentsec.delegator.agent.id` | Unchanged; omitted on MCP hop 0 |
| Requested scope | **AGENTSEC** | `agentsec.mcp.requested_scope` | Not an OTel MCP attribute |
| Allowed scope | **AGENTSEC** | `agentsec.mcp.allowed_scope` | Coded policy; never from HTTP |
| Operation flags | **AGENTSEC** | `agentsec.operation.*` | Same flags; new governed op = tool handler |
| Result trust | **AGENTSEC** | `agentsec.mcp.result.trust` | Always `untrusted_data` on completed |
| Result provenance | **AGENTSEC** | `agentsec.mcp.result.provenance` | `mcp.tool.handler` |
| `mcp.session.id` | **NOT USED** | — | OTel MCP session ≠ AgentSec hunt key |
| `mcp.protocol.version` | **NOT USED** | — | No initialize handshake |
| `gen_ai.tool.call.arguments` | **NOT USED** | — | Preview + hash via `agentsec.content.*` |
| `agentsec.mcp.server.id` | **NOT USED** | — | Use `service.name` |
| `agentsec.mcp.tool.name` | **NOT USED** | — | Duplicate of `gen_ai.tool.name` |

Authorization stays **`agentsec.control.decision`**. No second authorization event.

---

## Events

| `event.name` | `operation.type` | attempted | executed | outcome |
|--------------|------------------|-----------|----------|---------|
| `agentsec.control.decision` ALLOW | `control_evaluation` | false | false | omit |
| `agentsec.control.decision` DENY/ERROR | `control_evaluation` | false | false | prevented |
| `agentsec.mcp.started` | `mcp_tool_invoke` | true | true | omit |
| `agentsec.mcp.completed` | `mcp_tool_invoke` | true | true | success |
| `agentsec.mcp.failed` | `mcp_tool_invoke` | true | true | error |

DENY and pre-invoke ERROR emit **no** `mcp.started`.

Control `id`/`type` for this lab: `CTRL-MCP-001` / `mcp_allowlist`.

---

## Sequences

**A BASELINE** (authorized `lookup_policy`):  
`run.started` → `hop.started` → `control.decision` ALLOW → `mcp.started` → `mcp.completed` → `hop.completed` → `run.completed`

**B ATTACK** (`vulnerable`, `lookup_customer_tier`):  
ALLOW with labeled fail-open → `mcp.started` → `mcp.completed`

**C RETEST** (`defended`, same unauthorized tool):  
DENY → `pipeline.stopped` → **no** `mcp.started` → `run.completed` `completed_denied`

**D** handler failure after ALLOW: `mcp.started` → `mcp.failed` (`executed=true`, `outcome=error`)

**E** control/unknown/malformed ERROR: ERROR → **no** `mcp.started` → `run.failed`

---

## Proof

Runtime handler count is authoritative. `events.jsonl` corroborates sequence. Splunk is out of scope for 3B.
