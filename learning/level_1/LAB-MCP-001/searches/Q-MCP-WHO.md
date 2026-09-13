# Q-MCP-WHO

| Item | Value |
|------|--------|
| Query ID | `Q-MCP-WHO` |
| Security question | Which principal / agent requested which MCP tool? |
| Validation status | **VALIDATED** |
| Validation date | 2026-09-12 |
| SPL file | `Q-MCP-WHO.spl` |

## Required fields (indexed names)

`event.name`, `agentsec.run.id`, `agentsec.principal.id`, `gen_ai.agent.id`, `gen_ai.tool.name`, `mcp.method.name`, `agentsec.security.profile`, `agentsec.testbed.mode`

## SPL

See `Q-MCP-WHO.spl`. Filter `"event.name"=agentsec.control.decision` so tool and method are present.

## Line-by-line explanation

1. Scope `index=agentsec_telemetry sourcetype=otel:agentic:json` and one `agentsec.run.id`.
2. Restrict to the control event — that is where `gen_ai.tool.name` and `mcp.method.name` are always emitted for a governed invoke.
3. Collapse duplicate scalar copies with `mvindex(mvdedup(…),0)` (Phase 2C.1 `mvcount=3` still applies).
4. Table principal, dedicated MCP agent, tool, method `tools/call`, profile, mode.

`agentsec.delegator.agent.id` is **not** indexed on LAB-MCP-001 hop 0 (omitted at emit). Do not hunt it here.

## Expected result

One row per invoke that reached CTRL-MCP-001. HTTP schema failures that never authorize produce zero rows.

## Actual result

**VALIDATED** (Splunk CLI CSV, 2026-09-12).

| Run | principal | agent | tool | method | profile | mode |
|-----|-----------|-------|------|--------|---------|------|
| A BASELINE | `applicant-web` | `acme-agent-mcp-001` | `lookup_policy` | `tools/call` | defended | BASELINE |
| B ATTACK | `applicant-web` | `acme-agent-mcp-001` | `lookup_customer_tier` | `tools/call` | vulnerable | ATTACK |
| C RETEST | `applicant-web` | `acme-agent-mcp-001` | `lookup_customer_tier` | `tools/call` | defended | RETEST |

D/E/F also one row each. HTTP schema malformed: **0 rows**.

## Validated run.id / test data

`163d11e2-e751-4282-9406-19b490542ed4`, `5e8f55f3-eb46-47ee-b979-b72d9c9b1f49`, `7a1d37b5-d589-4dfd-8322-25ebd0152dbc`.

## Performance notes

Index + sourcetype + run.id + one event name. Lab-cheap.

## Known limitations

Does not prove execution. HTTP malformed requests never emit this control row.

## No-data semantics

Zero rows means this Splunk copy has no `agentsec.control.decision` for that `run.id`. That can be schema-validation-before-authorize, export loss, or a wrong run.id. It is not DENY.
