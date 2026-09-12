# Q-MCP-TOOL

| Item | Value |
|------|--------|
| Query ID | `Q-MCP-TOOL` |
| Security question | Which tool executions actually began? |
| Validation status | **VALIDATED** |
| Validation date | 2026-09-12 |
| SPL file | `Q-MCP-TOOL.spl` |

Uses `mcp.started` as corroborating telemetry. Do not equate ALLOW with execution.

## Required fields (indexed names)

`event.name`, `agentsec.run.id`, `gen_ai.tool.name`, `agentsec.sequence`, `agentsec.operation.executed`, `agentsec.operation.outcome`

## SPL

See `Q-MCP-TOOL.spl`. Filter `"event.name"=agentsec.mcp.started` only.

## Line-by-line explanation

1. Index/run filter.
2. Only `agentsec.mcp.started` — the schema event that means the handler **began**.
3. Collapse scalars. `executed=true` on this event. Outcome is empty on started (success/error land on completed/failed).

## Expected result

- A/B/F: one row, sequence 4, `executed=true`, empty outcome.
- C/D/E: zero rows (no start). Zero Splunk rows is corroboration of a complete copy, not independent prevention proof. Runtime handler count remains authoritative for RETEST.

## Actual result

**VALIDATED.** A, B, F: 1 row each (`lookup_policy` / `lookup_customer_tier` / `lookup_policy`). C, D, E, HTTP malformed: empty CSV.

## Validated run.id / test data

A `163d11e2-…`, B `5e8f55f3-…`, C `7a1d37b5-…` (0 rows; local handler_invoke_count=0).

## Performance notes

Single event name.

## Known limitations

`mcp.started` is not success. Incomplete export could hide a real start.

## No-data semantics

Zero rows does **not** automatically mean DENY. ERROR, schema failure, and incomplete ingest also yield zero `mcp.started`.
