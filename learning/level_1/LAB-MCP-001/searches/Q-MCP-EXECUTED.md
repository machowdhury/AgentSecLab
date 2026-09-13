# Q-MCP-EXECUTED

| Item | Value |
|------|--------|
| Query ID | `Q-MCP-EXECUTED` |
| Security question | Did the governed MCP operation begin? |
| Validation status | **VALIDATED** |
| Validation date | 2026-09-12 |
| SPL file | `Q-MCP-EXECUTED.spl` |

Do not infer success from `mcp.started`. Distinguish ALLOW-without-start-in-this-copy, `mcp.started`, `mcp.completed`, `mcp.failed`.

## Required fields (indexed names)

`event.name`, `agentsec.run.id`, `gen_ai.tool.name`, `agentsec.sequence`, `agentsec.control.decision`, `agentsec.operation.executed`, `agentsec.operation.outcome`

## SPL

See `Q-MCP-EXECUTED.spl`. `eventstats` per `run_id, tool` then keep the control row.

## Line-by-line explanation

1. Pull control + `mcp.started|completed|failed` for one run.
2. Flag which MCP execution events exist.
3. `eventstats max(…)` by run/tool.
4. Keep the control row. `execution_state` is `mcp.completed`, `mcp.failed`, `mcp.started`, `ALLOW_execution_not_proven_in_this_copy`, or `no_mcp_execution_event`.
5. The `executed` column is the **control** flag (`false`). That is not the handler flag. Use `execution_state` / `has_started`.

## Expected result

- A/B: ALLOW + `mcp.completed`.
- F: ALLOW + `mcp.failed` (execution then error, not prevention).
- C: DENY + `no_mcp_execution_event`.
- D/E: ERROR + `no_mcp_execution_event`.

## Actual result

**VALIDATED.** Matches the table above. HTTP malformed: 0 rows (no control event to hang state on).

## Validated run.id / test data

A, B, C, F as catalog.

## Performance notes

`eventstats` over one run’s control+mcp events. No join/transaction.

## Known limitations

Missing Splunk `mcp.*` on an ALLOW row is `ALLOW_execution_not_proven_in_this_copy` — export loss, not a runtime DENY. Runtime handler count is authoritative.

## No-data semantics

Zero rows: no control event. `no_mcp_execution_event` on a DENY row is corroboration of a complete copy, not independent proof the handler never ran.
