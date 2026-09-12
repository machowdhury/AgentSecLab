# Q-MCP-RESULT-TRUST

| Item | Value |
|------|--------|
| Query ID | `Q-MCP-RESULT-TRUST` |
| Security question | How is returned MCP content classified? |
| Validation status | **VALIDATED** |
| Validation date | 2026-09-12 |
| SPL file | `Q-MCP-RESULT-TRUST.spl` |

Preparatory only. Does **not** implement MCP-005 (result used as authority).

## Required fields (indexed names)

`event.name`, `agentsec.run.id`, `gen_ai.tool.name`, `agentsec.mcp.result.trust`, `agentsec.mcp.result.provenance`, `agentsec.operation.outcome`

## SPL

See `Q-MCP-RESULT-TRUST.spl`. Filter `event.name=agentsec.mcp.completed` because trust markers are emitted only on completed results.

## Line-by-line explanation

1. Completed tool results only.
2. Table `agentsec.mcp.result.trust` (current marker: `untrusted_data`) and provenance `mcp.tool.handler`.

`mcp.failed` has no result to classify. DENY/ERROR never produce this row.

## Expected result

A/B: `untrusted_data` / `mcp.tool.handler` / `success`. C/D/E/F: zero rows.

## Actual result

**VALIDATED.** A and B one row each `untrusted_data`. F empty (failed, no completed result). C/D/E/HTTP empty.

## Validated run.id / test data

A `163d11e2-e751-4282-9406-19b490542ed4`, B `5e8f55f3-eb46-47ee-b979-b72d9c9b1f49`.

## Performance notes

One event name.

## Known limitations

Does not detect “result used as a new grant.” Policy remains coded. MCP-005 is out of scope.

## No-data semantics

Zero rows: no completed MCP result in this copy. Not proof that returned content was trusted.
