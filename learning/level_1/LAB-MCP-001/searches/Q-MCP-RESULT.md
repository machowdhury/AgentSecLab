# Q-MCP-RESULT

| Item | Value |
|------|--------|
| Query ID | `Q-MCP-RESULT` |
| Security question | What result did the MCP tool produce? |
| Validation status | **VALIDATED** |
| Validation date | 2026-09-12 |
| SPL file | `Q-MCP-RESULT.spl` |

Full tool payloads are **not** a dedicated indexed schema. Completed events carry preview + hash + trust markers. Failed events have outcome `error` and no result preview.

## Required fields (indexed names)

`event.name`, `agentsec.run.id`, `gen_ai.tool.name`, `agentsec.sequence`, `agentsec.operation.outcome`, `agentsec.content.hash`, `agentsec.content.preview`, `agentsec.mcp.result.trust`, `agentsec.mcp.result.provenance`

## SPL

See `Q-MCP-RESULT.spl`. `mcp.completed` OR `mcp.failed`. Do not search `_raw` for a fuller dump.

## Line-by-line explanation

1. Terminal MCP execution events only.
2. Collapse scalars.
3. On completed: hash/preview of the fixture JSON, `result.trust=untrusted_data`, provenance `mcp.tool.handler`, outcome `success`.
4. On failed: outcome `error`; preview/trust empty because no result was produced.

Do not weaken the evidence model to invent a pretty result object.

## Expected result

- A/B: one `mcp.completed` row, lab fixture preview, `untrusted_data`.
- F: one `mcp.failed` row, empty result columns.
- C/D/E: zero rows.

## Actual result

**VALIDATED.** A/B as expected. F: `mcp.failed` sequence 5, outcome `error`, empty hash/trust/preview. C/D/E/HTTP: empty CSV.

## Validated run.id / test data

A `163d11e2-…`, B `5e8f55f3-…`, F `5b83b6e4-…`.

## Performance notes

Two event names on one run.

## Known limitations

Preview is capped at 200 characters. Trust classification is preparatory (MCP-005 not implemented). `mcp.started` is not a result.

## No-data semantics

Zero rows: no completed/failed MCP event in this copy. That includes DENY, ERROR, and schema failure. Not a result of `null`.
