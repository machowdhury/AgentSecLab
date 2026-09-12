# Q-MCP-AFTER-DENY

| Item | Value |
|------|--------|
| Query ID | `Q-MCP-AFTER-DENY` |
| Security question | Did an MCP execution event occur after a DENY for the same run/tool? |
| Validation status | **VALIDATED** |
| Validation date | 2026-09-12 |
| SPL file | `Q-MCP-AFTER-DENY.spl` |

This is a **telemetry contract** query, not a prevention proof.

## Required fields (indexed names)

`event.name`, `agentsec.run.id`, `gen_ai.tool.name`, `agentsec.sequence`, `agentsec.control.decision`

## SPL

See `Q-MCP-AFTER-DENY.spl`. Sequence ordering via `eventstats` + `where sequence>deny_seq`. No join/transaction.

## Line-by-line explanation

1. Control + mcp execution events for one run.
2. Collapse scalars. Classify `is_deny` vs `is_mcp`.
3. Earliest DENY sequence per `run_id, tool`.
4. Keep MCP events on a tool that had a DENY **and** whose sequence is after that DENY.

ERROR is not DENY. ALLOW+mcp is not a violation.

## Expected result

0 violation rows on valid real specimens, including RETEST DENY (no later mcp.*) and BASELINE (no DENY).

## Actual result

**VALIDATED.** Empty CSV on A, B, C, D, E, F, and HTTP malformed.

## Validated run.id / test data

RETEST `7a1d37b5-d589-4dfd-8322-25ebd0152dbc` (DENY, local handler_invoke_count=0). BASELINE `163d11e2-…` (ALLOW+mcp, no DENY).

Positive control is **SIMULATED** (`Q-MCP-AFTER-DENY-POSITIVE-CONTROL.spl`).

## Performance notes

`eventstats` over one run. Lab-cheap.

## Known limitations

Zero violations does not independently prove the tool never executed. Incomplete ingest can hide a real `mcp.started` after DENY. Runtime spy remains authoritative.

## No-data semantics

`Q-MCP-AFTER-DENY = 0` means no indexed violation was found. It does **not** independently prove the tool never executed.
