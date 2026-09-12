# Q-MCP-AUTHZ

| Item | Value |
|------|--------|
| Query ID | `Q-MCP-AUTHZ` |
| Security question | What authorization decision was made? |
| Validation status | **VALIDATED** |
| Validation date | 2026-09-12 |
| SPL file | `Q-MCP-AUTHZ.spl` |

Do not collapse ERROR into DENY.

## Required fields (indexed names)

`event.name`, `agentsec.run.id`, `gen_ai.tool.name`, `agentsec.control.id`, `agentsec.control.decision`, `agentsec.control.reason`, `agentsec.mcp.requested_scope`, `agentsec.mcp.allowed_scope`, `agentsec.operation.attempted`, `agentsec.operation.executed`, `agentsec.operation.outcome`

## SPL

See `Q-MCP-AUTHZ.spl`.

## Line-by-line explanation

1. Same index/run filter as Q-MCP-WHO.
2. Only `event.name=agentsec.control.decision`.
3. Collapse scalars. KEEP `decision` as the raw token (`ALLOW` / `DENY` / `ERROR`).
4. Control-event `attempted`/`executed` are `false`. That is the control evaluation, not the handler. Outcome is empty on ALLOW; `prevented` on DENY/ERROR.

## Expected result

- BASELINE: ALLOW `tool_granted`, scopes both `policy:read`, outcome empty.
- ATTACK: ALLOW with labeled fail-open reason; requested `customer:read`, allowed still `policy:read`.
- RETEST: DENY `tool_not_granted`, outcome `prevented`.
- Unknown tool: ERROR `unknown_tool` (not DENY).
- Malformed args: ERROR `malformed_arguments` (not DENY).

## Actual result

**VALIDATED.**

| Run | decision | reason | requested | allowed | outcome |
|-----|----------|--------|-----------|---------|---------|
| A | ALLOW | `tool_granted` | policy:read | policy:read | (empty) |
| B | ALLOW | `vulnerable_profile_fail_open:CTRL-MCP-001…` | customer:read | policy:read | (empty) |
| C | DENY | `tool_not_granted` | customer:read | policy:read | prevented |
| D | ERROR | `unknown_tool` | policy:read | policy:read | prevented |
| E | ERROR | `malformed_arguments` | policy:read | policy:read | prevented |
| F | ALLOW | `tool_granted` | policy:read | policy:read | (empty) |

HTTP schema malformed: **0 rows** (no control event).

ALLOW `executed=false` on this row does **not** mean the handler was skipped. See Q-MCP-EXECUTED.

## Validated run.id / test data

A–F as in `catalog.json`.

## Performance notes

One event name on one run.id.

## Known limitations

Does not answer whether the handler began. Fail-open ALLOW is still ALLOW.

## No-data semantics

Zero rows: no indexed control decision. Not a DENY. HTTP schema failures look like this.
