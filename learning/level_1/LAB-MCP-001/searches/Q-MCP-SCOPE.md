# Q-MCP-SCOPE

| Item | Value |
|------|--------|
| Query ID | `Q-MCP-SCOPE` |
| Security question | What scope was requested and what scope was granted? |
| Validation status | **VALIDATED** |
| Validation date | 2026-09-12 |
| SPL file | `Q-MCP-SCOPE.spl` |

## Required fields (indexed names)

`event.name`, `agentsec.run.id`, `gen_ai.tool.name`, `agentsec.mcp.requested_scope`, `agentsec.mcp.allowed_scope`, `agentsec.control.decision`

## SPL

See `Q-MCP-SCOPE.spl`.

## Line-by-line explanation

1. Control events only — scopes are emitted on `agentsec.control.decision`.
2. Compare requested vs coded `allowed_scope`.
3. Display helper `scope_relation`: `granted` when ALLOW and scopes match; `known_but_ungranted` when requested ≠ allowed (including fail-open ALLOW); `not_a_grant` for ERROR.

`allowed_scope` is the **coded policy wire** (`policy:read`), not “whatever the caller asked for.” Fail-open ALLOW does not rewrite allowed_scope.

## Expected result

- BASELINE: requested=allowed=`policy:read`, ALLOW, `granted`.
- ATTACK/RETEST: requested=`customer:read`, allowed=`policy:read`, `known_but_ungranted` (decision ALLOW vs DENY differs).

## Actual result

**VALIDATED.** A `granted`. B and C `known_but_ungranted`. D/E `not_a_grant`. F `granted`. HTTP malformed: 0 rows.

## Validated run.id / test data

A, B, C as catalog BASELINE/ATTACK/RETEST.

## Performance notes

One control event per run.

## Known limitations

Does not implement MCP-003/004 scope bypass labs. Helper column is display-only.

## No-data semantics

Zero rows: no control event in this copy, not “no scope was requested.”
