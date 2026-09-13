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
3. Display helper `scope_relation` (eval `case()` order matters):
   - `not_a_grant` when `decision=ERROR` (**first**)
   - `granted` when ALLOW and scopes match
   - `known_but_ungranted` when requested ≠ allowed (including fail-open ALLOW and defended DENY mismatch)
   - `denied_without_scope_mismatch` when DENY and scopes match
   - `other` otherwise

`allowed_scope` is the **coded policy wire** (`policy:read`), not “whatever the caller asked for.” Fail-open ALLOW does not rewrite allowed_scope.

ERROR is not a grant decision. It is also not DENY. The helper must not label `unknown_scope` or `missing_requested_scope` as `known_but_ungranted`.

## Contract gap (documented before the helper order change)

Phase 4C live MCP-003 specimens D (`policy:write`, ERROR `unknown_scope`) and E (`unspecified`, ERROR `missing_requested_scope`) both have `requested_scope != allowed_scope`.

The previous `case()` tested mismatch **before** `decision="ERROR"`. Live CLI therefore labeled D and E `known_but_ungranted`. That contradicted this file’s intended `not_a_grant` for ERROR and silently treated ERROR as a scope-grant story.

Correction (same query ID, not a new Q-MCP-003 search): evaluate `decision="ERROR"` first. LAB-MCP-001 D/E (ERROR with matching or later ERROR clause) remain `not_a_grant`. MCP-003 A/B/C/F labels are unchanged.

## Expected result

LAB-MCP-001:

- BASELINE: requested=allowed=`policy:read`, ALLOW, `granted`.
- ATTACK/RETEST: requested=`customer:read`, allowed=`policy:read`, `known_but_ungranted` (decision ALLOW vs DENY differs).
- ERROR paths: `not_a_grant`.

MCP-003 (same SPL):

- BASELINE: requested=allowed=`policy:read`, ALLOW, `granted`.
- ATTACK/RETEST: requested=`policy:restricted:read`, allowed=`policy:read`, `known_but_ungranted`.
- UNKNOWN SCOPE / missing scope ERROR: `not_a_grant` even when the strings differ.

## Actual result

LAB-MCP-001 Phase 3C: A `granted`. B and C `known_but_ungranted`. D/E `not_a_grant`. F `granted`. HTTP malformed: 0 rows.

MCP-003 Phase 4C (after helper-order correction, same indexed data): A `granted`. B/C `known_but_ungranted`. D/E `not_a_grant`. F `granted`. Pre-correction D/E were `known_but_ungranted` (MEASURED gap).

## Validated run.id / test data

LAB-MCP-001 A, B, C as catalog BASELINE/ATTACK/RETEST.

MCP-003 live: `docs/PHASE4C_MCP003_SPLUNK_VALIDATION.md`.

## Performance notes

One control event per run. Index, sourcetype, `run.id`, `event.name`, `eval`, `table`. No `join` / `transaction` / `map`.

## Known limitations

Display helper only. Does not enforce scope. Does not implement MCP-004. MCP-003 reuses this search; it does not need a duplicate query ID.

## No-data semantics

Zero rows: no control event in this copy, not “no scope was requested.”
