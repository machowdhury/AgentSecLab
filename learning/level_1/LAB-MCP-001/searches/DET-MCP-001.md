# DET-MCP-001 — MCP execution after authorization DENY

| Item | Value |
|------|--------|
| Detection ID | `DET-MCP-001` |
| Saved search | `AgentSec - MCP Execution After Authorization Deny` |
| Severity | **HIGH** |
| Default | **disabled** (`savedsearches.conf`) |
| Validation status | live negatives **MEASURED** in `docs/PHASE3E_MCP_DETECTION.md`; positive control **SIMULATED** |
| SPL file | `DET-MCP-001.spl` |

This is **one** operational detection of a high-confidence invariant violation. It does **not** detect every MCP authorization bypass.

## Detection objective

Did an MCP tool execution begin after CTRL-MCP-001 denied the same run/tool?

## Invariant

If CTRL-MCP-001 returns DENY for a run/tool, no later `event.name=agentsec.mcp.started` may occur for that same `agentsec.run.id` and `gen_ai.tool.name` with `agentsec.sequence` greater than the DENY sequence.

## Required fields (indexed names)

`event.name`, `agentsec.run.id`, `gen_ai.tool.name`, `agentsec.sequence`, `agentsec.control.decision`, `gen_ai.agent.id`, `agentsec.principal.id`, `agentsec.control.id`, `agentsec.security.profile`, `agentsec.testbed.mode`, `agentsec.mcp.requested_scope`, `agentsec.mcp.allowed_scope`, `trace_id`

Scopes and `control.id` exist on the DENY control event. The detection copies them onto the `mcp.started` row with `eventstats` (same run/tool). It does not invent values.

## SPL

See `DET-MCP-001.spl`. Operationalization of `Q-MCP-AFTER-DENY.spl`:

- No `__RUN_ID__` (continuous check, not a hunt token).
- `mcp.started` only, not `mcp.completed` / `mcp.failed`.
- Identity / scope / `trace_id` carried from the DENY event.
- Time window is `dispatch.earliest_time` / `dispatch.latest_time` on the saved search (`-24h` to `now`). The `.spl` file has no `earliest=` so lab validation can override.

Hunt query `Q-MCP-AFTER-DENY` is unchanged.

## Line-by-line explanation

1. Index + sourcetype. Only `control.decision` and `mcp.started`.
2. Collapse multivalue copies (`mvindex(mvdedup(...),0)`).
3. Classify DENY vs `mcp.started`.
4. Per `run_id, tool`: earliest DENY sequence; copy DENY identity/scope; capture start `trace_id`.
5. Keep `mcp.started` rows with `sequence > deny_sequence` on a tool that had a DENY.
6. Output the detection contract columns. `decision` is the prior DENY (context), not a claim that the start event itself was a DENY.

## What this does not alert on

DENY alone. ALLOW. vulnerable fail-open ALLOW. mcp.failed after ALLOW. unknown tool ERROR. malformed args ERROR. zero MCP execution rows.

## Expected result

0 rows on validated LIVE specimens. 1 row on `DET-MCP-001-POSITIVE-CONTROL` (**SIMULATED**).

## Actual result

See `docs/PHASE3E_MCP_DETECTION.md`.

## Validated run.id / test data

Negatives: Phase 3C specimens A–F listed in `searches/catalog.json`. Positive: synthetic `simulated-det-mcp-001-0001` only.

## Performance notes

Index + sourcetype + two `event.name` values. `eventstats` by `run_id, tool`. Lab-cheap. Saved search window `-24h`. No `join` / `transaction` / `map`.

## Known limitations

Zero detections does not independently prove the handler never ran. Incomplete ingest can hide a true `mcp.started` after DENY. Runtime spy remains authoritative. Splunk does not enforce authorization. This is not a general MCP bypass detector.

## No-data semantics

0 rows = no indexed DENY-then-`mcp.started` sequence in the search window. Not DENY. Not all-clear. Not prevention.
