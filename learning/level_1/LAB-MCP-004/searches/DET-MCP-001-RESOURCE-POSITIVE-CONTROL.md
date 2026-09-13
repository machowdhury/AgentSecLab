# DET-MCP-001 resource teaching fixture

| Item | Value |
|------|--------|
| Query ID | `DET-MCP-001-RESOURCE-POSITIVE-CONTROL` |
| Evidence class | **SIMULATED** |
| Test source | Splunk `makeresults` (search-time only). Not indexed. Not written to `index=agentsec_telemetry`. Not a runtime AcmeBank run. Not local `events.jsonl`. |
| Validation status | **SIMULATED** (sensitivity only) |
| SPL file | `DET-MCP-001-RESOURCE-POSITIVE-CONTROL.spl` |

This is **not** OBSERVED runtime behavior. It exists only to teach that the **existing** DET-MCP-001 invariant still fires when the DENY reason is MCP-004 `resource_not_granted` and a later `mcp.started` shares the same run/tool.

This is **not** DET-MCP-004. Do not index it. Do not treat it as a new detector. Do not modify `DET-MCP-001.spl`.

The original `DET-MCP-001-POSITIVE-CONTROL` and `DET-MCP-001-SCOPE-POSITIVE-CONTROL` remain unchanged.

## Required fields (indexed names)

Synthetic copies of the DET-MCP-001 contract fields. Resource id/grant are teaching context on the DENY row only; the detector still correlates `run_id` + `tool`.

## SPL

See `DET-MCP-001-RESOURCE-POSITIVE-CONTROL.spl`. Generating commands are `makeresults` / `eval`. The violation block after field collapse matches `DET-MCP-001.spl`. Output adds `evidence_class=SIMULATED`.

Teaching context on the DENY row: `reason=resource_not_granted`, `resource.id=executive-restricted`, `allowed_resource.ids=lending-basics`, `requested_scope=policy:read`.

## Line-by-line explanation

1. Build two in-memory rows. Label `evidence_class=SIMULATED`.
2. DENY at sequence 3 with MCP-004 resource mismatch, `agentsec.mcp.started` at sequence 4, same synthetic run/tool (`lookup_policy`).
3. Apply the DET-MCP-001 block (`is_deny` / `is_started` / `eventstats` / `sequence>deny_sequence`).

## Expected result

Exactly **one** detection-shaped row: `deny_sequence=3`, `mcp_start_sequence=4`, `decision=DENY`, `evidence_class=SIMULATED`.

## Actual result

See `docs/PHASE5C_MCP004_SPLUNK_VALIDATION.md`. Evidence class: **SIMULATED**. Indexed count for `simulated-det-mcp-001-resource-0001` = **0**.

## Validated run.id / test data

Synthetic `simulated-det-mcp-001-resource-0001` only. Never present as OBSERVED runtime evidence.

## Performance notes

`makeresults count=2`. No index scan. No `join` / `transaction` / `map`.

## Known limitations

Proves detection sensitivity on a resource-context DENY only. Does not prove a real DENY-then-invoke runtime failure. Live MCP-004 RETEST has DENY and no later `mcp.started`.

DET-MCP-001 still groups by `run_id` + tool. A future run with two `lookup_policy` calls (granted then ungranted) could mis-correlate. Do not invent `invocation.id` in this phase.

## No-data semantics

Does not apply to this fixture. Live DET-MCP-001 returning 0 is documented in Phase 5C and does **not** prove the handler never ran.
