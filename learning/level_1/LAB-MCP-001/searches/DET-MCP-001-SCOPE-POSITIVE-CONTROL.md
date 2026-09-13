# DET-MCP-001 scope teaching fixture

| Item | Value |
|------|--------|
| Query ID | `DET-MCP-001-SCOPE-POSITIVE-CONTROL` |
| Evidence class | **SIMULATED** |
| Test source | Splunk `makeresults` (search-time only). Not indexed. Not written to `index=agentsec_telemetry`. Not a runtime AcmeBank run. Not local `events.jsonl`. |
| Validation status | **SIMULATED** (sensitivity only) |
| SPL file | `DET-MCP-001-SCOPE-POSITIVE-CONTROL.spl` |

This is **not** OBSERVED runtime behavior. It exists only to teach that the **existing** DET-MCP-001 invariant still fires when the DENY reason is MCP-003 `scope_not_granted` and a later `mcp.started` shares the same run/tool.

This is **not** DET-MCP-003. Do not index it. Do not treat it as a new detector.

The original `DET-MCP-001-POSITIVE-CONTROL` remains VALIDATED and unchanged.

## Required fields (indexed names)

Synthetic copies of the DET-MCP-001 contract fields. Not read from the index.

## SPL

See `DET-MCP-001-SCOPE-POSITIVE-CONTROL.spl`. Generating commands are `makeresults` / `eval`. The violation block after field collapse matches `DET-MCP-001.spl`. Output adds `evidence_class=SIMULATED`.

Teaching context on the DENY row: `reason=scope_not_granted`, `requested_scope=policy:restricted:read`, `allowed_scope=policy:read`.

## Line-by-line explanation

1. Build two in-memory rows. Label `evidence_class=SIMULATED`.
2. DENY at sequence 3 with MCP-003 scope mismatch, `agentsec.mcp.started` at sequence 4, same synthetic run/tool (`lookup_policy`).
3. Apply the DET-MCP-001 block (`is_deny` / `is_started` / `eventstats` / `sequence>deny_sequence`).

## Expected result

Exactly **one** detection-shaped row: `deny_sequence=3`, `mcp_start_sequence=4`, `decision=DENY`, `requested_scope=policy:restricted:read`, `allowed_scope=policy:read`, `evidence_class=SIMULATED`.

## Actual result

See `docs/PHASE4C_MCP003_SPLUNK_VALIDATION.md`. Evidence class: **SIMULATED**.

## Validated run.id / test data

Synthetic `simulated-det-mcp-001-scope-0001` only. Never present as OBSERVED runtime evidence.

## Performance notes

`makeresults count=2`. No index scan. No `join` / `transaction` / `map`.

## Known limitations

Proves detection sensitivity on a scope-context DENY only. Does not prove a real DENY-then-invoke runtime failure. Live MCP-003 RETEST has DENY and no later `mcp.started`.

## No-data semantics

Does not apply to this fixture. Live DET-MCP-001 returning 0 is documented in Phase 4C and does **not** prove the handler never ran.
