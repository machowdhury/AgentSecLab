# DET-MCP-001 positive control

| Item | Value |
|------|--------|
| Query ID | `DET-MCP-001-POSITIVE-CONTROL` |
| Evidence class | **SIMULATED** |
| Test source | Splunk `makeresults` (search-time only). Not indexed. Not written to `index=agentsec_telemetry`. Not a runtime AcmeBank run. Not local `events.jsonl`. |
| Validation status | **SIMULATED** (sensitivity only) |
| SPL file | `DET-MCP-001-POSITIVE-CONTROL.spl` |

This is **not** OBSERVED runtime behavior. It exists only to prove DET-MCP-001 can return a row when DENY sequence 3 is followed by `mcp.started` sequence 4 for the same run/tool.

The hunt fixture `Q-MCP-AFTER-DENY-POSITIVE-CONTROL` remains VALIDATED and unchanged.

## Required fields (indexed names)

Synthetic copies of the DET-MCP-001 contract fields. Not read from the index.

## SPL

See `DET-MCP-001-POSITIVE-CONTROL.spl`. Generating commands are `makeresults` / `eval`. The violation block after field collapse matches `DET-MCP-001.spl`. Output adds `evidence_class=SIMULATED`.

## Line-by-line explanation

1. Build two in-memory rows. Label `evidence_class=SIMULATED`.
2. DENY at sequence 3, `agentsec.mcp.started` at sequence 4, same synthetic run/tool.
3. Apply the DET-MCP-001 block (`is_deny` / `is_started` / `eventstats` / `sequence>deny_sequence`).

## Expected result

Exactly **one** detection-shaped row: `deny_sequence=3`, `mcp_start_sequence=4`, `decision=DENY`, `evidence_class=SIMULATED`.

## Actual result

See `docs/PHASE3E_MCP_DETECTION.md`. Evidence class: **SIMULATED**.

## Validated run.id / test data

Synthetic `simulated-det-mcp-001-0001` only. Never present as OBSERVED runtime evidence.

## Performance notes

`makeresults count=2`. No index scan.

## Known limitations

Proves detection sensitivity only. Does not prove a real DENY-then-invoke runtime failure.

## No-data semantics

Does not apply to this fixture. Live DET-MCP-001 returning 0 is documented on `DET-MCP-001.md`.
