# Q-MCP-AFTER-DENY positive control

| Item | Value |
|------|--------|
| Query ID | `Q-MCP-AFTER-DENY-POSITIVE-CONTROL` |
| Evidence class | **SIMULATED** |
| Test source | Splunk `makeresults` (search-time only). Not indexed. Not written to `index=agentsec_telemetry`. Not a runtime AcmeBank run. Not local `events.jsonl`. |
| Validation status | **VALIDATED** (SIMULATED) |
| Validation date | 2026-09-12 |

This is **not** OBSERVED runtime behavior. It exists only to prove the violation query can return a row when the invalid sequence is present.

## Required fields (indexed names)

Synthetic copies of `event.name`, `agentsec.run.id`, `gen_ai.tool.name`, `agentsec.sequence`, `agentsec.control.decision`. Not read from the index.

## SPL

See `Q-MCP-AFTER-DENY-POSITIVE-CONTROL.spl`. Generating commands are `makeresults` / `eval`. The violation block after field collapse is the same logic as `Q-MCP-AFTER-DENY.spl`.

## Line-by-line explanation

1. Build two in-memory rows. Label `evidence_class=SIMULATED`.
2. DENY at sequence 3, `agentsec.mcp.started` at sequence 4, same synthetic `run.id` and tool `lookup_customer_tier`.
3. Apply the live violation block (`is_deny` / `is_mcp` / `eventstats` / `sequence>deny_seq`).

## Expected result

Exactly **one** violation row: sequence 4, `agentsec.mcp.started`, `deny_seq=3`, `evidence_class=SIMULATED`.

## Actual result

**VALIDATED** against Splunk CLI `-output csv` on 2026-09-12. Evidence class: **SIMULATED**.

| run_id | tool | deny_seq | sequence | event_name | decision | evidence_class |
|--------|------|----------|----------|------------|----------|----------------|
| `simulated-q-mcp-after-deny-0001` | `lookup_customer_tier` | 3 | 4 | `agentsec.mcp.started` | (empty) | `SIMULATED` |

Index leak check: `index=agentsec_telemetry "agentsec.run.id"=simulated-q-mcp-after-deny-0001 | stats count` returned **0**.

## Validated run.id / test data

Synthetic `simulated-q-mcp-after-deny-0001` only. Never present as OBSERVED runtime evidence.

## Performance notes

`makeresults count=2`. No index scan.

## Known limitations

Proves query sensitivity only. Does not prove a real DENY-then-invoke runtime failure.

## No-data semantics

Does not apply to this fixture. The live invariant query returning 0 is documented on `Q-MCP-AFTER-DENY.md`.
