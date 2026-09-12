# Q-LLM-AFTER-DENY positive control

| Item | Value |
|------|--------|
| Query ID | `Q-LLM-AFTER-DENY-POSITIVE-CONTROL` |
| Evidence class | **SIMULATED** |
| Test source | Splunk `makeresults` (search-time only). Not indexed. Not written to `index=agentsec_telemetry`. Not a runtime AcmeBank run. Not local `events.jsonl`. |
| Validation status | **VALIDATED** (SIMULATED) |
| Validation date | 2026-09-11 |

This is **not** OBSERVED runtime behavior. It exists only to prove the violation query can return a row when the invalid sequence is present.

## Simulated events (2)

1. `event.name=agentsec.control.decision`, `agentsec.control.decision=DENY`, `agentsec.sequence=3`, hop `0`
2. `event.name=agentsec.llm.started`, `agentsec.sequence=4`, same `run.id`, same hop `0`

Synthetic `run.id`: `simulated-q-llm-after-deny-0001`

## Expected result

Exactly **one** violation row: sequence 4, `agentsec.llm.started`, `deny_seq=3`.

## Actual result

**VALIDATED** against Splunk CLI `-output csv` on 2026-09-11. Evidence class: **SIMULATED**.

Exactly **1** row:

| run_id | hop_index | deny_seq | sequence | event_name | decision | evidence_class |
|--------|-----------|----------|----------|------------|----------|----------------|
| `simulated-q-llm-after-deny-0001` | 0 | 3 | 4 | `agentsec.llm.started` | (empty; llm.started has no control decision) | `SIMULATED` |

Index leak check: `index=agentsec_telemetry "agentsec.run.id"=simulated-q-llm-after-deny-0001 | stats count` returned **0**. The fixture was not written to the AgentSec evidence stream.

## SPL

See `Q-LLM-AFTER-DENY-POSITIVE-CONTROL.spl`. Generating commands are `makeresults` / `eval`. The violation block after field collapse is the same logic as `Q-LLM-AFTER-DENY.spl`.
