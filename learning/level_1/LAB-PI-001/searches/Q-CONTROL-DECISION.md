# Q-CONTROL-DECISION

| Item | Value |
|------|--------|
| Query ID | `Q-CONTROL-DECISION` |
| Security question | What security decisions were made, by which control, and at which hop? |
| Validation status | **VALIDATED** |
| Validation date | 2026-09-11 |
| SPL file | `Q-CONTROL-DECISION.spl` |

## Required fields (indexed names)

`event.name`, `agentsec.run.id`, `agentsec.sequence`, `agentsec.hop.index`, `agentsec.control.id`, `agentsec.control.type`, `agentsec.control.decision`, `agentsec.control.reason`, `agentsec.security.profile`, `agentsec.operation.attempted`, `agentsec.operation.executed`, `agentsec.operation.outcome`, `agentsec.invariant.id{}`, `gen_ai.agent.id`, `gen_ai.agent.name`

## SPL

See `Q-CONTROL-DECISION.spl`. Filter `"event.name"=agentsec.control.decision` (not `agentsec.event.name`).

## Line-by-line explanation

1. Same index/sourcetype/run filter as Q-RUN-EVENTS.
2. Restrict to control events via `event.name`.
3. Collapse scalar duplicates with `mvindex(mvdedup(…),0)`.
4. Keep the JSON array as Splunk mv: `agentsec.invariant.id{}` then `mvjoin(mvdedup(…), ",")` for a readable cell.
5. ALLOW rows omit `operation.outcome` in schema 1.0.0; the `outcome` column is empty. That is not a miss.

## Expected result

- BASELINE: four rows, hops 0–3, `CTRL-INPUT-001`, `ALLOW`, `attempted=false`, `executed=false`, empty outcome, then LLM events exist separately (this query does not prove execution).
- Defended ATK-002: one hop-0 row, `DENY`, `input_pattern_matched`, `attempted=false`, `executed=false`, `outcome=prevented`.

## Actual result

**VALIDATED.**

BASELINE: 4 ALLOW rows, hops 0–3, agents intake/credit/risk/compliance, invariants `INV-004,INV-007` (hop 0) and `INV-002,INV-004,INV-007` (later hops), outcome blank.

Defended ATK-002: 1 DENY row, hop 0, `prevented`, invariants `INV-008,INV-007`.

## Validated run.id / test data

`b3611d56-0d3f-4b2e-9a51-75ae36628155`, `78f05d1b-728e-4e70-8993-f5e365871f87`.

## False-positive / false-negative considerations

- FP: treating ALLOW as “the model ran.” It did not; check Q-LLM-EXECUTED.
- FN: querying `agentsec.invariant.id` without `{}` may miss the mv field on this sourcetype.
- FN: boolean tokens are the strings `true`/`false`.

## Performance notes

Highly selective (`event.name` + run.id). Lab-cheap.

## Known limitations

Does not answer execution. `invariants` concatenation is display-only; the mv field remains the native array.
