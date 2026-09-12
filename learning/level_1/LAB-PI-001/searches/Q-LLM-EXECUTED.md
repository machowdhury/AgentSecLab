# Q-LLM-EXECUTED

| Item | Value |
|------|--------|
| Query ID | `Q-LLM-EXECUTED` |
| Security question | Which governed LLM operations actually began and how did they end? |
| Validation status | **VALIDATED** |
| Validation date | 2026-09-11 |
| SPL file | `Q-LLM-EXECUTED.spl` |

## Required fields (indexed names)

`event.name`, `agentsec.run.id`, `agentsec.sequence`, `agentsec.hop.index`, `agentsec.operation.attempted`, `agentsec.operation.executed`, `agentsec.operation.outcome`, `gen_ai.agent.id`, `gen_ai.operation.name`, `gen_ai.provider.name`, `gen_ai.request.model`

## SPL

See `Q-LLM-EXECUTED.spl`.

Count form also executed on the defended run:

```
<same base filter>
| stats count as llm_events
```

## Line-by-line explanation

1. Filter the run and only `agentsec.llm.started`, `agentsec.llm.completed`, `agentsec.llm.failed`.
2. Collapse duplicate scalar copies.
3. `executed=true` on `llm.started` means the governed call **began**, not that it succeeded.
4. `outcome=success` is on `llm.completed`. `llm.started` has no outcome. `llm.failed` would be `outcome=error` (not prevented).

## Expected result

- BASELINE: 8 rows (4 started + 4 completed), hops 0–3, `attempted=true`, `executed=true`, completed `outcome=success`, `gen_ai.operation.name=chat`, provider `ollama`.
- Defended ATK-002: **zero rows**. Count form `llm_events=0`.

Zero Splunk `llm.*` is corroboration of a complete copy for that `run.id`. It is not independent runtime proof. Local `events.jsonl` / LLM spy remain authoritative.

## Actual result

**VALIDATED.**

BASELINE: 8 rows, sequences 4/5, 9/10, 14/15, 19/20; started has empty outcome; completed `success`; model `llama3.2:1b`.

Defended ATK-002: table form returned **no rows**; count form returned `llm_events=0`.

## Validated run.id / test data

`b3611d56-0d3f-4b2e-9a51-75ae36628155`, `78f05d1b-728e-4e70-8993-f5e365871f87`.

## False-positive / false-negative considerations

- FP: counting `llm.failed` as prevention. It is invocation-then-error.
- FN: incomplete export (sequence F) would also show zero `llm.*` on a run that invoked the model. Require local completeness before teaching “did not execute.”
- FN: searching `agentsec.llm.started` without `event.name=` may miss if you use a wrong field.

## Performance notes

Selective event-name OR on one run.id.

## Known limitations

Does not read Ollama itself. `executed=true` is the schema meaning “call began.”
