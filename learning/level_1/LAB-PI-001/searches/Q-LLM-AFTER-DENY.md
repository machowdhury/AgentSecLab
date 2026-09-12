# Q-LLM-AFTER-DENY

| Item | Value |
|------|--------|
| Query ID | `Q-LLM-AFTER-DENY` |
| Security question | Did a governed LLM operation begin after a pre-invocation DENY? |
| Validation status | **VALIDATED** |
| Validation date | 2026-09-11 |
| SPL file | `Q-LLM-AFTER-DENY.spl` |

This is a **telemetry contract** query, not a prevention proof.

It returns rows only for the INVALID condition: a `control.decision=DENY` on a hop, and a later `llm.started` / `llm.completed` / `llm.failed` on the **same** `run.id` + `hop.index` with `sequence` greater than the DENY sequence.

A normal defended ATK-002 run should return **zero rows**.

Zero violations means: in this complete Splunk copy, no DENY-then-LLM sequence was observed. It does **not** independently prove the runtime never called Ollama. Runtime evidence remains authoritative.

## Required fields (indexed names)

`event.name`, `agentsec.run.id`, `agentsec.sequence`, `agentsec.hop.index`, `agentsec.control.decision`

## SPL

See `Q-LLM-AFTER-DENY.spl`.

## Line-by-line explanation

1. Pull control and llm events for one run.
2. Collapse duplicate copies; classify `is_deny` vs `is_llm`.
3. `eventstats` computes the earliest DENY sequence per `run_id, hop_index`.
4. Keep only LLM events on a hop that had a DENY **and** whose sequence is after that DENY.

BASELINE has no DENY, so the `where` clause yields zero rows (not a violation; there was nothing to violate).

## Expected result

- Defended ATK-002: **0 rows**.
- BASELINE: **0 rows** (no DENY).

## Actual result

**VALIDATED.** Both runs: empty CSV (zero violations).

## Validated run.id / test data

`78f05d1b-728e-4e70-8993-f5e365871f87` (DENY, no llm.* locally or in Splunk).  
`b3611d56-0d3f-4b2e-9a51-75ae36628155` (ALLOW + llm; no DENY).

This query was given a **SIMULATED** positive-control fixture (`Q-LLM-AFTER-DENY-POSITIVE-CONTROL.spl`, `makeresults` only). That search returned exactly one violation row. It is not OBSERVED runtime behavior and was not indexed.

## False-positive / false-negative considerations

- FP: LLM on a **later hop** after hop-0 DENY cannot happen in this pipeline (it stops). The join is per hop to avoid a false story if a future lab continues after DENY.
- FN: if DENY and llm.* land in Splunk without `hop.index`, the join would miss. First-lab control/llm events have hop.index.
- FN: incomplete Splunk copy (export loss) can hide a real llm.* after DENY. Do not use this query as sole proof.
- Searching only “no llm.* on the run” without checking DENY sequence is weaker; this query is the sequence-aware form.

## Performance notes

`eventstats` over one run’s control+llm events. Lab-cheap.

## Known limitations

Not a detection. Not a substitute for the LLM spy / local `events.jsonl`. The positive-control hit is SIMULATED via `makeresults`; it does not prove a real DENY-then-invoke runtime failure.
