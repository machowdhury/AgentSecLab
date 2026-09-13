# SPL validation (Phase 2C.1)

## WHAT IS IT?

Four **investigation searches** for LAB-PI-001. They ask questions of indexed AgentSec events in Splunk. They do not ALLOW or DENY anything.

## WHY DOES IT EXIST?

Phase 2B proved the events arrive and fields extract. Detection engineering starts with questions you can actually run, not with notable event names. These four questions are: what happened in a run, what the control decided, whether the LLM call began, and whether telemetry claims LLM after DENY.

## HOW DOES IT WORK?

1. Filter `index=agentsec_telemetry sourcetype=otel:agentic:json` and one `agentsec.run.id`.
2. Use **indexed** field names (`event.name`, not `agentsec.event.name`).
3. Collapse duplicate field copies with `mvindex(mvdedup(field),0)` so counts match events. Body-only scalars appear twice (`INDEXED_EXTRACTIONS=json` plus `KV_MODE=json`). Keys also sent as OTLP attributes (`agentsec.run.id`) appear three times. `stats count by "agentsec.run.id"` therefore shows 66 for 22 unique events. That is not 66 indexed events.
4. Keep `agentsec.invariant.id{}` as a multivalue field.

## WHERE DOES IT SIT IN AGENTSEC?

After OBSERVE, before DETECT. Splunk is the workbench. AcmeBank remains the enforcement point.

## WHAT IS THE TRUST BOUNDARY?

Searches read an analytical copy. They cannot change CTRL-INPUT-001 or stop Ollama.

## WHAT COULD AN ATTACKER CONTROL?

Not these searches. They could try to confuse a future detection by shaping `input` text. The control decision is still server-side.

## WHAT CAN GO WRONG?

- Searching a conceptual field returns nothing (false sense of “no attacks”).
- `stats count by` a duplicated dotted field inflates counts.
- Treating “no llm.* in Splunk” as prevention when export was incomplete.

## WHAT TELEMETRY SHOULD EXIST?

Schema 1.0.0 events already defined. These searches only read them.

## HOW WILL SPLUNK SHOW IT?

Tables of sequence-ordered events, control rows, llm rows, or (for Q-LLM-AFTER-DENY) violation rows. Dashboards are later.

## WHAT CONTROL COULD CHANGE THE RESULT?

CTRL-INPUT-001 DENY removes llm.* from a complete copy. Changing the search does not change the runtime.

## WHAT TEST PROVES THE LOGIC?

Actual Splunk CLI execution on known BASELINE and defended ATK-002 run IDs (this phase). Pytest only checks that the search files stay honest about field names.

## What I should now be able to explain

1. Why `event.name` is the indexed name and `agentsec.event.name` is a false friend.
2. Why `agentsec.security.profile` is not `agentsec.profile`.
3. Why `agentsec.outcome` is not `agentsec.pipeline.outcome`.
4. Why `agentsec.invariant.id{}` is the Splunk mv field.
5. Why `stats count by "agentsec.run.id"` shows 66 for 22 unique events (mv explosion: 2 JSON extractions + 1 OTLP attribute).
6. Why ALLOW is not execution.
7. Why `executed=true` means the call began.
8. Why zero Q-LLM-AFTER-DENY rows is not independent prevention proof.
9. Why a complete local `events.jsonl` is still required for DENY proof.
10. What each of the four query IDs is for.
11. How a SIMULATED `makeresults` positive control differs from OBSERVED runtime evidence.
