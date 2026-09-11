# Phase 2 runtime

**Status:** Phase 2A first trustworthy slice is IMPLEMENTED in `src/agentsec/` and stub/security tests. See `docs/PHASE2A_RUNTIME_VALIDATION.md`. Live Ollama success was SKIPPED in that run. Splunk export is NOT ATTEMPTED.

The **event contract** is Phase 1B (`SECURITY_EVENT_MODEL.md`, schema 1.0.0).

## WHAT IS IT?

Phase 2A is the first honest AgentSec range loop: AcmeBank `POST /process`, four sequential agents, one legitimate loan, Attack Service with one prompt-injection, CTRL-INPUT-001 before Ollama, closed-schema events, and `artifacts/<run-id>/` packs.

## WHY DOES IT EXIST?

Architecture docs cannot prove INV-008. You need DENY before the model, with a spy on the LLM client.

## HOW DOES IT WORK?

1. Explicit benign `POST /process` (`testbed.mode=BASELINE`, `execution.mode=LIVE`, `telemetry.fidelity=OBSERVED`).
2. `CTRL-INPUT-001` inspects the text.
3. DENY/ERROR **before invoke** → no Ollama call, attempted=false, executed=false, outcome=prevented.
4. If an LLM call **starts** and then fails → attempted=true, executed=true, outcome=error.
5. ALLOW → Intake → Credit → Risk → Compliance, each with the same `agentsec.run.id` = `agentsec.incident.id`.
6. Events go to memory and a local evidence pack. OTLP is optional and off by default in Phase 2A.

Attack Service only POSTs ATK-002 to `/process`. It cannot call Ollama.

## WHERE DOES IT SIT IN AGENTSEC?

Defend/offense runtime under LEARN → BASELINE → ATTACK → OBSERVE. No MCP, A2A, memory, RAG, MLTK, Cisco, ticker, or governance dashboards.

## WHAT IS THE TRUST BOUNDARY?

The AcmeBank HTTP API. Attack Service is untrusted. Ollama output is untrusted data. Splunk cannot ALLOW a loan.

## WHAT COULD AN ATTACKER CONTROL?

The `input` string, optional `user_id` label. Not profile, `run.id`, `incident.id`, control decision, schema version, operation flags, or experiment dimensions.

## WHAT CAN GO WRONG?

- Vulnerable profile fail-open (labeled).
- Collector/Splunk unused → incomplete Splunk, local artifacts still exist.
- Live small models are nondeterministic; stub tests plus the LLM spy are the DENY proof.

## WHAT TELEMETRY SHOULD EXIST?

Closed fields in `schemas/security_event.schema.json` (schema **1.0.0**). Contract event names are `run.*`, `hop.*`, `control.decision`, `llm.*`, `pipeline.stopped`. Withdrawn names (`normal_request`, `prompt_attack`) are not emitted.

## HOW WILL SPLUNK SHOW IT?

Not in Phase 2A. `export.json` records that Splunk export has not been attempted / NOT VERIFIED.

## WHAT CONTROL COULD CHANGE THE RESULT?

`CTRL-INPUT-001` in `defended`. `vulnerable` allows the same payload through and writes a fail-open reason that names the lab reference control.

## WHAT TEST PROVES THE LOGIC?

`tests/security/test_input_control_before_llm.py::test_defended_atk002_negative_contract` — stub/spy LLM call list stays empty on ATK-002.

## What I should now be able to explain

1. Why four agents in one process is not A2A.
2. Where the trust boundary is.
3. What happens if DENY is recorded after Ollama already ran.
4. Why Attack Service must not import the LLM client.
5. What `agentsec.run.id` is for, and why it equals `incident.id`.
6. Why HTTP cannot set `testbed.mode`, `execution.mode`, or `telemetry.fidelity`.
7. Why `executed=true` is “call began,” not “call succeeded.”
8. How `vulnerable` is still a teaching profile, not a silent bypass.
9. Why empty input is ERROR in both profiles.
10. What was intentionally left out of Phase 2A.
