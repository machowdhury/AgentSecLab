# Phase 2 runtime

**Status:** EXPERIMENTAL code under `src/agentsec/`. The **event contract** is Phase 1B (`SECURITY_EVENT_MODEL.md`). This note describes the existing thin runtime, which may still emit withdrawn event names. Do not treat this file as the telemetry contract.

**Status after this implementation:** core loop IMPLEMENTED in code and tests. Live Ollama / live Splunk HEC are **not claimed** unless you start Compose and check them.

## WHAT IS IT?

Phase 2 is the first running AgentSec range: AcmeBank (four sequential agents), one legitimate loan, benign baseline ticks, Attack Service with one prompt-injection, one input control before Ollama, OpenTelemetry export, closed-schema events, Splunk ingest config, and `artifacts/<run-id>/` packs.

## WHY DOES IT EXIST?

Architecture docs cannot prove INV-008. You need a path where malicious text is DENY **before** the model, with a `run.id` you can hunt.

## HOW DOES IT WORK?

1. Browser or explicit benign `POST /process` sends a loan request to AcmeBank (`testbed.mode=BASELINE`, `execution.mode=LIVE`, `telemetry.fidelity=OBSERVED`).
2. `CTRL-INPUT-001` inspects the text.
3. DENY/ERROR **before invoke** → no Ollama call, attempted=false, executed=false, outcome=prevented. If an LLM call **starts** and then fails → attempted=true, executed=true, outcome=error.
4. ALLOW → Intake → Credit → Risk → Compliance, each with the same `agentsec.run.id` = `agentsec.incident.id`.
5. Events go to an in-memory sink, a local evidence pack, and (if enabled) OTLP → collector → Splunk HEC.

Attack Service only POSTs ATK-002 to `/api/v1/process`. It cannot call Ollama.

## WHERE DOES IT SIT IN AGENTSEC?

This is the defend/offense runtime under LEARN → BASELINE → ATTACK → OBSERVE. No MCP, A2A, memory, RAG, MLTK, Cisco, or governance dashboards.

## WHAT IS THE TRUST BOUNDARY?

The AcmeBank HTTP API. Attack Service is untrusted. Ollama output is untrusted data. Splunk cannot ALLOW a loan.

## WHAT COULD AN ATTACKER CONTROL?

The `input` string, optional `user_id` / `technique_id` labels. Not profile, `run.id`, `incident.id`, control decision, schema version, operation flags, or `testbed.mode` / `execution.mode` / `telemetry.fidelity`.

## WHAT CAN GO WRONG?

- Vulnerable profile fail-open (labeled).
- Collector down → incomplete Splunk, local artifacts still exist.
- Live small models are nondeterministic; stub tests are the DENY proof.

## WHAT TELEMETRY SHOULD EXIST?

Closed fields in `schemas/security_event.schema.json` (schema **1.0.0**). Contract event names are `run.*`, `hop.*`, `control.decision`, `llm.*`, `pipeline.stopped`. Withdrawn names (`normal_request`, `prompt_attack`, `agent_handoff` as event.name) are not the contract.

## HOW WILL SPLUNK SHOW IT?

After a live lab start, Search with macro `` `agentsec_index` ``. Saved searches Q-RUN and Q-DENY are **disabled placeholders** until someone validates them in Splunk. Python `agentsec.detections` answers the same questions against the evidence file and is labeled not-Splunk.

## WHAT CONTROL COULD CHANGE THE RESULT?

`CTRL-INPUT-001` in `defended`. `vulnerable` allows the same payload through and writes `vulnerable_profile_fail_open:<rule>`.

## WHAT TEST PROVES THE LOGIC?

`tests/security/test_input_control_before_llm.py` — stub LLM call list stays empty on ATK-002.

## What I should now be able to explain

1. Why four agents in one process is not A2A.
2. Where the trust boundary is.
3. What happens if DENY is recorded after Ollama already ran.
4. Why Attack Service must not import the LLM client.
5. What `agentsec.run.id` is for.
6. Why HTTP cannot set `testbed.mode`, `execution.mode`, or `telemetry.fidelity`.
7. What evidence class “MEASURED against local events, not Splunk” means.
8. How `vulnerable` is still a teaching profile, not a silent bypass.
9. Which two hunt questions Phase 2 cares about.
10. What was intentionally left out of Phase 2.
