# Security Event Model

**Status:** Schema designed; fixtures are SIMULATED representatives, not live telemetry.

## WHAT IS IT?

A closed JSON contract so every AcmeBank security log can answer the same Splunk questions: who, which agent, which model, what content, what tool, what decision, why, which run/trace.

## WHY DOES IT EXIST?

AgentWatch mixed `session.id` / `session_id` and minted a new incident per hop. Hunts could not reconstruct a pipeline. AgentSec pins OpenTelemetry GenAI names and a small `agentsec.*` extension set.

## HOW DOES IT WORK?

OTLP log body validates against `schemas/security_event.schema.json`. DENY cannot set `agentsec.operation.executed=true`. Unknown keys are rejected.

## WHERE DOES IT SIT IN AGENTSEC?

Between reference controls and Splunk. Dashboards must not invent extra fields.

## WHAT IS THE TRUST BOUNDARY?

Event bodies are produced **inside** AcmeBank. Attacker JSON is not copied into `agentsec.control.*`.

## WHAT COULD AN ATTACKER CONTROL?

Payload text (preview/hash only). Not `agentsec.run.id`, profile, or decision fields.

## WHAT CAN GO WRONG?

Full prompt capture; DENY after the LLM ran; SIMULATED events without `agentsec.testbed.mode=SIMULATED`.

## WHAT TELEMETRY SHOULD EXIST?

See `docs/SECURITY_EVENT_MODEL.md` investigation table.

## HOW WILL SPLUNK SHOW IT?

`` `agentsec_index` agentsec.run.id=<uuid> `` then group by `gen_ai.agent.id` and `agentsec.control.decision`.

## WHAT CONTROL COULD CHANGE THE RESULT?

The control that emitted `agentsec.control.id` / `decision` / `reason`.

## WHAT TEST PROVES THE LOGIC?

`tests/telemetry/test_security_event_schema.py` against `telemetry/events/`.

## What I should now be able to explain

1. Which investigation questions use plain OTel names vs `agentsec.*`.
2. Why `user.id`, principal, and `gen_ai.agent.id` are three fields.
3. Why DENY requires `operation.executed=false`.
4. How handoff uses `parent_span_id` and content origin.
5. Why tool allow vs deny needs both requested and allowed scope.
6. Why memory events carry `agentsec.memory.trust_level`.
7. Why RAG uses `gen_ai.data_source.id` plus origin type `retrieval`.
8. The difference between `run.id`, `incident.id`, `chain.id`, and `trace_id`.
