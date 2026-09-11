# Security Telemetry 101

**Status:** PLANNED (Phase 1B contract, schema **1.0.0**). Existing AcmeBank emitters are EXPERIMENTAL.

---

## WHAT IS IT?

A **security event** is a JSON record of something AcmeBank actually did, tagged with `agentsec.schema.version`.

Telemetry is those records. **Local evidence** is the on-disk pack. Splunk is a possibly incomplete copy.

## WHY DOES IT EXIST?

AgentWatch mixed session fields, per-hop incidents, and HARD_DENY without a real call. AgentSec separates:

- **testbed** (BASELINE / ATTACK / RETEST)
- **how it ran** (`execution.mode=LIVE` here)
- **how truthful the bytes are** (`telemetry.fidelity=OBSERVED` here)

And it separates **never invoked** from **invoked then failed**.

## HOW DOES IT WORK?

1. Runtime decides whether Ollama is invoked. That is authoritative.
2. Events use `operation.attempted`, `operation.executed` (started), `operation.outcome` (`prevented` / `success` / `error`).
3. DENY: attempted=false, executed=false, outcome=prevented, **no LLM span**.
4. Ollama timeout after start: attempted=true, executed=true, outcome=error — **not** prevented.
5. Bundle stores preview + hash only. Splunk absence of `llm.*` is corroboration, not proof, unless the run is complete in the index.

## WHERE DOES IT SIT IN AGENTSEC?

RUNTIME → LOCAL EVIDENCE → EXPORT → SPLUNK

Splunk does not authorize and does not outrank the runtime.

## WHAT IS THE TRUST BOUNDARY?

AcmeBank produces events. Attackers do not set `run.id`, profile, or control fields.

## WHAT COULD AN ATTACKER CONTROL?

Loan text (preview/hash). Not operation flags.

## WHAT CAN GO WRONG?

- Treating Splunk “no LLM event” as prevention
- Recording `executed=false` after `llm.started`
- Calling an Ollama failure DENY
- Putting BASELINE and ATTACK in one `testbed.mode` called LIVE
- Storing full prompts by default

## WHAT TELEMETRY SHOULD EXIST?

See `docs/SECURITY_EVENT_MODEL.md`. Schema name + version on every event. Delegator id on hops after intake.

## HOW WILL SPLUNK SHOW IT?

Filter `agentsec.run.id` and `testbed.mode`. Compare `control.decision` with `llm.failed` vs missing `llm.*`. Confirm `export.json` before treating a hunt as complete. SPL is not validated here.

## WHAT CONTROL COULD CHANGE THE RESULT?

CTRL-INPUT-001. Same ATK-002 payload: `ATTACK`+vulnerable vs `RETEST`+defended.

## WHAT TEST PROVES THE LOGIC?

Runtime stub: DENY ⇒ zero generate calls. Local events: outcome=prevented and no `llm.*`. That is not a Splunk test.

---

## What I should now be able to explain

1. The four-layer evidence hierarchy.  
2. What `operation.executed` means (invoked, not succeeded).  
3. Why LLM-failed is executed=true, outcome=error.  
4. Why Splunk cannot prove DENY alone.  
5. BASELINE vs ATTACK vs RETEST vs execution.mode vs fidelity.  
6. Why schema version is on every event.  
7. Why evidence defaults to preview+hash.  
8. Why hop 1+ has `delegator.agent.id` without being A2A.  
9. Why ALLOW does not prove success.  
10. Why `incident.id` equals `run.id`.
