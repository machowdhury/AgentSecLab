# Splunk Search Contract

**Status:** PLANNED (Phase 1C)  
**Schema:** `agentsec.security_event` **1.0.0**  
**Index:** `agentsec_telemetry`  
**Sourcetype:** `otel:agentic:json`

This file lists **security questions** future searches must answer. It does **not** contain SPL, saved searches, or macros.

Never invent fields. Never state that a query works until it is run against representative events (`docs` rule 31). Splunk results are corroborating unless completeness for that `run.id` is established.

Field map: `schemas/splunk_investigation_fields.json`.

---

## How to read a row

| Column | Meaning |
|--------|---------|
| QUERY ID | Stable id for later SPL validation |
| QUESTION | What the analyst is asking |
| REQUIRED EVENT TYPES | `event.name` values that must exist to answer honestly |
| REQUIRED FIELDS | Closed contract fields |
| EXPECTED BASELINE | `testbed.mode=BASELINE`, typically `defended`, ATK-001 benign |
| EXPECTED ATTACK | `testbed.mode=ATTACK`, `vulnerable`, ATK-002 |
| EXPECTED DEFENDED | `testbed.mode=RETEST`, `defended`, same ATK-002 payload |
| VALIDATION REQUIREMENT | What must be true before teaching the search as MEASURED |

First-lab sequences: A (benign), B (vulnerable attack), C (defended retest), D (Ollama failed after start), E (control evaluation ERROR), F (export failed) — `SECURITY_EVENT_MODEL.md`.

---

## Q-RUN-EVENTS

**QUESTION:** Show all security events for this `run.id`.

**REQUIRED EVENT TYPES:** Any first-lab names present for that id (`run.*`, `hop.*`, `control.decision`, `llm.*`, `pipeline.stopped`).

**REQUIRED FIELDS:** `agentsec.run.id`, `agentsec.incident.id`, `agentsec.schema.version`, `agentsec.sequence`, `event.name`, `timestamp`.

**EXPECTED BASELINE:** Ordered sequence: run.started → four hops ALLOW + llm.started/completed → run.completed completed_allowed. incident.id = run.id.

**EXPECTED ATTACK:** Four hops ALLOW (fail-open labeled) + llm.* unless sequence D.

**EXPECTED DEFENDED:** hop 0 DENY → pipeline.stopped denied → hop.completed hop_denied → run.completed completed_denied. No hops 1–3. No llm.*.

**VALIDATION REQUIREMENT:** Events in the index for a known lab run.id. Sequence unique and increasing. schema.version = 1.0.0.

---

## Q-WHO

**QUESTION:** Who initiated this run?

**REQUIRED EVENT TYPES:** `agentsec.run.started` (and subsequent events sharing run.id).

**REQUIRED FIELDS:** `user.id`, `agentsec.principal.id`, `agentsec.principal.type`, `agentsec.workflow.entry`.

**EXPECTED BASELINE / ATTACK / DEFENDED:** Initiator is the HTTP client. workflow.entry = `/process`. Attacker cannot be shown as setting run.id.

**VALIDATION REQUIREMENT:** Principal fields present; not taken from payload policy keys.

---

## Q-PROFILE-MODE

**QUESTION:** What profile and experiment was this?

**REQUIRED EVENT TYPES:** Any event for the run (all carry dimensions).

**REQUIRED FIELDS:** `agentsec.security.profile`, `agentsec.testbed.mode`, `agentsec.execution.mode`, `agentsec.telemetry.fidelity`, `agentsec.attack.id`.

**EXPECTED BASELINE:** BASELINE, LIVE, OBSERVED, ATK-001.

**EXPECTED ATTACK:** ATTACK, LIVE, OBSERVED, ATK-002, vulnerable.

**EXPECTED DEFENDED:** RETEST, LIVE, OBSERVED, ATK-002, defended.

**VALIDATION REQUIREMENT:** Do not query `testbed.mode=LIVE`. First lab must not present SIMULATED/SYNTHETIC as OBSERVED proof.

---

## Q-HOP-SEQUENCE

**QUESTION:** Which agents ran, in what order, and who influenced later hops?

**REQUIRED EVENT TYPES:** `hop.started`, `hop.completed`.

**REQUIRED FIELDS:** `gen_ai.agent.id`, `agentsec.hop.index`, `agentsec.delegator.agent.id` (hops 1–3), `agentsec.outcome`.

**EXPECTED BASELINE:** Hops 0–3. Hop 0 has no delegator. Hops 1–3 have delegator. All hop_allowed.

**EXPECTED ATTACK:** Hops 0–3 hop_allowed (unless D/E).

**EXPECTED DEFENDED:** Hop 0 hop_denied. No hop 1–3 events.

**VALIDATION REQUIREMENT:** hop.index 0 forbids delegator; ≥1 requires it. Not labeled A2A.

---

## Q-CONTROL-DECISION

**QUESTION:** What did CTRL-INPUT-001 decide on this hop, and why?

**REQUIRED EVENT TYPES:** `agentsec.control.decision`.

**REQUIRED FIELDS:** `agentsec.control.id`, `control.type`, `control.decision`, `control.reason`, `security.profile`, `invariant.id`, `operation.attempted`, `operation.executed`, `hop.index`.

**EXPECTED BASELINE:** ALLOW, attempted=false, executed=false, outcome omitted, then llm.* follows.

**EXPECTED ATTACK:** ALLOW + fail-open reason on vulnerable; attempted=false, executed=false at decision time.

**EXPECTED DEFENDED:** DENY, attempted=false, executed=false, outcome=prevented, hop 0.

**VALIDATION REQUIREMENT:** Control events are not llm events. ALLOW is not execution.

---

## Q-LLM-EXECUTED

**QUESTION:** Did Ollama execute on this hop, and how did the call end?

**REQUIRED EVENT TYPES:** `llm.started`, `llm.completed`, and/or `llm.failed` — or none.

**REQUIRED FIELDS:** `event.name`, `hop.index`, `operation.attempted`, `operation.executed`, `operation.outcome`, `gen_ai.provider.name`, `gen_ai.request.model`.

**EXPECTED BASELINE:** started + completed; attempted=true, executed=true, outcome=success.

**EXPECTED ATTACK:** same if generate succeeded; if sequence D: started + failed, executed=true, outcome=error.

**EXPECTED DEFENDED:** **no** llm.* on hop 0.

**VALIDATION REQUIREMENT:** executed=true on llm.started and llm.failed. Do not treat llm.failed as prevented. ALLOW without llm.* is not “did not execute” unless completeness is established.

---

## Q-LLM-AFTER-DENY

**QUESTION:** Did any LLM activity occur after DENY on this hop?

**REQUIRED EVENT TYPES:** `control.decision` (DENY) plus any `llm.*` for the same run.id + hop.index.

**REQUIRED FIELDS:** `run.id`, `hop.index`, `control.decision`, `event.name`.

**EXPECTED BASELINE:** N/A (no DENY).

**EXPECTED ATTACK:** N/A if vulnerable ALLOW.

**EXPECTED DEFENDED:** Zero llm.* for hop 0. Any llm.* after DENY is a contract break.

**VALIDATION REQUIREMENT:** Local complete events.jsonl is required for **proof**. Splunk zero llm.* is corroboration only.

---

## Q-PIPELINE-STOP

**QUESTION:** Where did the pipeline stop?

**REQUIRED EVENT TYPES:** `pipeline.stopped` and/or `hop.completed`, `run.completed` / `run.failed`.

**REQUIRED FIELDS:** `stop.reason`, `hop.index`, `agentsec.outcome`, `error.stage` if failed.

**EXPECTED BASELINE:** No pipeline.stopped. run.completed completed_allowed.

**EXPECTED ATTACK:** Usually no stop until four hops done (unless D/E).

**EXPECTED DEFENDED:** stop.reason=denied, hop.index=0, hop_denied, completed_denied.

**VALIDATION REQUIREMENT:** denied ≠ error. Sequence D: stop.reason=error, run.failed, llm.failed executed=true.

---

## Q-OPERATION-CASES

**QUESTION:** Which operation case is this hop?

**REQUIRED EVENT TYPES:** `control.decision` and llm.* as applicable.

**REQUIRED FIELDS:** `control.decision`, `operation.attempted`, `operation.executed`, `operation.outcome`, `event.name`.

**EXPECTED BASELINE:** ALLOW then success.

**EXPECTED ATTACK:** ALLOW then success or ALLOW then error (D).

**EXPECTED DEFENDED:** DENY prevented.

**VALIDATION REQUIREMENT:** UI/search must be able to classify the six cases in `SPLUNK_UX_DESIGN.md` without an LLM narrator.

---

## Q-SPLUNK-COMPLETENESS

**QUESTION:** Is Splunk telemetry complete enough to corroborate this run?

**REQUIRED EVENT TYPES:** The **expected set** for the sequence (A/B/C/D/E), compared to what is indexed.

**REQUIRED FIELDS:** `run.id`, `event.name`, `sequence`, `schema.version`. Completeness vs disk also needs `export.json` (not a Splunk field unless later emitted — treat as NOT VERIFIED in Splunk).

**EXPECTED BASELINE:** Indexed set matches sequence A.

**EXPECTED ATTACK:** Matches B (or D).

**EXPECTED DEFENDED:** Matches C. Missing llm.* is expected **and** other C events must be present (run.started, control DENY, pipeline.stopped, …). Missing **everything** is not C.

**VALIDATION REQUIREMENT:** Do not answer “complete” from “no llm.*” alone. Sequence F (export failed): Splunk must not be used as prevention proof. Default UI state NOT VERIFIED until local export.json + event-count match are confirmed.

---

## Q-COMPARE-RETEST

**QUESTION:** How does the vulnerable ATTACK run differ from the defended RETEST of the same payload?

**REQUIRED EVENT TYPES:** Two run.ids: ATTACK + RETEST.

**REQUIRED FIELDS:** `run.id`, `compare` pair, `profile`, `testbed.mode`, `control.decision`, `operation.executed`, `operation.outcome`, llm.* presence.

**EXPECTED BASELINE:** Not this question.

**EXPECTED ATTACK:** vulnerable, ALLOW fail-open, LLM likely executed.

**EXPECTED DEFENDED:** defended, DENY prevented, no LLM.

**VALIDATION REQUIREMENT:** Same attack.id ATK-002. Do not compare unrelated run.ids as before/after. Color not the only difference.

---

## Q-CONTENT

**QUESTION:** What content influenced the hop, without full prompts?

**REQUIRED EVENT TYPES:** Hop/control events that carry content fields.

**REQUIRED FIELDS:** `content.preview`, `content.hash`, `content.origin.type`, `content.influence.kind`.

**EXPECTED BASELINE / ATTACK / DEFENDED:** Preview ≤200 + hash. No `gen_ai.input.messages`.

**VALIDATION REQUIREMENT:** No secrets. Full prompts not required for evidence.

---

## Q-SCHEMA

**QUESTION:** Which event contract produced this record?

**REQUIRED EVENT TYPES:** All.

**REQUIRED FIELDS:** `agentsec.schema.name`, `agentsec.schema.version`.

**EXPECTED BASELINE / ATTACK / DEFENDED:** `agentsec.security_event` / `1.0.0`.

**VALIDATION REQUIREMENT:** Reject hunts that assume withdrawn names (`normal_request`, `prompt_attack`, `session.id`).

---

## First-lab detection mapping

| DETECTION ID | Built from | Explain without ML |
|--------------|------------|--------------------|
| DET-001 | Q-CONTROL-DECISION + Q-LLM-AFTER-DENY + Q-SPLUNK-COMPLETENESS | Prevented-before-invoke, with completeness caveat |

DET-001 true positive: defended RETEST hop 0 DENY, prevented, no llm.*, **and** expected C events present.  
DET-001 negative: BASELINE ALLOW + llm.completed.  
DET-001 false positive risk: export loss on an ALLOW path; llm.failed; empty index.

---

## Explicitly out of scope (no questions yet)

- Tools, MCP, A2A, RAG, memory  
- `agentsec.chain.id`  
- MLTK / anomaly  
- Cisco / adapter sourcetypes  
- `session.id` / `session_id`

---

## Later validation process (not this phase)

1. Confirm fields in real events.  
2. Write the simplest SPL.  
3. Run it.  
4. Record actual output.  
5. Then bind to Dashboard Studio.

Until then every search is **unvalidated**.
