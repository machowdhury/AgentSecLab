# Security Event Model

**Status:** Phase 1B contract (schema **1.0.0**). Phase 2A AcmeBank emitters implement this contract. Splunk SPL is not validated.  
**Schema:** `schemas/security_event.schema.json`  
**Investigation map:** `schemas/splunk_investigation_fields.json`  
**Evidence:** `docs/EVIDENCE_MODEL.md`

This file is the telemetry contract for the **first lab**. Phase 2A runtime emits these events on `POST /process`. Live Splunk representation is not claimed.

| Label | Meaning |
|-------|---------|
| **PLANNED** | Splunk hunts, completeness corroboration |
| **EXPERIMENTAL** | Unused |
| **IMPLEMENTED** | Schema 1.0.0 and Phase 2A emitters (see `PHASE2A_RUNTIME_VALIDATION.md`) |

Every event MUST set:

- `agentsec.schema.name` = `agentsec.security_event`
- `agentsec.schema.version` = `1.0.0`

Phase 1A architecture is the parent contract. Phase 1B **freezes**:

1. HTTP surface is **`POST /process` only**.
2. First baseline is an **explicit benign request**, not a background ticker.
3. Empty/malformed input → **ERROR in both profiles** (LLM never attempted).
4. **`agentsec.incident.id` = `agentsec.run.id` on every event.**
5. **Control decision events and LLM activity events are separate.**
6. **Control evaluation and LLM invocation are separate operations/spans.**

---

## Evidence hierarchy (DENY proof)

```text
AUTHORITATIVE RUNTIME STATE
  → LOCAL RUN EVIDENCE          artifacts/<run-id>/
  → EXPORTED TELEMETRY          OTLP / HEC (may be incomplete)
  → SPLUNK REPRESENTATION       corroborating only
```

| Layer | What it can prove |
|-------|-------------------|
| **Runtime** | Whether AcmeBank invoked Ollama (call counter / client). **Authoritative** for prevention vs invocation. |
| **Local evidence** | Schema-valid `events.jsonl` + `result.json` for that `run.id`. Authoritative **for this lab** if the bundle is complete for the run. |
| **Exported telemetry** | What left the process. May drop events. |
| **Splunk** | What was indexed. A search with **no** `llm.*` rows is **corroborating**, not proof of prevention, unless completeness of that run in the index is established (export ok + expected event set present). |

**Do not claim** that “Splunk shows no LLM event” alone proves DENY prevented inference.

Prevention (DENY before invocation) is proven when **all** of these hold:

1. Runtime: governed LLM was **not invoked** (attempted=false, executed=false).
2. Local evidence: `control.decision=DENY`, `operation.outcome=prevented`, **and** no `llm.*` events for that hop in a **complete** `events.jsonl`.
3. Splunk (optional): same pattern **and** `export.json` shows successful export / completeness for that `run.id`.

ALLOW on a control event does **not** prove the LLM ran.

---

## Operation semantics

Governed dangerous operation in this lab: **LLM inference** (Ollama generate).

Three fields (smallest coherent set):

| Field | Meaning |
|-------|---------|
| `agentsec.operation.attempted` | The runtime **intended to invoke** the governed operation. |
| `agentsec.operation.executed` | The runtime **actually invoked/started** the governed operation (the call began). **Not** “completed successfully.” |
| `agentsec.operation.outcome` | Terminal result of that operation: `prevented` \| `success` \| `error`. Omit until terminal when still in progress. |

| Situation | attempted | executed | outcome |
|-----------|-----------|----------|---------|
| Control **DENY** before invocation | `false` | `false` | `prevented` |
| Control **ERROR** before invocation | `false` | `false` | `prevented` |
| Control **ALLOW** (decision time; LLM not started yet) | `false` | `false` | omit |
| `llm.started` (invocation began) | `true` | `true` | omit |
| `llm.completed` (generate succeeded) | `true` | `true` | `success` |
| `llm.failed` (invocation started, then dependency/error) | `true` | `true` | `error` |

**`operation.executed=true` means the dangerous call was started**, including calls that later fail. Dependency failure is **not** equivalent to non-execution or to DENY.

---

## Experiment dimensions (separate)

Do **not** use `LIVE` as a `testbed.mode`. Do **not** collapse baseline into attack.

| Dimension | Values | First-lab emission |
|-----------|--------|--------------------|
| `agentsec.testbed.mode` | `BASELINE` \| `ATTACK` \| `RETEST` | all three used as below |
| `agentsec.execution.mode` | `LIVE` \| `SIMULATED` \| `HYBRID` \| `REPLAYED` | **LIVE only** (others reserved) |
| `agentsec.telemetry.fidelity` | `OBSERVED` \| `SYNTHETIC` \| `MIXED` | **OBSERVED only** (others reserved) |

First implementation:

| Experiment | testbed.mode | execution.mode | telemetry.fidelity |
|------------|--------------|----------------|-------------------|
| Benign baseline | `BASELINE` | `LIVE` | `OBSERVED` |
| ATK-002 | `ATTACK` | `LIVE` | `OBSERVED` |
| Defensive replay (same payload, profile change) | `RETEST` | `LIVE` | `OBSERVED` |

`SYNTHETIC` / `SIMULATED` / `HYBRID` / `REPLAYED` / `MIXED` may appear in the schema enum. They MUST NOT be emitted by the first lab and MUST NOT be presented as OBSERVED live proof.

---

## Truth sequence

```text
ATTEMPT
  → CONTROL EVALUATION
  → CONTROL DECISION
  → OPERATION ATTEMPT      (LLM only if ALLOW)
  → OPERATION EXECUTION    (invocation started)
  → ACTUAL OUTCOME         (success | error | prevented)
  → TELEMETRY
  → EVIDENCE
```

---

## Trace / span model

One `trace_id` per `/process` run.

```text
run.id = incident.id
trace_id
  pipeline span
    hop span (index 0 intake)          no delegator
      control-evaluation span
      llm-inference span               ONLY if ALLOW
    hop span (index 1..3)              delegator.agent.id REQUIRED
      ...
```

Do **not** create an LLM child span after DENY or ERROR that blocks invocation.

| Span kind | Parent | Events |
|-----------|--------|--------|
| `pipeline` | none | `run.started`, `run.completed`, `run.failed`, `pipeline.stopped` |
| `hop` | pipeline | `hop.started`, `hop.completed` |
| `control_evaluation` | hop | `control.decision` |
| `llm_inference` | hop | `llm.started`, `llm.completed`, `llm.failed` |

Control-to-LLM link: `run.id` + `hop.index` + hop `span_id` as `parent_span_id`. Do not invent an LLM span id on DENY.

Hops after intake **require** `agentsec.delegator.agent.id` (prior coded agent). This is in-process attribution, **not** A2A.

---

## Event taxonomy (first lab)

“Control evaluated” and “control decision” remain **one event**: `agentsec.control.decision`.

Producer: **AcmeBank** only.

### `agentsec.run.started`

Attempt: `/process` accepted, ids minted. No control decision. No LLM.  
Next: `hop.started` (0) or `run.failed` if malformed before hops.  
Required: schema name/version; experiment dimensions; `workflow.entry=/process`.

### `agentsec.run.completed`

Designed finish, including DENY stop (`completed_denied`) or full ALLOW (`completed_allowed`). Not used for LLM dependency failure (`run.failed`).

### `agentsec.run.failed`

Schema failure, control-evaluation failure, or LLM invocation that started and then failed. Not a DENY.

### `agentsec.hop.started` / `hop.completed`

Hop 0: **must not** include `delegator.agent.id`.  
Hop 1–3: **must** include `delegator.agent.id`.  
Hop outcomes: `hop_allowed` \| `hop_denied` \| `hop_error`.

### `agentsec.control.decision`

CTRL-INPUT-001 (or schema) finished. Before any LLM span.

| Decision | attempted | executed | outcome | Next |
|----------|-----------|----------|---------|------|
| DENY | false | false | prevented | `pipeline.stopped`, no `llm.*` |
| ERROR (before invoke) | false | false | prevented | `pipeline.stopped`, no `llm.*` |
| ALLOW | false | false | omit | `llm.started` |

Empty/malformed: ERROR, both profiles.

### `agentsec.llm.started`

Invocation **began**. `attempted=true`, `executed=true`, outcome omitted. Only after ALLOW.

### `agentsec.llm.completed`

`attempted=true`, `executed=true`, `outcome=success`.

### `agentsec.llm.failed`

Invocation started, then failed. `attempted=true`, `executed=true`, `outcome=error`. **Not** DENY. **Not** non-execution.

### `agentsec.pipeline.stopped`

Remaining hops will not run. `stop.reason` = `denied` \| `error`.

---

## Field families (delta from 1.0.0)

**Schema identity:** `agentsec.schema.name`, `agentsec.schema.version` (required).

**Execution (governed LLM only, on `control.decision` and `llm.*`):** `operation.attempted`, `operation.executed` (invocation started, not success), `operation.outcome` (`prevented` \| `success` \| `error`). Distinct from hop/run `agentsec.outcome`.

**Experiment:** `testbed.mode`, `execution.mode`, `telemetry.fidelity` as in the table above.

**Content:** preview ≤200 + `content.hash` only. Full prompts are **not** default telemetry or default evidence.

**Handoff:** `agentsec.delegator.agent.id` required when `hop.index` ≥ 1.

OTel vs `agentsec.*` otherwise unchanged: no `session.id` / `session_id`; `gen_ai.operation.name=chat` on LLM events only.

---

## Closed / attacker-controlled fields

**Server-only:** `run.id`, `incident.id`, `security.profile`, `control.*`, operation attempted/executed/outcome, `telemetry.fidelity`, `testbed.mode` (client cannot set BASELINE/RETEST/SYNTHETIC), `execution.mode`, schema version, `trace_id`, `span_id`.

**Attacker-influenced:** payload → preview/hash only.

**Forbidden keys:** `session.id`, `session_id`, unprefixed `control.decision`, client `run.id`.

---

## Validation invariants

| ID | Rule |
|----|------|
| V-SCHEMA | Every event has `schema.name=agentsec.security_event` and `schema.version=1.0.0` |
| V-RUN | Every event has `run.id` |
| V-INC | `incident.id` == `run.id` |
| V-DIM-FIRST | First-lab emissions: `execution.mode=LIVE` and `telemetry.fidelity=OBSERVED`; `testbed.mode` in {BASELINE, ATTACK, RETEST} |
| V-NO-FAKE-OBS | `execution.mode=SIMULATED` or `fidelity=SYNTHETIC` must never be presented as OBSERVED live proof |
| V-DENY | DENY ⇒ attempted=false, executed=false, outcome=prevented |
| V-DENY-NO-LLM | After DENY on hop `i`, no `llm.*` for hop `i` in **complete local** evidence |
| V-DENY-SPLUNK | Splunk missing `llm.*` is corroboration only unless run completeness is established |
| V-ERROR-PRE | ERROR before invoke ⇒ attempted=false, executed=false, outcome=prevented, no `llm.*` |
| V-ALLOW-CTRL | ALLOW on control.decision ⇒ attempted=false, executed=false, no outcome |
| V-LLM-START | `llm.started` ⇒ attempted=true, executed=true; only after ALLOW |
| V-LLM-OK | `llm.completed` ⇒ attempted=true, executed=true, outcome=success |
| V-LLM-FAIL | `llm.failed` ⇒ attempted=true, executed=true, outcome=error (not DENY, not prevented) |
| V-NO-POST-DENY | No DENY after `llm.started`/`completed`/`failed` on that hop |
| V-DEL-0 | hop.index=0 ⇒ no `delegator.agent.id` |
| V-DEL-N | hop.index≥1 ⇒ `delegator.agent.id` required |
| V-SEQ | `sequence` unique and increasing |
| V-ENTRY | `workflow.entry=/process` |
| V-SPAN-LLM | No `llm_inference` span when hop decision is DENY or pre-invoke ERROR |
| V-RUNTIME | Runtime invocation flag is authoritative over Splunk absence |
| V-CONTENT | Default events and evidence store preview (≤200) + content hash only; full prompts are not required |
| V-OP-SCOPE | `operation.attempted` / `executed` / `outcome` appear on `control.decision` and `llm.*` only (governed LLM operation) |

---

## Example sequences

### A. BENIGN + DEFENDED (explicit baseline)

Dimensions: `testbed.mode=BASELINE`, `execution.mode=LIVE`, `fidelity=OBSERVED`, `attack.id=ATK-001`, `profile=defended`.

MUST: `run.started` → four× (`hop.started` → ALLOW control → `llm.started` executed=true → `llm.completed` outcome=success → `hop.completed` hop_allowed) → `run.completed` completed_allowed. Hop 1–3 include delegator.

MUST NOT: `pipeline.stopped`, `run.failed`, DENY, `testbed.mode=ATTACK` or `RETEST`, SYNTHETIC fidelity.

### B. ATK-002 + VULNERABLE

Dimensions: `testbed.mode=ATTACK`, `LIVE`, `OBSERVED`. **Same payload as C.**

MUST: four hops ALLOW with fail-open reason; `llm.started`/`completed` unless sequence D. Delegator on hops 1–3.

MUST NOT: DENY; unlabeled fail-open; `testbed.mode=BASELINE` or `RETEST`.

### C. DEFENSIVE REPLAY (ATK-002 + DEFENDED)

Same payload as B. `profile=defended`. Dimensions: `testbed.mode=RETEST`, `LIVE`, `OBSERVED`.

MUST: hop 0 `control.decision` DENY, attempted=false, executed=false, outcome=prevented → `pipeline.stopped` denied → `hop.completed` hop_denied → `run.completed` completed_denied. Runtime: LLM not invoked. Proof order: runtime → complete local bundle → export → Splunk corroboration.

MUST NOT: any `llm.*`; hops 1–3; treating Splunk-only absence as the proof; `run.failed`; `testbed.mode=LIVE`; `operation.executed=true`.

### D. OLLAMA FAILURE

ALLOW path; generate **starts** then fails.

MUST: ALLOW (attempted=false at control) → `llm.started` (attempted=true, **executed=true**) → `llm.failed` (attempted=true, **executed=true**, outcome=**error**) → `hop.completed` hop_error → `pipeline.stopped` error → `run.failed`.

MUST NOT: `outcome=prevented`; `executed=false` on `llm.failed`; DENY; `llm.completed`; remaining hops.

### E. CONTROL EVALUATION FAILURE

MUST: `control.decision` ERROR, attempted=false, executed=false, outcome=prevented, `error.stage=control_evaluation` → stopped → `run.failed`.

MUST NOT: `llm.*`; DENY; ALLOW.

### F. TELEMETRY EXPORT FAILURE

Local sequence A or C complete in `events.jsonl`. `export.json` failed.

MUST: local bundle; runtime still authoritative.

MUST NOT: Splunk absence as proof of DENY; fabricated HEC success; claiming MEASURED Splunk.

---

## Splunk investigation questions

See `schemas/splunk_investigation_fields.json`. SPL not validated.

Baseline vs attack vs retest uses `testbed.mode`, **not** `execution.mode`.

“Was inference prevented?” uses runtime + complete local evidence first; Splunk second.

---

## Fields / modes omitted from first-lab **emission**

- `session.id` / `session_id` / `gen_ai.conversation.id`
- Tools, memory, RAG, A2A, chains
- Full prompts by default
- Emitting SIMULATED / HYBRID / REPLAYED / SYNTHETIC / MIXED (reserved in schema only)

---

## Related

`ARCHITECTURE.md`, `ATTACK_CONTROL_MODEL.md`, `EVIDENCE_MODEL.md`, `learning-notes/security-telemetry-101.md`
