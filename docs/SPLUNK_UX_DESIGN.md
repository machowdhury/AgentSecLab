# Splunk UX Design

**Status:** PLANNED (Phase 1C)  
**Companion:** `SPLUNK_INFORMATION_ARCHITECTURE.md`, `SPLUNK_WORKSHOP_STANDARD.md`, `SPLUNK_SEARCH_CONTRACT.md`  
**Palette:** `SPLUNK_DESIGN_SYSTEM.md`

This file specifies interaction and visual rules for first-lab Splunk pages. It is not JSON and not SPL.

---

## Roles Splunk plays

Splunk **is:** telemetry workbench, investigation workbench, detection workbench, learning interface, later MLTK workbench, evidence interface.

Splunk **is not:** the authorizer, the control, the Ollama client, or the evidence manufacturer.

Runtime truth is authoritative. Local `artifacts/<run-id>/` is the lab record when complete. Export may drop events. The index is a copy.

---

## Visual system

| Token | Hex | Use |
|-------|-----|-----|
| Background | `#F6F8FB` | Page |
| Primary text | `#17202A` | Body |
| Secondary text | `#5B6573` | Captions, hints |
| Navy | `#0B1F33` | Headers, chrome |
| Accent teal | `#007F86` | Links, focus, next step |
| Success | `#2E7D32` | ALLOW / success **with label** |
| Warning | `#B7791F` | Incomplete / warn **with label** |
| Critical | `#C62828` | DENY / fail / contract break **with label** |
| Info | `#3568A8` | Neutral info, OBSERVED |
| Advanced/ML | `#6B46C1` | MLTK track only (not first lab) |
| Border | `#D9E0E7` | Panels |

Calm professional appearance. No neon, no extra gradients, no vanity metrics, no decorative dashboards.

**Color is never the only severity indicator.** Every state has a text label (and an icon when the visualization allows): ALLOW, DENY, ERROR, prevented, success, error, COMPLETE, PARTIAL, FAILED, NOT VERIFIED.

Layout: Dashboard Studio **GRID** for workshops, hunts, OBSERVE, INVESTIGATION, CONTROL VALIDATION, DETECTION LAB, HOME, PROGRESS.

**Absolute layout** only for a later architecture-story or executive-story view, with a written justification. First lab uses GRID only.

---

## Five learner questions (every learner-facing page)

1. What am I looking at?  
2. Why does it matter?  
3. What happened?  
4. What evidence supports that conclusion?  
5. What should I do next?

If a panel cannot answer one primary page question, it does not belong on that page.

---

## Experiment and operation labels

Show three **separate** dimensions. Do not badge `LIVE` as testbed.mode.

| Dimension | First-lab values |
|-----------|------------------|
| `testbed.mode` | BASELINE, ATTACK, RETEST |
| `execution.mode` | LIVE (label) |
| `telemetry.fidelity` | OBSERVED (label) |

Operation fields (control.decision and llm.* only):

| Field | Learner gloss |
|-------|----------------|
| attempted | Did the runtime intend to call Ollama? |
| executed | Did the call **start**? (Failure after start is still yes.) |
| outcome | prevented / success / error — omit while in progress |

---

## What Happened (data-driven)

Never static narrative. Never an LLM summary of the run.

Render a **field template**. If a field is missing, show `—` and lower evidence completeness. Do not guess.

### Minimum template

| Concept | Source fields |
|---------|----------------|
| Run ID | `agentsec.run.id` |
| Incident ID | `agentsec.incident.id` (must equal run.id) |
| Schema | `agentsec.schema.name` / `version` |
| Experiment mode | `agentsec.testbed.mode` |
| Execution / fidelity | `agentsec.execution.mode`, `agentsec.telemetry.fidelity` |
| Security profile | `agentsec.security.profile` |
| Attack ID | `agentsec.attack.id` |
| Agent / hop | `gen_ai.agent.id`, `agentsec.hop.index`, `delegator.agent.id` if hop ≥ 1 |
| Control decision | `agentsec.control.decision`, `control.id`, `control.reason` |
| Operation attempted | `agentsec.operation.attempted` |
| Operation executed | `agentsec.operation.executed` |
| Operation outcome | `agentsec.operation.outcome` |
| Pipeline outcome | `agentsec.outcome`, `stop.reason`, `event.name` |
| Evidence completeness | four-layer status (below) |

### Distinctions the UI must make

| Case | How the UI knows (fields / events) | Learner label |
|------|--------------------------------------|---------------|
| ALLOW but operation never happened | `control.decision=ALLOW` and no `llm.*` for that hop | ALLOW — not executed (incomplete or still before invoke) |
| ALLOW then successful operation | `llm.completed`, attempted=true, executed=true, outcome=success | ALLOW — executed, success |
| ALLOW then failed operation | `llm.failed`, attempted=true, executed=true, outcome=error | ALLOW — executed, error (not DENY) |
| DENY before operation | `control.decision=DENY`, attempted=false, executed=false, outcome=prevented, no `llm.*` | DENY — prevented (runtime still authoritative) |
| ERROR before operation | `control.decision=ERROR`, attempted=false, executed=false, outcome=prevented, no `llm.*` | ERROR — not invoked |
| Missing / incomplete telemetry | Expected events for this sequence absent, or schema mismatch | INCOMPLETE — do not treat as prevention |

**ALLOW alone is not execution.** Missing `llm.*` after ALLOW is not proof of non-execution (export loss). Missing `llm.*` after DENY is corroboration only.

Content in this block: preview + hash only. No full prompts.

---

## Correlation UX

Learner path (plain language first):

```text
run.id  (= incident.id)
  → pipeline (run.started … run.completed|failed)
    → hop 0 intake     (no delegator)
      → control.decision
      → llm.* only if ALLOW
    → hop 1 credit     (delegator = intake)
    → hop 2 risk
    → hop 3 compliance
  → pipeline.stopped if remaining hops will not run
```

**First-lab visualization:** numbered hop cards, not a raw trace flame graph.

Parent/child without OTel jargon:

- “This hop is part of this run.”  
- “This control belongs to this hop.”  
- “This LLM call belongs to this hop, only after ALLOW.”

Later (not first lab): optional Advanced toggle showing `trace_id`, `span_id`, `parent_span_id`, `span.kind`.

Do not ask the learner to understand OTLP exporters to finish WS-001.

---

## Evidence-status model

Four **independent** layers. The page must not collapse them into one green “PROVEN.”

| Layer | What Splunk can see | What the learner must understand |
|-------|---------------------|----------------------------------|
| RUNTIME EVIDENCE | Not the call counter. Events are claims about runtime. | Authoritative invocation is AcmeBank (`result.json` / stub call count). |
| LOCAL BUNDLE | Not the filesystem. Show path `artifacts/<run.id>/`. | Complete `events.jsonl` + `export.json` + `result.json` are the lab record. |
| EXPORT STATUS | Indirect: presence/absence of events. `export.json` is on disk. | If export failed, Splunk is an incomplete copy. |
| SPLUNK INDEXED | Events in `agentsec_telemetry` for this run.id | A copy. |
| SPLUNK COMPLETENESS VERIFIED | Candidate only: expected `event.name` set for this sequence is present | Verified only if export succeeded **and** index matches local `events.jsonl`. Until the learner (or a later tool) compares those, state is NOT VERIFIED. |

### Learner-friendly states (per layer)

| State | Meaning |
|-------|---------|
| COMPLETE | This layer has what this lab requires for its role. |
| PARTIAL | Some data, not the expected set. |
| FAILED | This layer recorded a failure (export failed, run.failed, schema break). |
| NOT VERIFIED | Splunk cannot confirm this layer (default for runtime and local bundle). |

**Never show PROVEN** because rows exist in Splunk.

Icon + text + color. Example: warning icon + `NOT VERIFIED` + `#B7791F`.

### PROVE interaction (first lab)

CONTROL VALIDATION / workshop row 11 asks the learner to:

1. Confirm runtime (no generate on DENY) on AcmeBank / tests.  
2. Open `artifacts/<run.id>/result.json` and `export.json`.  
3. See Splunk indexed events for the same run.id.  
4. Only then treat Splunk as corroboration.

Splunk UI copy: “I cannot see your disk. Absence of llm.* here is not proof.”

---

## Detection-learning workflow (no SPL)

Order on DETECTION LAB (DET-001):

1. SECURITY QUESTION  
2. REQUIRED FIELDS  
3. BASELINE BEHAVIOR  
4. ATTACK BEHAVIOR  
5. DETECTION LOGIC (plain language)  
6. EXPECTED TRUE POSITIVE  
7. EXPECTED NEGATIVE CASE  
8. FALSE POSITIVE DISCUSSION  
9. TUNING  
10. INVESTIGATION NEXT STEP  

First-lab detection must be explainable without ML. DET-001 is “was inference prevented before invocation on this hop?” — fields, not models.

A detection is not a control. A true positive does not stop Ollama.

---

## Investigation model

Run-centric. Answers:

- Who initiated? (`user.id`, principal)  
- What profile?  
- Which attack or baseline? (`testbed.mode`, `attack.id`)  
- Which agents executed? (hop cards; DENY on hop 0 ⇒ later hops absent)  
- Which control decisions?  
- Did the LLM execute? (llm.* + attempted/executed/outcome — not ALLOW alone)  
- Where did the workflow stop? (`pipeline.stopped`, hop_denied / hop_error)  
- Was telemetry complete? (four-layer status)  
- What evidence exists? (path + indexed copy)

Not: multi-index SOC, notable events, risk scores, asset inventories.

---

## HOME UX

Orient:

- Platform purpose (learning range)  
- Current learning level (0 / 1)  
- Current lab (WS-001)  
- Lifecycle progression (strip, not charts)  
- Recent runs (id, mode, profile, evidence chip)  
- Next recommended activity  

No vanity metrics (events/sec, “risk score,” technique %).

---

## Empty, no-data, and failure states

| Situation | UI |
|-----------|-----|
| No events in window | Explain how to create a baseline. Zero is not healthy. |
| run.id not found | “No indexed events for this id. Runtime may still have a bundle. Splunk absence ≠ DENY.” |
| HEC/index down | FAILURE: “Ingest not verified.” |
| ALLOW without llm.* | PARTIAL / NOT VERIFIED — do not auto-label prevented. |
| DENY with llm.completed | FAILURE / contract break. |
| llm.failed | Label executed + error. Not prevention. |
| Schema version ≠ 1.0.0 | FAILURE: contract mismatch. |
| Placeholder nav click | “Not in the first lab.” No empty dashboard. |

---

## Attack Service and AcmeBank

External links only. Splunk does not embed those apps as the control plane. Profile is lab configuration, not a Splunk token that changes AcmeBank.

---

## Accessibility and teaching

- Reading order top → bottom, left → right.  
- Decision words in text.  
- Delegator: “prior agent (in-process, not A2A).”  
- Preview ≤200; hash visible; no secrets.

---

## Major decisions

### Decision: GRID only in the first lab

**WHY:** Workshops and hunts are operational learning, not posters.  
**SECURITY:** Absolute art-boards hid empty states in the predecessor.  
**LEARNING:** One reading order.

### Decision: Splunk cannot mark RUNTIME COMPLETE by itself

**WHY:** Phase 1B: runtime is authoritative; the index is a copy.  
**SECURITY:** Prevents Splunk-only DENY theater.  
**LEARNING:** PROVE includes disk + runtime.

### Decision: Hop cards before spans

**WHY:** Learners need intake→compliance, not OTel first.  
**SECURITY:** Still uses real hop.index / event.name.  
**LEARNING:** Correlation without exporter jargon.
