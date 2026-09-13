# AgentSec Architecture

**Status:** Phase 1A contract. Phase 2A runtime implements the first `/process` slice; see `docs/IMPLEMENTATION_STATUS.md` and `docs/PHASE2A_RUNTIME_VALIDATION.md`.  
**This document remains the architecture source of truth.**  
**Event, operation, testbed, and evidence-field semantics:** `docs/SECURITY_EVENT_MODEL.md` (Phase 1B) is authoritative.  
**Predecessor:** AgentWatch Range (READ-ONLY). Borrow shapes. Do not copy blindly.

Nothing in this file is a claim that live Ollama success, live Splunk ingest, or production controls work. Phase 2A stub/security tests are documented in `PHASE2A_RUNTIME_VALIDATION.md`.

| Label | Meaning in this file |
|-------|----------------------|
| **PLANNED** | Architecture decision. Not proven by a live stack in this phase. |
| **EXPERIMENTAL** | Historical label for pre-2A `src/agentsec/` alignment. |
| **IMPLEMENTED** | Phase 2A first runtime slice where tests in `PHASE2A_RUNTIME_VALIDATION.md` passed. Live Ollama success and Splunk remain unclaimed. |
| **SIMULATED** | Not used in the first runtime path. Forbidden as live control proof. |

Companion specs: `TRUST_BOUNDARIES.md`, `THREAT_MODEL.md`, `SECURITY_INVARIANTS.md`, `LAB_SPECIFICATION.md`, `ATTACK_CONTROL_MODEL.md`. Event field design is in `SECURITY_EVENT_MODEL.md` (Phase 1B). Where this file disagrees with that contract on telemetry, operation flags, or experiment dimensions, **Phase 1B wins**.

`docs/ARCHITECTURE_PROPOSAL.md` is historical. Where it disagrees with this file or Phase 1B, **those later contracts win**.

---

## Reconciliation

Kept from prior AgentSec architecture work:

- Green-field lab, not an AgentWatch fork
- Five-process Compose mesh
- Attack Service as a separate untrusted client
- Two security profiles and honest DENY
- OpenTelemetry as the evidence bus; Splunk as the SOC
- Thin first loop instead of 51 techniques

Corrected in Phase 1A:

| Prior claim | Phase 1A correction |
|-------------|---------------------|
| Agents include “document ingest” | Four roles are **intake → credit → risk → compliance** |
| Output inspection is in the first slice | First slice has **one** reference control: input inspection **before** the LLM |
| This file described a finished Phase 2 product | This file is the **architecture contract**. Existing `src/` is EXPERIMENTAL alignment only |
| ATK-003 output-pattern attack in Phase 1 | **Not** in the first implementation |

Phase 0 constraints that this architecture must not reintroduce:

- no fabricated control outcomes
- no regex pretending to be MCP / A2A / RAG
- no simulated telemetry presented as live proof
- no post-inference inspection represented as pre-inference prevention
- no broken correlation (`run.id` missing or per-hop `incident.id`)
- no `session.id` / `session_id` split
- no hardcoded credentials
- no Kubernetes, Kafka, extra databases, cloud control planes, or enterprise IAM

---

## What AgentSec is

An open agentic AI security learning and SOC experimentation range.

Practitioners attack AI agents, analyze runtime telemetry in Splunk, build detections, validate reference controls, and reproduce evidence.

It is **not** a production AI-security product.

Learning lifecycle:

LEARN → BASELINE → ATTACK → OBSERVE → HUNT → DETECT → DEFEND → RETEST → INVESTIGATE → MEASURE → PROVE

Authoritative truth flow:

```text
USER / ATTACKER
      ↓
AGENTIC APPLICATION
      ↓
SECURITY DECISION
      ↓
ACTION
      ↓
ACTUAL OUTCOME
      ↓
TELEMETRY
      ↓
SPLUNK
      ↓
INVESTIGATION / DETECTION
      ↓
EVIDENCE
```

Telemetry describes **what actually happened**. It must not manufacture the story.

For whether the governed LLM was invoked, proof order is: **runtime → local run evidence → exported telemetry → Splunk**. Splunk is corroborating unless completeness for that `run.id` is established. Absence of `llm.*` in Splunk is not prevention by itself.

---

## 1. System components

```text
Learner
  ├─ AcmeBank (:5000)         sequential 4-agent loan application
  ├─ Attack Service (:5001)   lab attacks into AcmeBank only
  ├─ Ollama                   one local model for all agents
  ├─ OTel Collector           OTLP → Splunk HEC + optional file archive
  └─ Splunk                   hunt / detect / evidence workbench
```

| Component | Responsibility | First implementation |
|-----------|----------------|----------------------|
| AcmeBank | Enforce policy, run the pipeline, mint correlation ids, emit telemetry, write local evidence | Required |
| Attack Service | Untrusted HTTP client that submits the catalog attack | Required |
| Ollama | Untrusted model. Completes inference only after ALLOW | Required |
| OTel Collector | Forward logs/traces. Does not authorize | Required |
| Splunk | Investigate, detect, learn. Does not authorize | Required as workbench; validated SPL is later |
| Workshop UI | Curriculum over the same events | Later |
| MCP / A2A / RAG / memory / chains / MLTK / Cisco | Extension points only | Absent |

---

## 2. Responsibilities

| Actor | May do | Must not do |
|-------|--------|-------------|
| Learner / Attack Service | Submit loan text; choose the catalog attack | Set `run.id`, profile, control decision, or skip enforcement in `defended` |
| AcmeBank | Decide ALLOW/DENY/ERROR; call Ollama; emit truth | Treat model JSON as policy; emit DENY after a successful LLM call |
| Ollama | Generate text | Authorize, mint ids, or change profile |
| Collector / Splunk | Record and query | Create ALLOW/DENY |
| Tests | Prove deterministic control logic with a stub LLM | Claim live Splunk or live model results unless those systems were run |

---

## 3. Data flow

### Benign (BASELINE)

```text
Explicit benign POST /process
  → AcmeBank mints run.id = incident.id (and trace_id)
  → testbed.mode=BASELINE, execution.mode=LIVE, telemetry.fidelity=OBSERVED
  → for each agent in order:
        input control (profile-aware)
        if DENY or ERROR: emit telemetry, stop, do not call Ollama
        if ALLOW: call Ollama, then emit telemetry for the actual outcome
  → OTel Collector → Splunk
  → artifacts/<run-id>/
```

### Attack (ATTACK)

```text
Attack Service POST /process → same AcmeBank pipeline
  → testbed.mode=ATTACK, execution.mode=LIVE, telemetry.fidelity=OBSERVED
  → same control and LLM path
```

### Defensive replay (RETEST)

Same payload as the attack, after a profile or control change: `testbed.mode=RETEST`, `execution.mode=LIVE`, `telemetry.fidelity=OBSERVED`.

`LIVE` is an **execution** mode, not a `testbed.mode`. There is **no** second LLM client on the Attack Service. There is **no** SIMULATED emit path in the first implementation.

---

## 4. Trust boundaries

Named in `TRUST_BOUNDARIES.md`. Summary:

| Boundary id | From | To |
|-------------|------|----|
| `acmebank.http_api` | Browser / Attack Service | AcmeBank |
| `acmebank.llm_call` | AcmeBank (after ALLOW) | Ollama |
| `acmebank.agent_handoff` | Prior agent text | Next agent prompt (same process) |
| `observability.export` | AcmeBank | Collector / Splunk / artifacts |

Authorization happens only on the AcmeBank side of `acmebank.http_api`, **before** `acmebank.llm_call`.

---

## 5. Attacker-controlled inputs

**Can control:** loan message text; which public AcmeBank route they hit; optional labels such as `user.id` / `technique_id` if the API accepts them as **labels**, not as policy.

**Cannot control in `defended`:** `run.id`, `incident.id`, `security.profile`, model name, control allowlists, `testbed.mode`, `execution.mode`, `telemetry.fidelity`, schema name/version, operation attempted/executed/outcome, HEC token, Splunk admin, control decision fields.

Unknown JSON fields are rejected (ERROR), not merged into policy.

---

## 6. Agent identity

Four coded roles, one process, one model:

| Order | Role | Identity |
|-------|------|----------|
| 1 | Intake | `acme-agent-intake-001` |
| 2 | Credit | `acme-agent-credit-002` |
| 3 | Risk | `acme-agent-risk-003` |
| 4 | Compliance | `acme-agent-compliance-004` |

Agent identity is an allow-list in AcmeBank code. The model cannot add an agent. Unknown ids → ERROR. This is **not** A2A and not four network enclaves.

---

## 7. Principal identity

| Concept | Meaning in the first implementation |
|---------|-------------------------------------|
| Initiator | The HTTP client (`user.id`), e.g. applicant UI, Attack Service, or an explicit benign request |
| Principal | The lab user / applicant on whose behalf the loan is processed. In this slice the principal is the initiator. Agents are not independent legal principals. |
| Agent | Which coded role is executing (`gen_ai.agent.id`) |

Do not collapse initiator, principal, and agent into one “actor” field in later telemetry. Phase 1A only **requires** initiator + agent to be reconstructable.

---

## 8. Delegation

First implementation: authority is **coded pipeline order**. Intake may call Ollama with the intake prompt. Credit/risk/compliance may call Ollama with their prompts and prior text as **data**.

A prompt cannot:

- add a tool
- reorder agents
- expand scope
- mint ALLOW after DENY

Handoff is string concatenation. That is a residual injection risk (`acmebank.agent_handoff`), not a cryptographic delegation object. Hops after intake record `agentsec.delegator.agent.id` (prior coded agent). That is in-process attribution, **not** A2A. Explicit A2A delegation is a **future extension**.

---

## 9. Security decision points

| Point | When | Legal decisions in this slice |
|-------|------|-------------------------------|
| Request validation | Before any agent | ERROR |
| Input reference control | Before each LLM call | ALLOW, DENY, ERROR |
| LLM client | After ALLOW | success or ERROR (dependency failure) |

QUARANTINE, REQUIRE_APPROVAL, and SANITIZE exist in the lab vocabulary. They are **not** used in the first implementation.

---

## 10. Dangerous-operation boundaries

The dangerous operation in this slice is **LLM inference** (Ollama generate).

| If this happened | Telemetry must not say |
|------------------|------------------------|
| Ollama returned a completion | `DENY` of that call |
| Control blocked before HTTP to Ollama | `operation.executed=true` (must be attempted=false, executed=false, outcome=prevented) |
| LLM invocation started, then failed | `operation.executed=false` or `outcome=prevented` (must be attempted=true, executed=true, outcome=error) |

There are no tools, no money movement, no memory writes, and no RAG retrievals in this slice.

---

## 11. Vulnerable vs defended profiles

| Profile | Source | Behavior |
|---------|--------|----------|
| `defended` | Lab configuration only | Empty/malformed → ERROR. Injection match → DENY. No LLM call. |
| `vulnerable` | Lab configuration only | May ALLOW on the same injection match. Telemetry **must** record the profile and a fail-open reason. |

The attacker cannot set the profile in `defended`. Switching profiles is the DEFEND / RETEST lesson.

---

## 12. Control decision semantics

See `ATTACK_CONTROL_MODEL.md`. Short form:

| Decision | Meaning | First slice? |
|----------|---------|--------------|
| ALLOW | Dangerous operation may proceed | Yes |
| DENY | Dangerous operation **must not** occur | Yes (input control) |
| ERROR | Cannot decide safely, or dependency/schema failure | Yes |
| SANITIZE | Transform output after a completed operation | Later |
| OBSERVE | Record without blocking | Later |
| REQUIRE_APPROVAL | Human gate before a privileged transition | Later |
| QUARANTINE | Isolate an agent or session | Later |

Every recorded decision has a reason. Decisions are computed in AcmeBank, never copied from attacker JSON.

---

## 13. Failure behavior

| Failure | `defended` | `vulnerable` |
|---------|------------|--------------|
| Empty / malformed body | ERROR, no LLM | ERROR, no LLM (same as `defended`) |
| Unknown agent id | ERROR, no LLM | ERROR |
| Injection rule match | DENY, no LLM | ALLOW + fail-open reason |
| Ollama down / timeout after invocation started | ERROR, `attempted=true`, `executed=true`, `outcome=error` | Same — infra failure is not DENY and not non-execution |
| Collector / Splunk down | Pipeline still decides; evidence pack still written; Splunk incomplete | Same |

Incomplete export is incomplete evidence. It is not a fabricated ALLOW in Splunk.

---

## 14. Fail-open vs fail-closed

| Profile | Default |
|---------|---------|
| `defended` | Fail-closed: missing required security context does not become ALLOW |
| `vulnerable` | Fail-open **only** as an intentional, labeled INV-008 demonstration |

Never hide fail-open behind unused env flags (AgentWatch lesson).

---

## 15. Runtime truth vs telemetry truth

| Runtime truth | Telemetry truth |
|---------------|-----------------|
| Whether Ollama was invoked | Runtime is authoritative. Telemetry: `operation.attempted` / `operation.executed` / `operation.outcome`. `executed=true` means the call **started**, not that it succeeded. |
| Whether the pipeline stopped | hop list + blocked flag |
| Control outcome | `control.decision` + `control.reason` |
| Profile in force | `security.profile` from lab config |

Forbidden:

- emitting DENY when the model already ran
- emitting SIMULATED `HARD_DENY` for a control that did not run
- writing Splunk-only “what happened” prose that is not derived from events
- letting the model’s JSON override a prior DENY

---

## 16–19. Correlation model

| Id | Granularity | First implementation rule |
|----|-------------|---------------------------|
| `run.id` (`agentsec.run.id`) | One AcmeBank pipeline request (one learner/baseline/attack action) | **Required.** Server-minted UUID. Shared by every hop. Never attacker-set. |
| `incident.id` (`agentsec.incident.id`) | Investigation grouping | **Always the same value as `run.id`** on every event (BASELINE, ATTACK, and RETEST). Do not mint a new incident per agent. Do not omit it on baseline. |
| `trace_id` | One pipeline execution | Same UUID/hex for all hops of that run |
| `span_id` | One hop (control and/or model call) | Unique per hop; handoff spans parent to the previous hop |

Do not emit both `session.id` and `session_id`. If a conversation id exists, use one name (`gen_ai.conversation.id`). Hunt keys for the first slice are `run.id` and `trace_id`.

Kill-chain `chain.id` is a **future** field. Unused now.

---

## 20. Evidence lifecycle

```text
Decision + outcome
  → events (same run.id)
  → local artifacts/<run-id>/   (always, even if Splunk is down)
  → Splunk (when collector/HEC work)
  → learner hunt / detection
  → PROVE using artifacts + (if MEASURED) Splunk export
```

Each pack records: lab id, schema name/version `1.0.0`, model, profile, `testbed.mode`, `execution.mode`, `telemetry.fidelity`, attack id, expected vs actual behavior, control result, limitations, evidence class (OBSERVED / MEASURED / …). Default content is a sanitized preview plus hash, not complete prompts.

Splunk results are MEASURED only when a query actually ran. Local event files are not “Splunk validated.” Missing `llm.*` in Splunk is not DENY proof unless completeness for that run is established.

---

## 21. Deterministic vs nondeterministic behavior

| Deterministic (test without Ollama) | Nondeterministic (live model) |
|-------------------------------------|-------------------------------|
| Schema validation | Wording of ALLOW completions |
| Input control match → DENY/ALLOW/ERROR by profile | Whether a paraphrased injection evades the reference regex |
| Zero LLM calls on DENY | Token counts on ALLOW |
| `run.id` propagation | Model JSON shape |

Security proofs for INV-008 in this slice are **stub-LLM tests**, not live jailbreak scores.

---

## 22. Testing boundaries

Required when the first implementation is built or changed:

| Suite | Proves |
|-------|--------|
| `tests/unit/` | Control function, pipeline stop, id minting |
| `tests/security/` | DENY before stub LLM; attacker JSON cannot set decision/profile |
| `tests/telemetry/` | DENY ⇒ attempted=false, executed=false, outcome=prevented; `llm.failed` ⇒ executed=true, outcome=error; shared `run.id` = `incident.id` |
| `tests/integration/` | HTTP API contract with stub LLM |

Not required to finish architecture: live Ollama, live Splunk, dashboard tests.

---

## 23. Splunk’s exact role

Splunk is the primary telemetry, investigation, detection, learning, MLTK, and evidence **workbench**.

Splunk does **not**:

- authorize loans
- call Ollama
- flip ALLOW/DENY
- invent “what happened”

First implementation needs an ingest path (index + HEC + sourcetype). Validated searches and dashboards are **after** the event model exists and events are real. MLTK is later.

---

## 24. Future extension boundaries

May appear later as labeled labs. Must not leak into the first slice as fake protocols:

| Extension | Boundary to add later |
|-----------|----------------------|
| MCP / tools | Check **before** tool invoke (INV-001) |
| A2A | Explicit identity/delegation object (INV-005) |
| RAG | Retrieved text is data (INV-002) |
| Memory | Trust-tagged records (INV-003) |
| Workflow / HITL | State machine + REQUIRE_APPROVAL (INV-006) |
| Attack chains | Shared incident across **labeled** stages |
| Output inspection | SANITIZE/OBSERVE **after** inference; never DENY-of-call |
| MLTK / Cisco / compliance UIs | Splunk-side or optional overlay; not runtime authorization |

---

## Major decisions

### Decision: Four sequential in-process agents, not A2A

**WHY:** Privilege increases along a loan path without fake network identity.  
**SECURITY:** Trust labels are teaching names. Handoff text remains untrusted data.  
**LEARNING:** Learners can explain “four agents” ≠ “four services.”

### Decision: One reference control in the first slice

**WHY:** User-required minimum. AgentWatch output HARD_DENY taught the wrong DENY lesson.  
**SECURITY:** Input DENY is check-before-use. Output inspection waits until it can be taught honestly.  
**LEARNING:** Placement before catalog breadth.

### Decision: Green-field shapes, not an AgentWatch copy

**WHY:** Phase 0 showed unwired flags, SIMULATED proof, and broken correlation.  
**SECURITY:** Invariants can be designed in instead of retrofitted.  
**LEARNING:** Architecture matches the rules.

### Decision: Localhost lab, no extra platforms

**WHY:** Core rules. Attack Service is unauthenticated in this slice.  
**SECURITY:** Reachability equals attacker capability. Secrets from env only.  
**LEARNING:** Lab ≠ production exposure.

---

## Related

- Phase 0: `docs/MIGRATION_INVENTORY.md`, `docs/MIGRATION_PRIORITY.md`, `docs/learning-notes/how-agentwatch-works.md`
- Teaching: `docs/learning-notes/agentic-architecture-101.md`
- Events: `docs/SECURITY_EVENT_MODEL.md`, `docs/EVIDENCE_MODEL.md`
