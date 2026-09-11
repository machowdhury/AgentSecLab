# Lab Specification

**Status:** PLANNED (Phase 1A architecture). Existing `src/agentsec/` is an **EXPERIMENTAL** thin runtime that already resembles this spec. Phase 1A does not modify it and does not claim live Ollama or live Splunk.

AgentSec is a range. This file defines how the first implementation is supposed to behave.

---

## Mission

Give learners a small, honest place to:

1. Run a normal AcmeBank loan (baseline).
2. Fire one direct prompt-injection attack.
3. See a reference control decide **before** the model.
4. Reconstruct the run in telemetry and artifacts.
5. Hunt the same `run.id` in Splunk when ingest works.

Do not claim to be a production AI-security product.

---

## Names (locked)

| Thing | Name |
|-------|------|
| Defend-path app | **AcmeBank** |
| Offense-path app | **Attack Service** |
| Splunk index | `agentsec_telemetry` |
| Primary sourcetype | `otel:agentic:json` |
| Splunk app id | `agentsec` |
| Lab id (local) | `agentsec-local` |
| Agents | intake, credit, risk, compliance |

---

## Security profiles

| Profile | Fail-open allowed? | Use |
|---------|--------------------|-----|
| `defended` | No. Missing context → ERROR or DENY | Default teaching |
| `vulnerable` | Yes, only if labeled in telemetry | Workshops that demonstrate INV-008 gaps |

Profile comes from **lab configuration**, not from attacker JSON in `defended`.

---

## Capability labels

| Area | Phase 1A architecture | Notes |
|------|----------------------|-------|
| Four-agent sequential loan | PLANNED contract; EXPERIMENTAL code exists | intake → credit → risk → compliance |
| One benign workflow | PLANNED / EXPERIMENTAL | ATK-001 |
| One prompt-injection attack | PLANNED / EXPERIMENTAL | ATK-002 |
| Input reference control | PLANNED / EXPERIMENTAL | CTRL-INPUT-001 before LLM |
| Vulnerable / defended | PLANNED / EXPERIMENTAL | Config, not attacker |
| `run.id` correlation | PLANNED / EXPERIMENTAL | Must be one id for the pipeline |
| OTel export path | PLANNED | Live collector/HEC unproven until run |
| Splunk ingest | PLANNED | Searches unvalidated until event model + live events |
| Output inspection | Absent | Later, SANITIZE/OBSERVE only |
| MCP / A2A / RAG / memory | Absent | Extension points only |
| Attack chains / MLTK / Cisco / compliance UIs | Absent | — |
| 51-technique catalog | Absent | — |

Never describe planned or experimental as production-IMPLEMENTED.

---

## First-implementation definition of done (architecture)

A learner can:

1. Submit a normal loan on AcmeBank.
2. Fire one live attack from Attack Service.
3. See `run.id` in the UI and in local artifacts.
4. Explain whether the control ran before Ollama.
5. Switch `vulnerable` → `defended` (or the reverse) and RETEST the same payload.
6. When Splunk ingest exists, hunt that `run.id` (validated SPL is a later gate).

Engineering gate (when implementation work is allowed in a later phase):

- Unit / security / telemetry tests exist and have been **run**.
- Stubbed LLM: input DENY ⇒ zero model calls.
- No dashboard required.
- No Cisco, MLTK, MCP, A2A, RAG, or memory required.

---

## Runtime shape

| Process | Port | Bind |
|---------|------|------|
| AcmeBank | 5000 | localhost |
| Attack Service | 5001 | localhost |
| Ollama | 11434 | internal / localhost |
| OTel Collector | 4317/4318 | internal |
| Splunk (local profile) | 8000 / 8088 HEC | localhost; HEC not on the internet |

Default model: small local Ollama model (tag chosen at implementation; `llama3.2:1b` is an acceptable default). One model for all agents.

Secrets: from the environment. Lab examples only in `.env.example`. Never hardcode production credentials. Rotate before any non-localhost bind. Flask signing keys must not be committed as shared production secrets (**hardcoded-credentials rule**).

No extra databases, Kubernetes, Kafka, or enterprise IAM.

---

## Curriculum slice

Two runs, not fifty-one techniques:

| Run | Mode | Teaches |
|-----|------|---------|
| Benign loan | BASELINE or LIVE benign | Defend path, telemetry, `run.id` |
| Direct prompt injection | LIVE | DENY before LLM in `defended`; labeled ALLOW in `vulnerable` |

Optional: in-process baseline ticker generating BASELINE events. Not required to understand the architecture.

---

## Major decisions

### Decision: The lab is the proven loop, not the AgentWatch surface catalog

**WHY:** Phase 0 completeness was partly SIMULATED.  
**SECURITY:** Claimed controls will have tests.  
**LEARNING:** One path you can explain completely.

### Decision: Localhost-only default exposure

**WHY:** Attack Service is unauthenticated.  
**SECURITY:** Reachability equals attacker capability.  
**LEARNING:** Bind address is in the threat model.

### Decision: Tests before features

**WHY:** AgentWatch had zero tests.  
**SECURITY:** DENY-before-call regressions are catchable.  
**LEARNING:** Security logic is deterministic even when LLMs are not.
