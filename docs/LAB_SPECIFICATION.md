# Lab Specification

**Status:** Phase 1A architecture contract. Phase 2A implements the first runtime slice (`POST /process`, CTRL-INPUT-001, schema 1.0.0 events, local evidence). Live Ollama success and Splunk ingest are **not claimed**. See `docs/IMPLEMENTATION_STATUS.md`.

AgentSec is a range. This file defines how the first implementation is supposed to behave.

---

## Mission

Give learners a small, honest place to:

1. Run a normal AcmeBank loan (baseline).
2. Fire one direct prompt-injection attack.
3. See a reference control decide **before** the model.
4. Reconstruct the run in telemetry and artifacts.
5. Hunt the same `run.id` in Splunk when ingest works (corroboration only; runtime + local evidence prove invocation).

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

| Area | Phase 2A | Notes |
|------|----------|-------|
| Four-agent sequential loan | IMPLEMENTED (stub-proven) | intake → credit → risk → compliance |
| One benign workflow | IMPLEMENTED (stub-proven) | ATK-001 via explicit `POST /process` |
| One prompt-injection attack | IMPLEMENTED (stub-proven) | ATK-002 |
| Input reference control | IMPLEMENTED (stub-proven) | CTRL-INPUT-001 before LLM; not production IPS |
| Vulnerable / defended | IMPLEMENTED (stub-proven) | Config, not attacker |
| `run.id` correlation | IMPLEMENTED (stub-proven) | `incident.id` = `run.id` |
| OTel export path | PLANNED | Default off in Phase 2A; not Splunk-validated |
| Splunk ingest | PLANNED | Not attempted / NOT VERIFIED |
| Background ticker | Absent | Removed; first baseline is an explicit request |
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
6. When Splunk ingest exists, hunt that `run.id` (validated SPL is a later gate; Splunk is not invocation proof).

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

Two runs (plus a defensive replay), not fifty-one techniques:

| Run | testbed.mode | execution.mode | telemetry.fidelity | Teaches |
|-----|--------------|----------------|--------------------|---------|
| Benign loan | BASELINE | LIVE | OBSERVED | Defend path, telemetry, `run.id` = `incident.id` |
| Direct prompt injection | ATTACK | LIVE | OBSERVED | DENY before LLM in `defended`; labeled ALLOW in `vulnerable` |
| Same payload after profile change | RETEST | LIVE | OBSERVED | DEFEND then RETEST |

The first baseline is an **explicit benign request**, not a background ticker.

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
