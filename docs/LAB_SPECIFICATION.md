# Lab Specification

**Status:** Phase 2 runtime implemented in `src/agentsec/`. Architecture decisions in this file still apply.

AgentSec is a range. This file defines how the range is supposed to behave, not code that already exists.

---

## Mission

Give learners a small, honest place to attack an agentic loan pipeline, see reference controls, and prove outcomes in Splunk — without claiming to be a production AI-security product.

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

---

## Security profiles

| Profile | Fail-open allowed? | Use |
|---------|--------------------|-----|
| `defended` | No. Missing context → ERROR or DENY | Default teaching |
| `vulnerable` | Yes, only if labeled in telemetry | Workshops that demonstrate INV-008 gaps |

Profile comes from **lab configuration**, not from attacker JSON in `defended`.

---

## Capability labels

Use IMPLEMENTED / EXPERIMENTAL / PLANNED / SIMULATED. Never describe planned as implemented.

| Area | Phase 2 runtime (this repo) | Notes |
|------|-----------------------------|-------|
| AcmeBank 4-agent API | IMPLEMENTED | Intake, Credit, Risk, Compliance; tests with stub LLM |
| Attack Service thin LIVE | IMPLEMENTED | ATK-002 only; tests do not call Ollama |
| Input control | IMPLEMENTED | CTRL-INPUT-001 before LLM |
| Output inspect honesty | PLANNED | Not in Phase 2 |
| OTel + `run.id` | IMPLEMENTED in code | Export path unproven until collector/Splunk run |
| Baseline ticker | IMPLEMENTED | In-process BASELINE mode |
| Artifacts pack | IMPLEMENTED | `artifacts/<run-id>/` |
| Two Splunk searches | PLANNED / unvalidated | Disabled savedsearches; local Python hunts exist |
| Workshop one-path | EXPERIMENTAL | Wireframe only; no Studio JSON |
| MCP/A2A/RAG/memory | Absent | Phase 2 forbid list |
| MLTK / Cisco / adapters | Absent | Phase 2 forbid list |
| 51-technique catalog | Absent | — |

---

## Phase 1 definition of done

A learner can:

1. Submit a normal loan on AcmeBank.
2. Fire one live attack from Attack Service.
3. See `run.id` in the UI and in Splunk.
4. Explain whether the control ran before Ollama.
5. Open `artifacts/<run-id>/` and read expected vs actual.

Engineering gate:

- Unit/security/telemetry tests exist and have been **run**.
- Stubbed LLM: input DENY ⇒ zero model calls.
- No dashboard required.
- No Cisco, MLTK, or community adapters required.

---

## Runtime (Phase 1)

| Process | Port | Bind |
|---------|------|------|
| AcmeBank | 5000 | localhost |
| Attack Service | 5001 | localhost |
| Ollama | 11434 | internal / localhost |
| OTel Collector | 4317/4318 | internal |
| Splunk (local profile) | 8000 / 8088 HEC | localhost; HEC not on internet |

Default model: small local Ollama model (exact tag chosen at implementation). One model for all agents.

Secrets: lab defaults only in `.env.example`. Not production credentials. Rotate before any non-localhost bind.

---

## Curriculum slice (Phase 1)

Not 51 techniques. Two runs:

| Run | Mode | Teaches |
|-----|------|---------|
| Benign loan | BASELINE or LIVE benign | Defend path, telemetry |
| Input-injection catalog attack | LIVE | DENY before LLM |
| (optional second) output-pattern attack | LIVE | SANITIZE/OBSERVE after LLM |

---

## Major decisions

### Decision: Phase 1 is the proven loop, not the AgentWatch surface catalog

**DECISION:** DoD above. Coverage matrix, attestation, executive governance, MLTK, Cisco are later.

**ALTERNATIVES:** Port 14 dashboards first; port 51 techniques first.

**WHY CHOSEN:** Migration priority P0. AgentWatch completeness was partly SIMULATED.

**SECURITY CONSEQUENCE:** Claimed controls will have tests.

**LEARNING VALUE:** One path you can explain completely.

### Decision: Localhost-only default exposure

**DECISION:** Compose publishes to localhost. Cloud/VM patterns later with rotated secrets.

**ALTERNATIVES:** `0.0.0.0` for classroom convenience.

**WHY CHOSEN:** Attack Service is unauthenticated in Phase 1.

**SECURITY CONSEQUENCE:** Reachability equals attacker capability.

**LEARNING VALUE:** Lab threat model includes your own bind address.

### Decision: Tests before features

**DECISION:** No important Phase 1 feature is done without tests in `tests/unit`, `tests/security`, `tests/telemetry`.

**ALTERNATIVES:** Manual workshop only (AgentWatch).

**WHY CHOSEN:** AgentSec testing rule. AgentWatch had zero tests.

**SECURITY CONSEQUENCE:** Regressions in DENY-before-call are catchable.

**LEARNING VALUE:** Security logic is deterministic even when LLMs are not.
