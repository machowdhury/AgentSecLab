# AgentSec Architecture

**Status:** Architecture remains the contract. Phase 2 runtime code exists under `src/agentsec/` (not a production product).  
**Phase:** 2 runtime (thin loop). MCP/A2A/MLTK/Cisco still later.  
**Predecessor:** AgentWatch Range (READ-ONLY). Proven shapes only. Do not copy blindly.

This is the approved system architecture. Companion specs:

| Document | Topic |
|----------|--------|
| `TRUST_BOUNDARIES.md` | Who is trusted |
| `THREAT_MODEL.md` | Who attacks what |
| `SECURITY_INVARIANTS.md` | What must remain true |
| `SECURITY_EVENT_MODEL.md` | Telemetry contract |
| `LAB_SPECIFICATION.md` | Lab profiles, phases, definition of done |
| `ATTACK_CONTROL_MODEL.md` | Attacks vs reference controls |
| `SPLUNK_ARCHITECTURE.md` | Ingest and app |
| `SPLUNK_DESIGN_SYSTEM.md` | Visual language |
| `SPLUNK_INFORMATION_ARCHITECTURE.md` | Navigation and workshop flow |
| `FRAMEWORK_MAPPING_MODEL.md` | Educational mappings |
| `INTEGRATION_ARCHITECTURE.md` | Cisco track and adapters |

Nothing in this file is IMPLEMENTED until code and tests exist.

---

## What AgentSec is

A learning and SOC experimentation range for agentic AI security.

It is not a production AI-security product. Reference controls teach principles. Splunk is where learners hunt, detect, investigate, and keep evidence.

Lifecycle:

LEARN → BASELINE → ATTACK → OBSERVE → HUNT → DETECT → DEFEND → RETEST → INVESTIGATE → MEASURE → PROVE

Technical chain:

Attack → Trust Boundary → Security Invariant → Control → Control Decision → OpenTelemetry → Splunk → Detection → Investigation → Evidence

---

## System shape

```text
Learner
  ├─ AcmeBank (:5000)         sequential 4-agent loan fabric
  ├─ Attack Service (:5001)   lab attacks into AcmeBank only
  ├─ Ollama                   live LLM (one model for all agents)
  ├─ OTel Collector           OTLP → Splunk HEC + file archive
  └─ Splunk                   one AgentSec app (Dashboard Studio)
        └─ Workshop Engine    curriculum over the same events
```

Optional later, not Phase 1 runtime: MLTK track, Cisco Advanced Track overlay, community adapters.

No Kubernetes, Kafka, extra databases, cloud control plane, microservices mesh, or enterprise IAM.

---

## Major architecture decisions

### Decision: Green-field AgentSec, not an AgentWatch fork

**DECISION:** Build AgentSec as a new lab that borrows AgentWatch *shapes* (inventory classes REUSE/REFACTOR). Do not git-copy the old application.

**ALTERNATIVES:** Fork AgentWatch; wrap AgentWatch with a new name.

**WHY CHOSEN:** AgentWatch has no tests, unwired guard flags, SIMULATED events that look like live proof, and no `run.id`. Copying would recreate those defects.

**SECURITY CONSEQUENCE:** Controls, telemetry, and evidence rules can be designed to match INV-001–INV-008 instead of retrofitting regex theater.

**LEARNING VALUE:** Learners see an architecture that matches the rules they are taught.

### Decision: Five-container Compose lab

**DECISION:** AcmeBank, Attack Service, Ollama, OTel Collector, Splunk (local profile). External Splunk is an overlay later.

**ALTERNATIVES:** Single container; Kubernetes; Splunk SDK inside the app; no local Splunk.

**WHY CHOSEN:** AgentWatch proved this mesh is understandable and enough for the lifecycle. Core rules forbid extra platforms.

**SECURITY CONSEQUENCE:** Fewer moving parts, fewer accidental trust boundaries. HEC and Ollama stay off the public internet by default.

**LEARNING VALUE:** A learner can draw the whole system on one page.

### Decision: AcmeBank story with four sequential agents

**DECISION:** Keep the ACME Bank loan story. Four agents in one process: intake → document ingest → credit risk → compliance. Same Ollama model. Documented as sequential orchestration, not distributed A2A.

**ALTERNATIVES:** Two agents in Phase 1; HTTP-between-agents A2A now; a new domain (healthcare, trading).

**WHY CHOSEN:** Four roles teach privilege increase along a pipeline. One process avoids fake network A2A. The story is already proven pedagogy.

**SECURITY CONSEQUENCE:** Trust labels on agents are teaching names until later surfaces exist. Prompt-paste handoff is an explicit residual risk (see threat model).

**LEARNING VALUE:** Learners can explain why “four agents” is not the same as “four services with cryptographic identity.”

### Decision: Attack Service is a separate process

**DECISION:** Offense UI/API on its own port. It may only HTTP-call AcmeBank. It must not call Ollama or skip reference controls.

**ALTERNATIVES:** Combined bank+attack app; attacks injected inside the LLM client.

**WHY CHOSEN:** Makes the trust boundary visible. Matches AgentWatch’s strongest teaching split.

**SECURITY CONSEQUENCE:** Attack Service is untrusted relative to AcmeBank. There is no “admin exploit hook.”

**LEARNING VALUE:** Red team and blue team use different doors on the same pipeline.

### Decision: Reference controls, two profiles, honest DENY

**DECISION:** Lab-original reference controls with decisions ALLOW / DENY / SANITIZE / QUARANTINE / REQUIRE_APPROVAL / OBSERVE / ERROR. Profiles: `vulnerable` (labeled fail-open) and `defended` (fail closed). DENY is only valid if the dangerous operation did not succeed.

**ALTERNATIVES:** Always-on regex with no profiles (AgentWatch); vendor product as the only control; output HARD_DENY after inference reported as blocked call.

**WHY CHOSEN:** Teaches INV-008 and control placement. AgentWatch’s unused env flags taught the wrong lesson.

**SECURITY CONSEQUENCE:** Defended labs cannot silently ALLOW on missing context. Output inspection cannot rewrite history.

**LEARNING VALUE:** Placement and honesty matter more than a vendor name on a regex.

### Decision: OpenTelemetry is the evidence bus; Splunk is the SOC

**DECISION:** Apps emit OTLP. Collector exports to HEC. Apps do not embed a Splunk SDK. One `run.id` covers the whole pipeline.

**ALTERNATIVES:** Direct HEC from Flask; Splunk UF on the app; logs-only without traces.

**WHY CHOSEN:** AgentWatch’s collector pattern worked. Direct HEC duplicated schemas. Missing `run.id` broke reconstruction.

**SECURITY CONSEQUENCE:** Splunk cannot authorize. Incomplete export is incomplete evidence, not a fake ALLOW.

**LEARNING VALUE:** Separation of enforcement and observation.

### Decision: Phase 1 is a thin proven loop

**DECISION:** Phase 1 target is: one benign run, one live attack, input control before LLM, honest output inspect, OTel with `run.id`, artifacts pack, tests, two validated Splunk searches. Not 51 techniques, 14 dashboards, MLTK, or Cisco.

**ALTERNATIVES:** Import AgentWatch dashboards first; Run All 51 first.

**WHY CHOSEN:** Migration priority P0. Dashboards without fields and tests are theater.

**SECURITY CONSEQUENCE:** Every claimed control in Phase 1 can be unit-tested with a stubbed LLM.

**LEARNING VALUE:** Finish LEARN→PROVE on one path before adding coverage matrices.

---

## Component map

| Subsystem | Phase 1 | Later |
|-----------|---------|-------|
| AcmeBank | Sequential 4-agent API + baseline tick | Memory, tools, workflow states |
| Attack Service | Custom + one catalog LIVE attack | Top 10, chains, First Win |
| Reference controls | Input before LLM; output SANITIZE/OBSERVE | MCP allowlist, HITL, workflow |
| OTel | Logs + traces, `run.id` | Optional metrics index |
| Splunk | Index, HEC, 2 searches | Studio suite |
| Workshop Engine | One guided path | Exercise Runner, tiers 0–6 |
| Detection engineering | 1–2 hunts | Savedsearch library |
| Evidence | `artifacts/<run-id>/` | Richer packs |
| MLTK / Cisco / adapters | Absent | Optional tracks |

---

## Data flow (Phase 1)

```text
Learner or baseline ticker
  → AcmeBank mints run.id
  → per agent: controls → (DENY/ERROR: no Ollama) or Ollama → output inspect
  → OTel (same run.id) → Collector → Splunk
  → artifacts/<run-id>/

Attack Service → same AcmeBank APIs with testbed_mode=LIVE
```

SIMULATED emit (later) is OTel-only and must not count as live control proof.

---

## Related

- Inventory: `docs/MIGRATION_INVENTORY.md`
- Priority: `docs/MIGRATION_PRIORITY.md`
- Teaching: `docs/learning-notes/agentic-architecture-101.md`
