# AgentSec Architecture Proposal

**Status:** PLANNED  
**Phase:** Architecture review only. No application code.  
**Inputs:** AgentSec rules, `docs/MIGRATION_INVENTORY.md`, `docs/MIGRATION_PRIORITY.md`  
**Predecessor:** AgentWatch Range (READ-ONLY)

This document proposes the target AgentSec architecture. It is not an implementation claim. Nothing below is IMPLEMENTED unless AgentSec later ships code and tests that prove it.

---

## 1. Problem being solved

Security teams cannot practice agentic AI attacks, detections, and control evidence on a small, honest range.

AgentWatch already proved the loop:

baseline → live attack → reference control → OpenTelemetry → Splunk → hunt / coverage / attestation

AgentWatch also proved what breaks that loop:

- regex theater labeled as MCP / A2A / RAG
- SIMULATED OTel treated like live control proof
- no `run.id`
- no automated tests
- env flags and Cisco “enforce” that do not change runtime
- output DENY after the LLM already ran

AgentSec must keep the loop and fix the honesty.

---

## 2. Learning objective

After using AgentSec, a learner should be able to explain:

1. A legitimate AcmeBank loan path.
2. Where the trust boundary is.
3. What an attacker can control from the Attack Service.
4. Which reference control ran, and whether it ran **before** the dangerous operation.
5. How to find the same run in Splunk using `run.id`.
6. Why SIMULATED evidence is not a live experiment.
7. How a detection, a control decision, and a compliance mapping are three different things.

Lifecycle to teach:

LEARN → BASELINE → ATTACK → OBSERVE → HUNT → DETECT → DEFEND → RETEST → INVESTIGATE → MEASURE → PROVE

Technical chain to teach:

Attack → Trust Boundary → Security Invariant → Control → Control Decision → OpenTelemetry → Splunk → Detection → Investigation → Evidence

---

## 3. Existing AgentSec components involved

| Component | Status | Role in this architecture |
|-----------|--------|---------------------------|
| `.cursor/rules/` | IMPLEMENTED (process) | Invariants, tests, research integrity, Splunk gates |
| `.cursor/skills/` | IMPLEMENTED (process) | Architecture, SPL, workshop, dashboard, logic-proof |
| `docs/MASTER_SPEC.md` | Headings only | Must be filled from this proposal |
| `docs/MIGRATION_INVENTORY.md` | IMPLEMENTED (docs) | Approved reuse/refactor/redesign/drop list |
| `docs/MIGRATION_PRIORITY.md` | IMPLEMENTED (docs) | Phase 1 slice and P0 decisions |
| `apps/`, `splunk_app/`, runtime | Absent | Not built yet |
| `tests/`, `artifacts/`, `research/` | Empty dirs | Required destinations |

There is no AgentSec banking app, Attack Service, OTel pipeline, or Splunk app to extend. This is a green-field design that **borrows shapes** from AgentWatch, not a fork.

---

## 4. Existing AgentWatch functionality that may be reusable

Approved by inventory class:

| AgentSec subsystem | AgentWatch asset | Inventory class |
|--------------------|------------------|-----------------|
| AcmeBank | 4-agent sequential loan pipeline, Ollama client, Dockerfiles | REFACTOR |
| Attack Service | Attack Panel proxy + Top 10 + custom + First Win | REFACTOR |
| Reference Controls | Pre-LLM workflow guard **placement**; regex input/output as **reference** controls | REUSE placement; REFACTOR regex; REDESIGN MCP/A2A/RAG |
| OTel | Collector → HEC; GenAI field names; `testbed_mode`; baseline simulator | REUSE pipeline; REFACTOR correlation |
| Splunk | Canonical `splunk_compliance_app` Studio pattern, macros, lookups, generators | REUSE pattern; rebrand |
| Workshop Engine | Tiers 0–6, Exercise Runner, First Win 6→5→9 | REUSE pedagogy |
| Detection Engineering | `acme_control_block`, campaign macros, savedsearches (disabled) | REUSE after validation |
| MLTK | Anomaly hunting dashboard + CTSM `fit` path | REFACTOR as optional track |
| Evidence | Kill-chain `incident_id`; control matrix as measurement | REUSE idea; add `run.id` + `artifacts/` |
| Compliance | Framework lookups, NIST RMF dashboard, Technique Coverage, Control Attestation | REUSE UI ideas; verified mappings only |
| Cisco Advanced Track | `docker-compose.cisco.yml`, teach-mode routes | REUSE overlay; do not claim enforce |
| Community Adapters | Heterogeneous sourcetypes + `norm_*` | REUSE normalization lesson |

**Do not copy:** legacy `App-Agentic-Compliance`, bulk rename scripts, SOAR-as-control, unwired guard env, “Run All 51” as Phase 1 proof.

---

## 5. Proposed components

Keep the system small: Docker Compose, two Python apps, Ollama, OTel Collector, Splunk. No Kubernetes, Kafka, extra databases, or enterprise IAM.

```text
Learner
  ├─ AcmeBank (:5000)           sequential 4-agent loan fabric
  ├─ Attack Service (:5001)     authorized lab attacks into AcmeBank
  ├─ Ollama                     live LLM
  ├─ OTel Collector             OTLP → Splunk HEC + file archive
  └─ Splunk                     one AgentSec app (Dashboard Studio)
        └─ Workshop Engine      curriculum over the same events
```

Optional later (not Phase 1):

- MLTK track
- Cisco Advanced Track compose overlay
- Community adapter emitters (second sourcetype)

### 5.1 AcmeBank

**What:** The defend-path application. ACME Bank loan story is retained because it is already a proven teaching world.

**How:** Four sequential agents in one process (intake → doc ingest → credit risk → compliance). Same Ollama model for all. Document this as **sequential orchestration**, not distributed A2A.

**Phase 1:** pipeline + health + one session ring + baseline tick.  
**Later:** memory with trust tags, tiny tool allowlist, explicit workflow states.

### 5.2 Attack Service

**What:** The offense-path UI/API. Separate process so the trust boundary is visible.

**How:** HTTP POST into AcmeBank only. It must not call Ollama itself and must not bypass reference controls.

**Phase 1:** one custom live attack + one catalog attack + run metadata (`run.id`, technique, profile).  
**Later:** Top 10, chains, First Win, execute-all with LIVE/SIM/HYBRID labels.

### 5.3 Reference Controls

**What:** Teachable policy points. They are **reference controls**, not a product.

Required decisions (AgentSec enum): ALLOW, DENY, SANITIZE, QUARANTINE, REQUIRE_APPROVAL, OBSERVE, ERROR. Every decision has a reason.

Two security profiles:

| Profile | Intent |
|---------|--------|
| `vulnerable` | INV-008 exception: missing context may fail open, **labeled** |
| `defended` | Missing required context is ERROR or DENY, never silent ALLOW |

Control placement:

| Control | Dangerous operation | Must run |
|---------|---------------------|----------|
| Input inspection | LLM inference | **Before** Ollama |
| Tool / MCP allowlist | Tool invocation | **Before** tool call |
| Workflow / HITL | Privileged transition | **Before** transition |
| Output inspection | **Cannot** undo inference | After Ollama; telemetry must **not** say DENY-of-inference |

Output inspection may SANITIZE or OBSERVE. It must not be reported as “blocked the model call” if the call already succeeded.

### 5.4 OTel

**What:** The evidence bus.

Apps emit OTLP logs (primary) and traces. Collector exports to Splunk HEC. Apps do not embed a Splunk SDK.

Required fields on every security-sensitive event:

`run.id`, `lab.id`, `agentsec.version`, `model`, `security.profile`, `testbed_mode`, `control.decision`, `control.reason`, `gen_ai.agent.id`

`testbed_mode` values (reuse AgentWatch idea, AgentSec names):

- `BASELINE`
- `LIVE`
- `HYBRID`
- `SIMULATED`

### 5.5 Splunk

**What:** SOC range. One app. Dashboard Studio GRID. Macros for index/sourcetype so customers can retarget.

Phase 1: index exists, HEC works, 2–3 **validated** searches, empty-state dashboards optional.  
Later: Technique Coverage, Control Attestation, compliance overview, executive governance, Exercise Runner.

### 5.6 Workshop Engine

**What:** Curriculum over the same AcmeBank runs. Not a second product.

Reuse AgentWatch pedagogy: OBJECTIVE → BASELINE → ATTACK → HUNT → DETECT → DEFEND → RETEST → EVIDENCE → KNOWLEDGE CHECK.

Phase 1: one guided path (benign loan + one input-control attack).  
Later: Exercise Runner, tiers 0–6, First Win analog.

### 5.7 Detection Engineering

**What:** SPL that answers a security question against real fields.

Process (already an AgentSec rule): question → fields exist → simplest SPL → run → inspect → then dashboard.

Catalog detections only after that. Saved searches start disabled.

### 5.8 MLTK

**What:** Optional advanced track for anomaly hunting (token surge, drift).

Not required to complete the core lifecycle. Depends on Splunk MLTK (and CTSM if Cisco track is on). Python must not emit fake “MLTK detected” fields that look MEASURED.

### 5.9 Evidence

**What:** Reconstruct one run.

Store under `artifacts/<run-id>/`:

- run metadata JSON
- control decision
- key OTel events (or pointer to Splunk query + result export)
- detection result
- limitations
- evidence class: OBSERVED / MEASURED / DOCUMENTED / INFERRED / SIMULATED / REPLAYED

### 5.10 Compliance

**What:** Verified educational mappings. Not certification.

Allowed: NIST AI RMF, NIST SP 800-171 Rev. 3, 800-171A Rev. 3, 800-53 where relevant, MITRE ATLAS, OWASP LLM Top 10, OWASP Agentic, CSA MAESTRO.  
**Do not use NIST SP 800-17** (obsolete cryptographic-modes validation; not agentic AI security). Use 800-171 Rev. 3 and 800-171A Rev. 3 only when the requirement and assessment procedure genuinely apply.

Technique Coverage and Control Attestation are **measurement UIs** over live and explicitly SIMULATED events. They must filter or label SIMULATED so coverage % cannot be gamed by OTel injection.

### 5.11 Cisco Advanced Track

**What:** Optional overlay: teach-mode scanners, Foundation-Sec hunt, CTSM/MLTK comparison vs reference regex.

Default lab must work without Cisco binaries. Enforce-mode blocking is **PLANNED** only if a real caller exists and tests prove DENY-before-action. Until then, do not document it as implemented.

### 5.12 Community Adapters

**What:** Later demonstration that agentic apps disagree on schemas and Splunk normalizes them (`norm_*`).

Phase 1 uses one sourcetype. Additional adapters are optional emitters with labeled SIMULATED or third-party-shaped events — never implied to be vendor product feeds.

---

## 6. Data flow

### Legitimate (baseline)

```text
Learner or traffic simulator
  → AcmeBank POST /v1/process
  → mint run.id
  → for each agent:
        reference controls (profile-aware)
        if DENY/ERROR: emit OTel, stop, no Ollama
        else Ollama
        output inspect (SANITIZE/OBSERVE)
        emit OTel (same run.id, child span)
  → OTel Collector → Splunk HEC
  → optional artifacts/<run-id>/
```

### Attack (live)

```text
Attack Service
  → AcmeBank (same APIs)
  → same control + LLM path
  → testbed_mode=LIVE
  → technique_id + expected_behavior on the run
```

### Simulated (hunt/coverage only)

```text
Attack Service or workshop “emit simulated”
  → OTel only
  → testbed_mode=SIMULATED
  → MUST NOT increment “live control proved” attestation
```

### Detection / workshop / compliance

```text
Splunk reads index
  → macros
  → validated SPL
  → Workshop Engine shows ACTION / RUN ID / WHAT HAPPENED from those events
  → Evidence pack copies query output into artifacts/<run-id>/
```

---

## 7. State

| State | Store | Phase 1 |
|-------|-------|---------|
| `run.id` | Created at AcmeBank request entry; returned to Attack Service | Required |
| In-flight pipeline | Process memory | Yes |
| Recent sessions | In-memory ring | Yes |
| Durable DB | None | None |
| Memory / RAG / A2A registry | Not in Phase 1 | Later, trust-tagged |
| Artifacts | `artifacts/<run-id>/` on disk | Required for PROVE |
| Splunk | Index + lookups | Required for hunt |

Assumption: process restart loses in-memory sessions. Artifacts and Splunk are the durable teaching record.

---

## 8. Trust boundaries

```text
Untrusted:  learner browser, Attack Service payloads, retrieved/simulated documents (later)
Boundary:   AcmeBank HTTP API
Trusted:    reference-control decisioning inside AcmeBank (lab-trusted, not production-trusted)
Untrusted:  Ollama output (model is not a security oracle)
Observability: OTel Collector, Splunk (can detect, cannot authorize)
Optional:   Cisco scanners (untrusted until authenticated overlay is tested)
```

Attack Service is **untrusted relative to AcmeBank**. It is a lab peer, not an admin backdoor.

Ollama is **untrusted relative to controls**. Model text cannot GRANT authority (INV-002).

Splunk is **outside** the authorization boundary.

---

## 9. Attacker-controlled inputs

From Attack Service or any HTTP client:

- message / payload
- target agent vs full pipeline
- `technique_id` (must be allow-listed or ignored)
- `security.profile` — **must not** be attacker-set in defended labs; set from lab config
- headers / JSON extra fields (unknown fields rejected)

Not attacker-controlled in defended profile:

- `run.id` (server minted)
- control allowlists
- model name (lab config)
- Splunk HEC token

**UNCERTAIN:** whether a shared classroom Attack Service needs any authentication. Default proposal: localhost-only bind; auth is PLANNED if exposed beyond localhost.

---

## 10. Security invariants

| ID | How this architecture addresses it |
|----|-------------------------------------|
| INV-001 | Tool/MCP allowlist before tool call; sequential agents do not inherit extra tools by prompt paste alone (later: explicit delegation object) |
| INV-002 | Output and RAG content cannot flip ALLOW; retrieved text is data |
| INV-003 | Phase 1 has no durable memory; later memory records carry trust labels |
| INV-004 | Every privileged decision tagged with `run.id` + agent id + profile |
| INV-005 | Phase 1: no A2A network, so impersonation is out of scope except as SIMULATED; later: explicit identity check |
| INV-006 | Pipeline order is code, not model-chosen; later: state machine |
| INV-007 | OTel + artifacts reconstruct the run |
| INV-008 | `defended` fails closed; `vulnerable` fail-open is labeled and workshop-only |

---

## 11. Failure modes

| Failure | Expected control decision | Telemetry |
|---------|---------------------------|-----------|
| Ollama down | ERROR | reason=llm_unreachable; no fake ALLOW |
| Collector down | Request may still complete; evidence incomplete | ERROR/OBSERVE on export fail; do not invent Splunk proof |
| Missing profile | ERROR in defended; labeled fail-open only in vulnerable | reason=missing_profile |
| Malformed JSON | ERROR | no LLM call |
| Regex miss (live model complies) | ALLOW or OBSERVE — actual outcome | detection may still fire; do not rewrite as DENY |
| SIMULATED emit | N/A (no control executed) | testbed_mode=SIMULATED |
| Output pattern match after success | SANITIZE/OBSERVE | never DENY-of-call |

---

## 12. Observability requirements

- One `run.id` per user/API request, including all agent hops and control events
- Child spans per agent, same trace
- Field name `run.id` (and Splunk extraction of the same name — no `session.id` vs `session_id` split)
- Control events include decision + reason **and** whether the dangerous operation executed
- Baseline vs attack separable
- File archive on collector for lab debug
- Metrics to Splunk optional later; Phase 1 hunts use logs

---

## 13. Splunk requirements

| Item | Phase 1 | Later |
|------|---------|-------|
| Index | `agentsec_telemetry` (name PLANNED) | same |
| Sourcetype | `otel:agentic:json` | + adapter sourcetypes |
| HEC bootstrap | required | required |
| Macros | `agentsec_index`, time windows | campaign/technique macros |
| Studio dashboards | none required to prove pipeline | Workshop, Coverage, Attestation, Governance, Hunting |
| Detections | 1–2 validated searches | savedsearches library, disabled by default |
| Lookups | none or tiny technique table | registry, control matrix, frameworks |
| MLTK | absent | optional app |
| Generators | optional | sync scripts + validate script (reuse AgentWatch pattern) |

SPL is not approved until run against representative events.

---

## 14. Testing strategy

Deterministic tests (no LLM):

| Suite | Proves |
|-------|--------|
| `tests/unit/` | control decisions, profile flags, JSON validation |
| `tests/security/` | malicious input denied **before** a fake LLM stub is called |
| `tests/telemetry/` | `run.id` present; DENY events have `operation_executed=false` |
| `tests/splunk/` | later: fixture events + SPL |

Non-deterministic:

- live Ollama tests are optional, labeled, never the only proof of a control

Phase 1 gate: a stubbed LLM test shows input DENY occurs with zero stub invocations.

---

## 15. Alternatives considered

| Alternative | Why not |
|-------------|---------|
| Fork AgentWatch into AgentSec | Copies unwired flags, 45/51 drift, no tests |
| One process for bank + attacks | Hides the trust boundary |
| Real MCP/A2A/RAG in Phase 1 | Violates “smallest useful scope”; AgentWatch showed stubs get oversold |
| Splunk SDK in the app | Couples apps to SIEM; AgentWatch collector pattern is cleaner |
| 14 dashboards on day one | Dashboards without validated SPL |
| Database for sessions | Unnecessary; artifacts + Splunk persist teaching evidence |
| Skip profiles | Cannot teach INV-008 honestly |
| Cisco in default compose | Optional track; default must work offline-ish with Ollama only |

---

## 16. Why the proposed design is simplest

It is AgentWatch’s working shape minus the lies:

- same five-container lab
- same loan story
- same offense/defense split
- same OTel→Splunk bus
- **plus** `run.id`, profiles, honest DENY, tests, and staged tracks (core → workshop/detections → MLTK/Cisco → adapters)

That is enough to teach the lifecycle. Extra surfaces wait until a test can prove them.

---

## Capability labels (required)

| Subsystem | Now | Phase 1 target | Later |
|-----------|-----|----------------|-------|
| AcmeBank | PLANNED | IMPLEMENTED (sequential 4-agent) | memory/tools |
| Attack Service | PLANNED | IMPLEMENTED (thin live attack) | catalog, chains |
| Reference Controls | PLANNED | IMPLEMENTED (input + honest output) | MCP/HITL/workflow |
| OTel | PLANNED | IMPLEMENTED | richer GenAI metrics |
| Splunk | PLANNED | IMPLEMENTED (ingest + 2 searches) | Studio suite |
| Workshop Engine | PLANNED | EXPERIMENTAL (one path) | Exercise Runner |
| Detection Engineering | PLANNED | EXPERIMENTAL | IMPLEMENTED library |
| MLTK | PLANNED | absent | EXPERIMENTAL track |
| Evidence | PLANNED | IMPLEMENTED (`artifacts/`) | richer packs |
| Compliance | PLANNED | absent or one mapping doc | Coverage + Attestation |
| Cisco Advanced Track | PLANNED | absent | EXPERIMENTAL overlay |
| Community Adapters | PLANNED | absent | EXPERIMENTAL |

---

## Uncertain (must not be papered over)

1. Final names: `AcmeBank` vs `AgentSec Bank`; index name `agentsec_telemetry`.
2. Whether Phase 1 ships four agents or two (intake + compliance). Four matches the story; two is smaller.
3. When a real MCP stub is worth it vs keeping tool abuse SIMULATED.
4. Attack Service auth for non-localhost.
5. Whether Technique Coverage belongs in core Splunk or only after 10+ live techniques exist.
6. Cisco license/runtime availability on learner machines.
7. `docs/MASTER_SPEC.md` is still empty; this proposal should be merged into it before coding.

None of these block agreeing the **shape**. They block starting Phase 1 code until chosen.

---

## Affected files if Phase 1 proceeds (not created now)

- `docs/MASTER_SPEC.md` — fill from this proposal
- `apps/acmebank/` — runtime, agents, controls, OTel
- `apps/attack_service/` — UI/API
- `config/otel-collector-config.yaml`
- `docker-compose.yml`
- `tests/unit/`, `tests/security/`, `tests/telemetry/`
- `splunk_app/` — minimal app
- `artifacts/` — run packs
- `docs/learning-notes/` — after the first implemented slice

**Do not implement those in this review.**

---

## Stop

This is the architecture proposal. No AgentSec application code should be written until the uncertain items above are decided and `MASTER_SPEC.md` is filled to match.
