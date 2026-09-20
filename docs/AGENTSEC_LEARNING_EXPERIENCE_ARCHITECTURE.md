# AgentSec learning experience architecture

**Status:** Phase 14A DESIGN / RESEARCH / CONTRACT ONLY. **Not implemented.**  
**Schema:** 1.9.0 unchanged  
**Parents:** `docs/AGENTSEC_LEARNING_ARCHITECTURE.md`, `docs/AGENTSEC_UI_INFORMATION_ARCHITECTURE.md`, `docs/AGENTSEC_WORKSHOP_UI_STANDARD.md`  
**Do not start Phase 14B from this file.**

AgentSec is a hands-on Agentic Security learning platform. It is not merely a Splunk dashboard collection, an attack simulator, a CVE catalog, or a detection-rule repository.

---

## Learning objective

A learner who completes a supported workshop can:

1. Name the **security property** being tested (not the marketing name of an attack).
2. **Predict** what evidence should appear before anything is launched.
3. Generate or select BASELINE / ATTACK / RETEST evidence without treating Splunk as the enforcer.
4. Investigate in **Splunk Search** (or Studio tables bound to validated hunts) using `run.id` and evidence planes.
5. Distinguish CONTEXT ≠ HUNT ≠ DETECTION ≠ INCIDENT.
6. **Prove** what held, what did not, and what remains unproven.
7. **Connect** the lab to AgentSec invariants and adjacent labs.

Dashboard Studio may guide. It must not replace investigation.

---

## Instructional overlay (does not replace the workshop shell)

The published Studio shell remains:

LEARN → BASELINE → ATTACK → OBSERVE → HUNT → DETECT → DEFEND → RETEST → COMPARE → PROVE

Phase 14A adds **instructional beats**, not new product nav items:

UNDERSTAND → PREDICT → BASELINE → ATTACK → OBSERVE → INVESTIGATE → HUNT → DETECT → DEFEND → RETEST → COMPARE → PROVE → CONNECT

| Beat | Where it lives | Purpose |
|------|----------------|---------|
| UNDERSTAND | LEARN tab copy | Why this lab exists; trust boundary; invariant |
| PREDICT | ATTACK tab **before** launch | Learner states expected decision / execution |
| INVESTIGATE | HUNT + Search | Independent reconstruction; solution hidden until asked |
| CONNECT | New PROVE subsection (later) | Adjacent labs, verified framework notes, residual uncertainty |

Do not add a top-level Splunk nav item named UNDERSTAND, PREDICT, INVESTIGATE, or CONNECT.

PortSwigger Web Security Academy is **pedagogical inspiration only** (clear objectives, visible progression, solution after effort). Do not clone branding, layout, HTML, CSS, or content. AgentSec remains native Dashboard Studio + Attack Service Flask.

---

## Two planes the learner must keep separate

```text
EXECUTION PLANE                         INVESTIGATION PLANE
Attack Service / AcmeBank               Dashboard Studio
        |                                        |
        v                                        v
   Runtime controls                      Validated Q-* hunts
        |                                        |
        v                                        v
   OTEL → collector → HEC                 Splunk Search
        |
        v
   Indexed copy (eventually)
```

Studio does not authorize. Splunk does not enforce. The Attack Simulator does not become a second control plane.

---

## What “hands-on” means

**Hands-on** = the learner forms a question, opens Search or a bound hunt, binds `run.id`, reads fields, and writes a conclusion.

**Not hands-on** = only watching precomputed Studio tables and copying a verdict.

Guided solutions exist so an instructor can demonstrate and a stuck learner can continue. They are Path B, not Path A.

---

## Security semantics (unchanged)

OBSERVE ≠ ALLOW  
REQUEST ≠ GRANT  
ALLOW ≠ EXECUTION  
untrusted ≠ malicious  
zero rows ≠ SAFE  
missing Splunk event ≠ blocked  
Splunk ≠ enforcement  
handler count is authoritative where the lab already established that  
LIVE ≠ SIMULATED ≠ REPLAY  
authorized tool ≠ authorized use of tool  

Do not introduce SAFE / TRUSTED / APPROVED / BLOCKED / PREVENTED unless the evidence actually supports that exact statement.

---

## Related contracts

- Execution modes: `docs/AGENTSEC_LAB_EXECUTION_MODES.md`
- Guided investigation: `docs/AGENTSEC_GUIDED_INVESTIGATION_STANDARD.md`
- Attack Simulator: `docs/AGENTSEC_ATTACK_SIMULATOR_ARCHITECTURE.md`
- Launch: `docs/AGENTSEC_ATTACK_LAUNCH_CONTRACT.md`
- Studio/Search capability honesty: `docs/AGENTSEC_SPLUNK_LEARNING_INTERACTION_MATRIX.md`
- Workshop readiness: `docs/AGENTSEC_CROSS_WORKSHOP_READINESS_MATRIX.md`
- Umbrella: `docs/PHASE14A_LEARNING_EXPERIENCE_DESIGN.md`
