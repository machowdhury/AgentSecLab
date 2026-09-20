# Phase 14A — Learning experience design

**Status:** DESIGN / RESEARCH / CONTRACT ONLY (2026-09-19)  
**Schema:** 1.9.0 **UNCHANGED**  
**Runtime authorization:** **UNCHANGED**  
**Detectors:** none created. DET-MCP-001 **UNCHANGED**. No DET-GOAL.  
**Studio:** no new views. No Attack Simulator implementation.  
**Do not start Phase 14B from this file.**

---

## WHAT IS IT?

The contract for turning AgentSec from “canonical REPLAY dashboards” into a **Understand → Predict → Launch (where honest) → Investigate → Prove → Connect** product — without making Splunk or Studio into enforcement.

---

## WHY DOES IT EXIST?

UI/UX remediation PASS left a cohesive Studio shell. Learners still mostly inspect pre-bound run.ids. They need a designed path to **do** the attack and **do** the hunt.

---

## HOW IT WORKS

Documents in this phase (no code):

| Document | Role |
|----------|------|
| `docs/AGENTSEC_LEARNING_EXPERIENCE_ARCHITECTURE.md` | Overlay on LEARN→PROVE |
| `docs/AGENTSEC_ATTACK_SIMULATOR_ARCHITECTURE.md` | Closed execution plane |
| `docs/AGENTSEC_ATTACK_LAUNCH_CONTRACT.md` | Allowlist JSON + evidence states |
| `docs/AGENTSEC_LAB_EXECUTION_MODES.md` | LIVE / REPLAY / GUIDED |
| `docs/AGENTSEC_GUIDED_INVESTIGATION_STANDARD.md` | Path A/B, difficulty, CONNECT |
| `docs/AGENTSEC_SPLUNK_LEARNING_INTERACTION_MATRIX.md` | Native vs JS vs do-not-build |
| `docs/AGENTSEC_CROSS_WORKSHOP_READINESS_MATRIX.md` | Honest inventory |
| `docs/learning-notes/attack-investigate-prove.md` | Teaching note |

---

## Reference implementation recommendation (not implemented)

**Choose LAB-PI-001 / Direct Prompt Injection for Phase 14B–14E.**

| Criterion | PI-001 | MCP-001 |
|-----------|--------|---------|
| Runtime maturity | High (`POST /process`, CTRL-INPUT-001) | High (`POST /mcp/invoke`, CTRL-MCP-001) |
| Attack launch readiness | **Partial** — Attack Service already fires ATK-002 | None — invoke is manual/API |
| Telemetry completeness | Strong when the copy is indexed (22=22 BASELINE historically) | Strong; handler counts authoritative |
| Learner clarity | Obvious payload; prediction before LLM | Tool allow-list is the MCP curriculum’s foundation |
| BASELINE / ATTACK / RETEST | Yes; RETEST is env-gated | Yes; RETEST also env/override-gated |
| Splunk investigation quality | Q-RUN-EVENTS, Q-CONTROL-DECISION, Q-LLM-EXECUTED, Q-LLM-AFTER-DENY | Q-MCP-* family, reused by later MCP labs |
| Architectural distortion | Smallest: extend existing untrusted client | Would invent the first MCP launcher inside Attack Service |

**Why PI first:** the Attack Service already exists as the untrusted client. 14B can extend an allowlisted launch contract around ATK-001/ATK-002 without teaching Studio to POST. Guided investigation can reuse validated PI hunts. MCP-001 is the **designated second** reference once the launcher contract exists — better SAME-request / DIFFERENT-profile teaching, but not the smallest 14B.

**Honesty required in 14B:** do not advertise one-click LIVE RETEST until runtime actually accepts `mode` for that specimen. Document the override limitation rather than weakening INV-008.

---

## Suggested later phases (not started)

| Phase | Intent | Must not |
|-------|--------|----------|
| 14B | Attack Service allowlist + PI launch UX + Search deep link | Schema bump; Studio POST; auth theater |
| 14C | Guided investigation Path A/B on `ws_lab_pi_001` (bind-only Q-*) | New DET-*; GFM tables |
| 14D | Evidence-readiness copy + completeness vs `dc(_raw)` | Equate HEC 200 with READY |
| 14E | Apply the same launcher+guided pattern to MCP-001 if 14B–14D hold | Clone PI evidence onto MCP |

---

## Security boundaries (acceptance)

- Splunk is not enforcement.
- Studio is not an authorization engine.
- Attack Simulator is closed/allowlisted.
- CONTEXT ≠ HUNT ≠ DETECTION ≠ INCIDENT.
- DETECTION ANALYZED — NO NEW DETECTOR remains a valid ending.
- No schema 1.9.0 bump.
- No detector implementation in 14A.
- No Studio implementation in 14A.

---

## Framework mapping

Secondary. PI may cite ATLAS `AML.T0054` because `src/agentsec/attacks.py` already does. Do not add unverified OWASP/NIST rows in 14A.

---

## Tests

`tests/unit/test_phase14a_design.py` proves documents exist and 14A did not ship runtime/schema/SPL/Studio. Pytest does **not** prove Attack Simulator execution, Splunk rendering, HEC health, evidence readiness, attack safety, or detection effectiveness.
