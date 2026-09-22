# AgentSec learning levels (Phase 16A)

**Status:** DESIGN. Historical 16A snapshot. **16C canonical progression:** `docs/AGENTSEC_CURRICULUM_MAP.md`. The Level 3 “capstone DESIGNED, not implemented” line below is **stale**; 16B built `LAB-AGENTSEC-CAPSTONE-001`.  
**Historical dimensional levels (15A):** `docs/AGENTSEC_CURRICULUM_LEVELS.md` (still valid as grant-anatomy order; RAG/memory/identity rows there are **stale on LIVE**).  
**Do not start Phase 16B from this file.** Do not treat this as a nav rewrite. **Do not start Phase 16D from this file.**

Repository evidence: six LIVE Attack Service labs, plus REPLAY workshops. That is **not** eight product levels. Collapse to three learner levels plus orientation.

---

## Level 0 — Orientation

**Prerequisites:** Docker lab READY; Home opens.

**Learning objectives:** Name agent, tool, MCP, RAG, memory, identity claim, telemetry, control, hunt, detection. Name four platform roles. Splunk ≠ enforcement.

**Labs:** `ws_agentsec_home` (DESIGN EXERCISE / REFERENCE).

**Practical skills:** Open Home; copy nothing yet.

**Splunk skills:** None required.

**Security reasoning:** STUDIO = syllabus; SEARCH = notebook; RUNTIME = enforcement.

**Completion evidence:** Learner can state the 15 reasoning questions in `docs/AGENTSEC_SECURITY_REASONING_MODEL.md` as questions, not answers.

**Knowledge checks:** “If Splunk has no rows, was the attack prevented?” → NOT PROVEN.

**Exit competency:** FOUNDATION (`docs/AGENTSEC_COMPETENCY_MODEL.md`).

---

## Level 1 — Foundations (LIVE)

**Prerequisites:** Level 0.

**Learner understands:** Agent architecture on the loan/MCP path, trust boundaries, `run.id`, request vs grant, decision vs execution, HEC ≠ searchable evidence, BASELINE ≠ SAFE, RETEST ≠ universal security.

**Labs (LIVE required):**

1. LAB-PI-001
2. LAB-MCP-001

**Labs (REPLAY, same level’s grant anatomy — do not skip forever):** LAB-MCP-003, LAB-MCP-004.

**Practical skills:** Predict → launch closed experiment → copy `run.id` → Path A Search → Path B after honest try → COMPARE ATTACK/RETEST → PROVE with limitations.

**Splunk skills:** Filter `index=agentsec_telemetry sourcetype=otel:agentic:json`; sequence; `control.decision`; execution events; missing-event honesty.

**Security reasoning:** REQUEST ≠ GRANT; ALLOW ≠ EXECUTION; DENY ≠ PROOF OF NON-EXECUTION; MISSING EVENT ≠ PREVENTION.

**Completion evidence:** Fresh LIVE `run.id`s for PI and MCP-001; written prediction; Path A attempt; PROVE paragraph that names the PDP.

**Knowledge checks:** Distinguish hop-0 DENY from “Splunk blocked it.”

**Exit competency:** PRACTITIONER + early INVESTIGATOR + DEFENDER on two PDPs (CTRL-INPUT-001, CTRL-MCP-001).

---

## Level 2 — Context & authority (LIVE + REPLAY)

**Prerequisites:** Level 1 LIVE labs. MCP-003/004 REPLAY strongly recommended before claiming “I understand grants.”

**Learner investigates:** Retrieved content, persistent memory, task/goal integrity, identity/delegation claims — each as **data** until a coded PDP decides.

**LIVE labs (order):**

1. LAB-RAG-CONTEXT — provenance ≠ trust; retrieved content ≠ authority
2. LAB-MEMORY-001 — stored memory ≠ trusted instruction; two `run.id`s
3. LAB-AGENT-GOAL-INTEGRITY-001 — authorized tool ≠ authorized goal
4. LAB-AGENT-DELEGATION-001 — identity claim ≠ authentication; caller id ≠ grant

**REPLAY labs (INV-002 / deputy):** LAB-MCP-005, LAB-MCP-CATALOG, LAB-SCANNER-RUNTIME-EVIDENCE, LAB-MCP-006.

**Practical skills:** OBSERVE ≠ ALLOW; name classifier vs PDP; cross-run correlation; fingerprint equality ATTACK/RETEST.

**Splunk skills:** Domain hunts (Q-RAG-*, Q-MEMORY-*, Q-GOAL-*, Q-AGENT-DELEGATION-*) **plus** Q-MCP-* on the same experiment. Coalesce/eval only when the hunt already uses them. Cross-run `source_run_id`.

**Security reasoning:** Progressive inequalities in `docs/AGENTSEC_SECURITY_REASONING_MODEL.md`.

**Completion evidence:** Official or learner-launched LIVE pairs for all four Level 2 LIVE labs; one REPLAY write-up for MCP-006 so identity ≠ confused deputy.

**Knowledge checks:** “The tool executed after retrieved content requested it. Which evidence distinguishes influence from authorization?”

**Exit competency:** INVESTIGATOR + DEFENDER across OBSERVE classifiers and CTRL-MCP-001. Not yet ARCHITECT (no fused chain).

---

## Level 3 — System security / purple team

**Prerequisites:** Level 1–2 LIVE; REPLAY workshops listed in gap analysis class A.

**Learner must:** Reason across multiple controls and evidence planes **without being told which control failed.**

**Labs:** LAB-AGENTSEC-CAPSTONE-001 — **DESIGNED**, not implemented. See `docs/AGENTSEC_CAPSTONE_ARCHITECTURE.md`.

**Practical skills:** Symptom-first investigation; ATTACK → telemetry → hunt → mitigation recommendation → RETEST → COMPARE → PROVE; hunt vs detection recommendation without inventing DET-*.

**Splunk skills:** Campaign reconstruction; ATTACK vs RETEST compare; evidence completeness; what remains NOT PROVEN.

**Security reasoning:** Full 16A chain including INFLUENCE and EVIDENCE / PROOF classes.

**Completion evidence (future 16B+):** Capstone packet + Path A investigations + SOC readout. Until then, Level 3 is **not completable**. Do not fake a badge.

**Knowledge checks:** Classify statements SUPPORTED / CORROBORATED / NOT PROVEN / INCORRECT.

**Exit competency:** PURPLE TEAM / ARCHITECT (`docs/AGENTSEC_FINAL_COMPETENCY_MODEL.md`).

---

## UX / learner experience (design only)

Desired: professional, readable, guided, hands-on, progressive, evidence-driven.

Not: dashboard wall, SOC clone, LAB-* directory as the only IA, wall of UUIDs, wall of SPL, rainbow status cards.

| Surface | Current (OBSERVED) | 16A design |
|---------|--------------------|------------|
| HOME | Workshop directory (Attack Labs / Context / Authority / Supply Chain) | Keep one Home. Add a **Start here** path: L0 → PI → MCP-001 → Level 2 LIVE → REPLAY grant labs → capstone (later). Badge LIVE vs REPLAY honestly. |
| LEARNING PATH | Implicit in nav groups | Three levels above; do not invent a progress DB |
| LAB PAGE | 10-tab Studio syllabus | Unchanged in 16A |
| ATTACK SERVICE | Closed launcher | Unchanged; not a PDP |
| SPLUNK SEARCH | Notebook | Unchanged; Path A lives here |
| COMPARE / PROVE | Per-lab tabs | Capstone will reuse the pattern |
| CAPSTONE | Not built | Symptom brief + architecture diagram + Search; **no** “CTRL-X failed” title |

No global UI rewrite in 16A.

---

## Progress model (honest, not gamified)

Possible learner states: NOT STARTED → LEARNED → ATTACKED → INVESTIGATED → DEFENDED → RETESTED → PROVED.

**Persistence:** NOT IMPLEMENTED. A learner **can** prove a state with their own `run.id` + Splunk copy. The platform must not invent a completion cookie.

Do not store fake LEARNED from opening a tab.
