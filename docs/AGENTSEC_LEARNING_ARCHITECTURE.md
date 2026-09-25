# AgentSec learning architecture

**Status:** Phase 8A DESIGN (historical snapshot in this file). **Phase 15A** supersedes the teaching *order* — see `docs/AGENTSEC_CURRICULUM_LEVELS.md` and `docs/PHASE15A_AGENTSEC_CURRICULUM_ARCHITECTURE.md`. **Phase 16A** is the curriculum-integration design snapshot — see `docs/PHASE16A_CURRICULUM_INTEGRATION.md` and `docs/AGENTSEC_LEARNING_LEVELS.md`. **Phase 16B** implements `LAB-AGENTSEC-CAPSTONE-001` — see `docs/PHASE16B_CAPSTONE_RUNTIME_IMPLEMENTATION.md`. **Phase 16C** is the academy audit — see `docs/PHASE16C_AGENTSEC_ACADEMY_AUDIT.md` and `docs/AGENTSEC_CURRICULUM_MAP.md`. **Phase 16D** implements that P0/P1 packaging — see `docs/PHASE16D_ACADEMY_REMEDIATION.md`. **Phase 17A** adds Mastery Check — see `docs/PHASE17A_LEARNER_MASTERY_VALIDATION.md`. **Phase 17B** is fresh-learner usability — see `docs/PHASE17B_FRESH_LEARNER_VALIDATION.md`. **Phase 17C** is technical-correctness audit — see `docs/PHASE17C_TECHNICAL_CORRECTNESS_AUDIT.md`. The post-Capstone blue-team level is documented in `docs/BLUE_TEAM_INVESTIGATION_AND_THREAT_HUNTING.md`; it reuses validated evidence and adds no attack or detector. The post-Blue-Team security-architecture level is documented in `docs/THREAT_MODELING_AND_SECURITY_ARCHITECTURE.md`; it adds one bounded REPLAY / ARCHITECTURE challenge without changing runtime semantics. L8 is documented in `docs/PRIVACY_DATA_PROTECTION_AND_AGENTIC_DATA_GOVERNANCE.md`; it adds a synthetic privacy investigation and minimization comparison while preserving authorization and schema semantics. L9 is documented in `docs/MULTI_STAGE_AGENTIC_ATTACK_INVESTIGATION_AND_DEFENSE.md`; it integrates validated RAG, memory, MCP, privacy, external evidence, investigation, and architecture reasoning without creating a new runtime attack.

Parents: `docs/AGENTSEC_EXPANSION_ARCHITECTURE.md`, `docs/AGENTSEC_ATTACK_RESEARCH_PIPELINE.md`.

---

## What the repository already teaches (Level 1, complete)

The suggested “Level 1 = prompt injection + MCP authorization” is **already shipped**, and it is deeper than that phrase:

| Lab | Property | Workshop |
|-----|----------|----------|
| LAB-PI-001 | Direct PI; CTRL-INPUT-001 before LLM | `ws_lab_pi_001` |
| LAB-MCP-001 | Tool allow-list; DENY ≠ missing rows | `ws_lab_mcp_001` |
| LAB-MCP-003 | Scope | `ws_lab_mcp_003` |
| LAB-MCP-004 | Resource / parameter | `ws_lab_mcp_004` |
| LAB-MCP-005 | Result trust (INV-002) | `ws_lab_mcp_005` |
| LAB-MCP-006 | Confused deputy / ambient authority | `ws_lab_mcp_006` |
| LAB-MCP-CATALOG | Tool-description poisoning (INV-002) | `ws_lab_mcp_catalog` |
| LAB-SCANNER-RUNTIME | Scanner finding vs runtime authz | `ws_lab_scanner_runtime_evidence` |
| LAB-RAG-CONTEXT | Retrieved-context / indirect PI (INV-002) | `ws_lab_rag_context` |
| LAB-MEMORY-001 | Persistent memory / INV-003 | `ws_lab_memory_security` |
| LAB-AGENT-GOAL-INTEGRITY-001 | Goal / instruction integrity (INV-002 / INV-006) | `ws_lab_agent_goal_integrity` |
| LAB-BLUE-TEAM-INCIDENT-001 | Unknown-incident hypothesis, timeline, hunt, evidence ledger, and reporting | `ws_lab_blue_team_incident` |
| LAB-THREAT-MODELING-001 | System, asset, flow, boundary, authority, control, evidence-gap, and residual-risk reasoning | `ws_lab_threat_modeling` |

Result trust is **not** waiting for a future “knowledge” level. Do not re-teach MCP-005 as if it were new.

Detection engineering has a **single** operational detector (DET-MCP-001) plus governance. That is the start of Level 5, not a missing Level 1 item.

---

## Revised progression

Keep eight levels, but reorder so architecture dependencies are honest.

| Level | Name | Status | Contents |
|-------|------|--------|----------|
| **1** | Foundations: prompt + MCP authorization | **COMPLETE** | PI-001, MCP-001/003/004/005/006, Q-MCP hunts, one detector, Studio workshops |
| **2** | Agent trust: catalog, identity, A2A | **PARTIAL** | Catalog + scanner **COMPLETE**. INV-005 / A2A: **Phase 12C Splunk validated** (`LAB-AGENT-DELEGATION-001`; schema 1.8.0; `Q-AGENT-DELEGATION-AUTHORITY`). Workshop and live A2A transport remain later. Goal integrity: **Phase 13E workshop validated** (`LAB-AGENT-GOAL-INTEGRITY-001`; schema 1.9.0; hunt REUSE; **NO NEW DETECTOR**). Product UI: grouped nav + Home (`docs/AGENTSEC_UI_INFORMATION_ARCHITECTURE.md`). |
| **3** | Knowledge & memory | **PARTIAL** | RAG / LAB-RAG-CONTEXT **COMPLETE** (INV-002). INV-003 memory: **Phase 11E workshop validated**. Identity runtime remains 12B+. |
| **4** | Agent supply chain | **ABSENT** | AI BOM, package/model scans, MCP server provenance, skill-scanner — as **imported evidence**, not a tool zoo |
| **5** | Detection engineering | **PARTIAL** | Splunk KO review, hunts vs detections, no-data semantics, DET-MCP-001. Memory 11D: hunt ≠ detection; no DET-MEMORY. More detectors only when predicates exist. |
| **6** | Behavioral analytics | **PLANNED** | Counters first; AI Toolkit / CDTSM optional |
| **7** | Enterprise overlay | **PLANNED** | Optional Cisco enrichment + optional Splunk ES. Core still runs without them. |
| **8** | Research lab | **DESIGNED, not built** | The DISCOVER→TEACH pipeline |

---

## Workshop contract (unchanged)

LEARN → BASELINE → ATTACK → OBSERVE → HUNT → DETECT → DEFEND → RETEST → COMPARE → PROVE

Phase 14A (`docs/PHASE14A_LEARNING_EXPERIENCE_DESIGN.md`) adds instructional beats UNDERSTAND → PREDICT → INVESTIGATE → CONNECT **on top of** this shell. Phase 14E (`docs/PHASE14E_LEARNING_LOOP_GENERALIZATION.md`) promotes the reusable contracts proven by **two** reference labs: LAB-PI-001 (prompt/input trust) and LAB-MCP-001 (tool authorization). Learning metadata is not policy. Remaining labs are **not** auto-migrated. Phase 15A records the curriculum journey and migration waves without implementing them. **Do not start Phase 15B from this file.**

UI: `.cursor/rules/32-ui-design-system.mdc` + `/ui-review`  
Evidence: `/logic-proof`  
Splunk KO: `.cursor/rules/33-splunk-agent-skills.mdc` + `/splunk-ko-review`

A level is not complete because a scanner ran. It is complete when the learner can **retest a control** and **explain zero rows**.

---

## What not to add as a “level”

- Cisco product certification track
- Antares vulnerability localization (wrong job)
- MLTK before metrics
- Live A2A protocol before an identity/grant story (12A designed it; 12B implemented the in-process runtime; transport remains deferred)
