# AgentSec competency model

**Status:** DESIGN (Phase 15A historical body below). **Phase 16C canonical four-stage model is in the next section.** **16D:** stages appear on Home PATH (COMPETENCY). **17A:** Mastery Check uses FOUNDATIONAL / PRACTITIONER / INVESTIGATOR / ADVANCED / PURPLE TEAM as challenge labels. Not a certificate. Not a leaderboard.  
**Completion is competency-based.** Viewing dashboards is not completion.

16C stages are cumulative. 15A names FOUNDATION / DEFENDER / ARCHITECT remain valid as finer grain; they map onto the four 16C stages.

---

## 16C canonical stages

### FOUNDATIONAL

**Observable:** Explains DATA ≠ AUTHORITY, REQUEST ≠ GRANT, Splunk ≠ enforcement, OBSERVE ≠ ALLOW, ALLOW ≠ EXECUTION, missing event ≠ prevention — without launching.

**Evidence:** Walkthrough of Home + one LEARN tab using the reasoning chain.

**Not yet required:** SPL or Attack Service.

**15A map:** FOUNDATION.

### PRACTITIONER

**Observable:** Launches a closed allowlisted experiment, copies `run.id`(s), locates indexed evidence, reconstructs sequence, identifies the control decision, names the PDP.

**Evidence:** LIVE PI-001 or MCP-001 (then later LIVE labs). Rejects browser-supplied profile/grants.

**15A map:** PRACTITIONER + early DEFENDER.

### INVESTIGATOR

**Observable:** Correlates evidence planes without relying only on Studio tables. Distinguishes authoritative (runtime handler/LLM count, control decision) from corroborative (Splunk copy). Compares ATTACK/RETEST equivalent bytes. Explains what cannot be proven. Uses Path A for at least one hunt.

**Evidence:** RAG/memory cross-event; Goal dual-plane; Identity NOT PROVEN authentication; REPLAY MCP-003/004 if claiming grant anatomy.

**15A map:** INVESTIGATOR + DEFENDER.

### ADVANCED / PURPLE TEAM

**Observable:** Investigates a multi-stage packet (capstone retrieve → write → recall → MCP). Reasons across RAG/memory/tool and **rules out** goal/identity when the evidence does not require them. Recommends hunt vs detector without inventing DET-*. Does not convert every suspicious signal into an incident.

**Evidence:** LAB-AGENTSEC-CAPSTONE-001 Path A + CAP-I16 classifications. Handler count cited as execution authority.

**15A map:** PURPLE TEAM + ARCHITECT.

### Mapping after 16B (replaces the stale 15A table for *current* product)

| 16C stage | Labs that can demonstrate it now |
|-----------|----------------------------------|
| FOUNDATIONAL | Home (once orientation exists; today LEARN tabs only) |
| PRACTITIONER | All seven LIVE Attack Service labs |
| INVESTIGATOR | All seven LIVE + REPLAY workshops |
| ADVANCED / PURPLE TEAM | Capstone LIVE (16B) + Mastery Check PURPLE TEAM (17A) |

**17A:** completion evidence is a self-assessed readout plus the rubric in `docs/AGENTSEC_MASTERY_RUBRIC.md`. Viewing Mastery Check is not DEMONSTRATED.

Historical 15A mapping table is retained below and is **stale on Defender/Purple/Architect rows**.

---

## FOUNDATION

**Observable:** Given a diagram of an AgentSec lab, the learner names agent, tool, trust boundary, request, authorization, execution, and telemetry without mixing them.

**Evidence of ability:** Oral or written walkthrough of Home + one LEARN tab (PI or MCP-001) using the reasoning chain in `docs/AGENTSEC_SECURITY_REASONING_MODEL.md`.

**Not yet required:** Launching attacks or writing SPL.

---

## PRACTITIONER

**Observable:** Launches a **closed** experiment (or states honestly that this lab is REPLAY-only), records a fresh `run.id`, and opens Search with that id.

**Evidence of ability:** LIVE on LAB-PI-001 or LAB-MCP-001 Attack Service; equivalent for migrated labs later.

**Must not claim:** Browser-supplied profile or tool name was honored (Attack Service rejects those fields).

---

## INVESTIGATOR

**Observable:** Reconstructs an agent execution from telemetry **without relying solely on prebuilt dashboard panels**. Uses Path A (Search) for at least one hunt question.

**Evidence of ability:** Answers who / what was requested / what was decided / whether execution started, citing event names and `run.id`.

**Progression:** Early labs may use Path B after an honest try; advanced labs delay solution SPL (`docs/AGENTSEC_SPLUNK_SKILL_PROGRESSION.md`).

---

## DEFENDER

**Observable:** Names the actual enforcement boundary (CTRL-INPUT-001 vs CTRL-MCP-001 vs classify-only OBSERVE) and distinguishes runtime controls from Splunk monitoring.

**Evidence of ability:** Can activate or describe the **secure profile** path and explain what RETEST keeps constant (adversarial input) vs what it changes (profile/control).

**Must not claim:** Splunk, Studio, scanner, or a detector granted or denied the operation.

---

## PURPLE TEAM

**Observable:** Compares ATTACK and RETEST: same lab, equivalent adversarial bytes (fingerprint), different profile, different authorization/execution, and states limitations (one pair ≠ universal resistance; HEC lag; LLM nondeterminism on PI ALLOW).

**Evidence of ability:** Completed COMPARE/PROVE on PI-001 and MCP-001 (existing 14D/14E) or a later migrated pair.

---

## ARCHITECT

**Observable:** Reasons across input, catalog/result, RAG, memory, identity/delegation, tools, and goals **without granting authority to untrusted channels**. Recommends the correct control plane for a proposed design. Distinguishes hunt vs detection vs future analytic vs rejected signal.

**Evidence of ability:** Capstone-style investigation (when implemented) or a DESIGN EXERCISE that traces a mixed workflow and refuses to invent DET-* / ML-as-PDP.

---

## Mapping stages to current labs

| Stage | Labs that can demonstrate it today |
|-------|-------------------------------------|
| FOUNDATION | Home, any LEARN tab |
| PRACTITIONER | LAB-PI-001, LAB-MCP-001 LIVE |
| INVESTIGATOR | All published workshops (REPLAY or LIVE) |
| DEFENDER | PI-001, MCP-001 LIVE RETEST; others as DESIGN until migrated |
| PURPLE TEAM | PI-001, MCP-001 only (LIVE COMPARE) |
| ARCHITECT | Not yet as a single exercise; pieces exist across labs |

---

## Curriculum completion (graduate bar)

A graduate can:

1. Draw an agentic system and mark trust boundaries.
2. Distinguish data / instructions / requests / claims from authority.
3. Identify the actual enforcement point.
4. Explain request vs grant (including scope and resource once those labs are in the journey).
5. Reconstruct execution from telemetry.
6. Use Splunk Search without depending entirely on dashboards.
7. Compare ATTACK and RETEST.
8. Validate equivalent attack input.
9. Separate authoritative from corroborative evidence.
10. Distinguish hunt from detection.
11. Explain what missing telemetry does not prove.
12. Reason about RAG, memory, tools, identity/delegation, and goals (identity may be DESIGN EXERCISE until Studio exists).
13. Recommend the correct control plane.
14. Explain why Splunk is evidence rather than enforcement.
15. Communicate findings to security engineers and SOC analysts.

Until Level 8–9 exist, “complete AgentSec” for a given wave means meeting the KNOW/DO/… outcomes for that wave plus the inequalities it owns — not “clicked every view.”
