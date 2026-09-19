# PHASE 13D — LAB-AGENT-GOAL-INTEGRITY-001 detection engineering analysis + workshop design

**Date:** 2026-09-18  
**Type:** DESIGN / ANALYSIS ONLY  
**Primary verdict:** **DETECTION ANALYZED — NO NEW DETECTOR**  
**Workshop:** **DESIGNED — NOT IMPLEMENTED**  
**Schema:** `agentsec.security_event` **1.9.0** unchanged  
**Runtime:** UNCHANGED  
**DET-MCP-001:** unchanged  
**Q-GOAL-INTEGRITY-AUTHORITY:** **REUSE**  
**New detector:** none (`DET-GOAL` not created)  
**New SPL:** none  
**Studio:** none (`ws_lab_agent_goal_integrity` is a 13E name only)

Evidence class: 13B runtime + 13C Splunk = **DOCUMENTED** from LIVE field contracts. This file does **not** claim a new LIVE ingest. Pytest does **not** prove detection effectiveness, Splunk rendering, or production scale.

**Phase 13E not started.** No Agent Scan. No rug-pull. No A2A. No ML implementation. No schema bump. No INV-009.

Companion: `docs/GOAL_INTEGRITY_SOC_EVIDENCE_PLANES.md`, `docs/GOAL_INTEGRITY_WORKSHOP_DESIGN.md`.

---

## Security question

What should a SOC **detect** versus **hunt** versus retain as **context** when a **granted** tool is used for an **unauthorized goal**?

Not: “Did the agent have permission to call `lookup_policy`?” It did.

The question is: “Was `lookup_policy` exercised for the server-authorized task?”

**MCP ALLOW DOES NOT MEAN THE AGENT'S GOAL WAS AUTHORIZED.**

---

## Predecessor verification (13C)

Read 13A–13C contracts, schema 1.9.0, field/search contracts, `Q-GOAL-INTEGRITY-AUTHORITY`, Q-MCP, DET-MCP-001, inventory, learning architecture.

13C verdict **PASS — AGENT GOAL / INSTRUCTION INTEGRITY SPLUNK VALIDATED** is **DOCUMENTED**. Live IDs and `dc(_raw)` COMPLETE 10=10=10 are **DOCUMENTED** (not re-ingested in 13D).

| Spec | Profile | Goal | MCP | In-task | Wrong-goal | `run.id` |
|------|---------|------|-----|--------:|-----------:|----------|
| A | defended | OBSERVE cannot-redefine | ALLOW `tool_granted` | 1 | 0 | `0aced342-1295-4820-b807-9a8718d9e847` |
| B | vulnerable | OBSERVE overlay | ALLOW `tool_granted` | 0 | 1 | `fd994587-7e1c-4a70-8013-54cb2c85254d` |
| C | defended | DENY `unauthorized_task_expansion` | ALLOW `tool_granted` | 1 | 0 | `605ba7c1-449b-4338-92df-7da3b704b08e` |

Task hash A=B=C: `sha256:6f95aaf2adf5b37b11e35805f9bbbb24fdb34f38435590b5042d7c406bdf7b6c`.  
B=C instruction hash (preview): `sha256:15a1c5fa3724419b21b854623c594dba28bf4f357efe39c932084374a8cbe5e2`.  
B=C proposed fingerprint (MCP preview): `sha256:6326e3be47ecf73831a06be2b718f42219e0c950d4c989de23aa558bfdc01b34`.  
B=C proposed action: `extract_full_policy`. Tool/scope/resource: `lookup_policy` / `policy:read` / `lending-basics`.

**Discrepancies vs 13C:** none found in repository artifacts. 13D does not silently repair evidence.

Do not reuse 13B local IDs as Splunk proof.

---

## Evidence planes

See `docs/GOAL_INTEGRITY_SOC_EVIDENCE_PLANES.md`.

1 TASK · 2 INSTRUCTION · 3 GOAL DECISION · 4 TOOL AUTHZ · 5 EXECUTION

CTRL-MCP-001 remains the sole tool PDP. CTRL-GOAL-INTEGRITY-001 must not become a second tool PDP. INV-002 and INV-006 reused. **No INV-009.**

---

## ATTACK / RETEST proof

**SAME TASK. SAME MALICIOUS INSTRUCTION. SAME PROPOSED EXPANSION. SAME TOOL GRANT. DIFFERENT GOAL DECISION. DIFFERENT EFFECTIVE ACTION.**

Discriminator: CTRL-GOAL-INTEGRITY-001 + profile. **Do not claim MCP prevented RETEST.** MCP ALLOWs `lookup_policy` on both.

ATTACK: expansion accepted by **INTENTIONALLY VULNERABLE LAB PROFILE**; wrong-goal handler **1**.  
RETEST: DENY `unauthorized_task_expansion`; original summarize preserved; wrong-goal handler **0**.

The instruction did not authorize the tool. The tool was already granted.

---

## DET-MCP-001

Predicate: MCP **DENY** then later `mcp.started` for the **same** `run.id` + **tool**. Unchanged. Must not be taught as “goal DENY then tool start.”

13C MEASURED **0 / 0 / 0**:

- BASELINE: no tool DENY
- ATTACK: tool ALLOW (vulnerable goal profile; not a tool bypass)
- RETEST: GOAL DENY on `extract_full_policy`; hop-1 start is `lookup_policy` — different `gen_ai.tool.name`, so the detector must not fire

**0 rows is CORRECT BEHAVIOR.** **DET-MCP-001 silence != SAFE.** A goal-integrity failure is not automatically a tool-authorization failure.

Secondary statement only: **EXISTING DETECTOR SUFFICIENT FOR THE SPECIFIC INVARIANT** of execution-after-tool-DENY. Not sufficient for unauthorized-goal / authorized-tool.

---

## New detector decision

**DETECTION ANALYZED — NO NEW DETECTOR**

13C already reached this conclusion. 13D re-justifies it against the detection bar (security predicate, required telemetry, correlation, negatives, positive control, FP/FN, performance, severity, schedule, live validation). The bar is **unmet** for DET-GOAL:

- Overlay reason is LAB-ONLY (**REJECT** as production signal).
- `untrusted_instruction` is present on BASELINE (**CONTEXT**).
- Goal DENY is the defended success path (**HUNT**, not a notable).
- Effective action is preview-bounded, not first-class (**TELEMETRY DEPENDENT**).
- No first-class `agentsec.task.action` to compare proposal against without lab knowledge.
- `AGENT NOTE` is fixture vocabulary (**REJECT** as IOC).
- Three lab specimens are not a production population.

Not a later-phase “implement DET-GOAL in 13E” candidate. 13E is a workshop, not a detector phase.

---

## Detection candidate matrix

| ID | Candidate | Classification | Why |
|----|-----------|----------------|-----|
| A | `untrusted_instruction` observed | **CONTEXT** | True on BASELINE. Trust label ≠ malicious. |
| B | Proposed action differs from in-task summarize | **HUNT** | Distinguishes proposal from contract; B and C share the proposal. Needs analyst + task contract. No first-class `task.action`. |
| C | CTRL-GOAL-INTEGRITY-001 DENY | **HUNT** | Expected on defended RETEST. DENY ≠ incident. |
| D | Vulnerable overlay reason | **REJECT** | Lab vocabulary `vulnerable_profile_fail_open:untrusted_instruction_derived_task_authority`. |
| E | Authorized tool + out-of-task effective action | **FUTURE RESEARCH** / **TELEMETRY DEPENDENT** | Teaching gold; production needs first-class effective action + permitted-action taxonomy. |
| F | Rare retrieve/instruction → tool/action sequence | **FUTURE RESEARCH** | Behavioral; ANOMALY != INCIDENT. |
| G | DET-MCP-001 | existing **DETECTION** | Separate invariant (tool DENY then start). Silent here correctly. |

Do not convert HUNT or CONTEXT into DETECTION to make DETECT interesting.

---

## False positive analysis (future analytics)

No measured FP rates. Plausible FPs if someone naively alerted on A–C or E:

- Legitimate task evolution / versioned contracts
- Multi-step decomposition (summarize then extract as a later **authorized** task)
- Planner-generated subgoals that still serve the contract
- Broad but valid use of `lookup_policy`
- Task contracts that are too narrow (every extra read looks like expansion)
- Stale task fingerprints after a legitimate contract update
- Ambiguous action taxonomy (`extract_*` vs `summarize_*` naming)
- Authorized operator override / change-ticket
- Benign untrusted instructions (every user note is untrusted)
- Normal agent planning variance

Alerting on `untrusted_instruction` or GOAL OBSERVE would fire on BASELINE.

---

## False negative analysis

No measured FN rates. Plausible FNs:

- Semantically equivalent wrong goals with different action ids
- Missing instruction telemetry / preview truncation of hashes
- Missing first-class effective-action field
- Task contract too broad (extract still “in task”)
- Attacker stays inside nominal action taxonomy
- Multi-hop goal drift after the first hop
- Encoded/obfuscated instructions
- Planner state not observable (this lab has no LLM planner)
- Telemetry loss (incomplete transport)
- Wrong goal executed through another granted tool

---

## Severity model

Do **not** assign HIGH to `untrusted_instruction`, goal DENY, or proposed expansion.

Severity would need execution, resource, privilege, data sensitivity, blast radius, repetition, cross-agent propagation, downstream impact. **NOT IMPLEMENTED.** No risk score.

---

## Splunk question matrix

Uses the 13C field contract. Hunt `Q-GOAL-INTEGRITY-AUTHORITY` plus Q-MCP.

| Q | Question | Class |
|---|----------|-------|
| Q1 | What authoritative task was assigned? | **SUPPORTED** (`task.id`) |
| Q2 | What instruction influenced the agent? | **PARTIALLY SUPPORTED** (trust + bounded preview; full body NOT INDEXED) |
| Q3 | Trusted or untrusted? | **SUPPORTED** (`untrusted_instruction`) |
| Q4 | What action did the agent propose? | **SUPPORTED** (`goal.proposed`) |
| Q5 | Did that expand the authoritative task? | **PARTIALLY SUPPORTED** (compare proposed to lab permitted action; no first-class `task.action`) |
| Q6 | What did CTRL-GOAL-INTEGRITY-001 decide? | **SUPPORTED** |
| Q7 | What action became effective? | **PARTIALLY SUPPORTED** (MCP `content.preview`) |
| Q8 | Tool / scope / resource requested? | **SUPPORTED** on hop-1 MCP |
| Q9 | What did CTRL-MCP-001 decide? | **SUPPORTED** |
| Q10 | Did execution start? | **SUPPORTED** (`mcp.started`) |
| Q11 | Complete or fail? | **SUPPORTED** (`mcp.completed` / `mcp.failed`) |
| Q12 | Did ATTACK and RETEST share task/instruction/proposal? | **SUPPORTED** / **PARTIALLY SUPPORTED** (hashes first-class + preview) |
| Q13 | Why did outcomes differ? | **SUPPORTED** (goal decision + profile) |
| Q14 | Did MCP ALLOW prove the goal was authorized? | **SUPPORTED** as a **negative**: ALLOW on A/B/C while goals differ. Answer is **no**. |
| Q15 | Authoritative wrong-goal handler proof? | **PARTIALLY SUPPORTED** — runtime counts authoritative; Splunk corroborates via preview + COMPLETE transport |

**REQUIRES NEW TELEMETRY** for production detector E: first-class effective action and permitted-action id. **NOT APPLICABLE:** `session.id`, CIM Authentication.

---

## Existing hunt review

`Q-GOAL-INTEGRITY-AUTHORITY` already reconstructs:

task → instruction trust/preview → proposed action → goal decision → MCP preview (effective action / proposed fingerprint) → MCP ALLOW → execution observation

**REUSE.** Do not create Q-GOAL-TASK, Q-GOAL-INSTRUCTION, Q-GOAL-EXECUTED, or Q-GOAL-DENY. Prefer one strong investigation search.

Limitations (already documented in 13C): preview-bounded hashes; no rex aliases; handler counts remain runtime.

---

## Q-MCP reuse

Unmodified. Known GOAL limitations (13C MEASURED):

| Search | Limitation |
|--------|------------|
| Q-MCP-WHO | Extra row; `gen_ai.tool.name` on GOAL hop is proposed **action id** |
| Q-MCP-AUTHZ | Extra GOAL row with empty MCP scopes |
| Q-MCP-TOOL | AS-IS; `lookup_policy` started A/B/C |
| Q-MCP-EXECUTED | Extra row grouped by action id (`no_mcp_execution_event`) |
| Q-MCP-AFTER-DENY | 0 rows; DENY tool ≠ start tool |

Do not rewrite them for workshop cosmetics.

---

## CIM

**CIM NOT APPLICABLE.** Goal/task/instruction fields are not Malware, IDS, Web, Authentication, Endpoint, or Change. MCP ALLOW is not Authentication. Task-expansion DENY is not Change. Do not force-map.

---

## Performance

Existing hunt: index + sourcetype + `run.id` + event names; `eval` / `eventstats` / `where` / `dedup` / `table`; `mvindex(mvdedup(...),0)`; no join / transaction / map / append / rex. ~10 events/specimen. `earliest=0` lab-only.

**LAB PERFORMANCE** only. **LAB VOLUME != PRODUCTION SCALE.** No production-scale claim.

---

## Privacy

Workshop must show ids, hashes, bounded previews, trust labels, action ids, decisions, reasons, run ids. Must **not** dump `_raw`, full instruction, full policy, credentials, tokens, Authorization headers, or secrets. 13C indexed events did not contain `AGENT NOTE` bodies (**DOCUMENTED**).

---

## Framework mapping

| Class | Mapping |
|-------|---------|
| **DIRECT** | None verified for a specific MITRE ATLAS technique id |
| **RELATED** | INV-002 (data ≠ authority); INV-006 (workflow/task integrity); OWASP/NIST agentic instruction-influence discussion in 13A research (not a numbered proof) |
| **UNMAPPED / REQUIRES REVALIDATION** | GOAL-001 ATLAS AML.Txxxx — do not invent |

Framework labels ≠ exploitation proof.

---

## Behavioral analytics (FUTURE only)

Design only, **NOT IMPLEMENTED:** rare effective action after a common task; task→action novelty; instruction-provenance novelty; unusual tool/action pairs; repeated expansion attempts; per-agent deviation; multi-step drift. Possible later techniques: statistical SPL, MLTK, CDTSM.

**ANOMALY != INCIDENT.** **ML MAY PRIORITIZE INVESTIGATION.** **ML MUST NOT GRANT OR DENY AUTHORITY.** LLM is not an authorization authority.

---

## Phase 13E workshop

Contract: `docs/GOAL_INTEGRITY_WORKSHOP_DESIGN.md`. Ten tabs. View name `ws_lab_agent_goal_integrity`. Tokens = 13C LIVE IDs. **NOT IMPLEMENTED.**

---

## Security review (claims 13D must not introduce)

Forbidden equivalences remain false: MCP ALLOW = goal authorized; goal DENY = tool DENY; untrusted_instruction = malicious; proposed expansion = execution; ALLOW = execution; `mcp.started` = success; `mcp.failed` = prevention; missing Splunk row = blocked; DET-MCP-001 silence = safe; Splunk authorized/prevented anything; ML anomaly = incident; pytest proves Splunk; lab volume proves production scale.

---

## Verdict

**PASS — GOAL / INSTRUCTION INTEGRITY DETECTION ENGINEERING ANALYZED + WORKSHOP DESIGN COMPLETE**

LAB-AGENT-GOAL-INTEGRITY-001: IMPLEMENTED + LOCALLY VALIDATED + SPLUNK VALIDATED  
Schema 1.9.0 · Runtime UNCHANGED · Splunk VALIDATED FROM 13C · Hunt REUSE · CTRL-MCP-001 UNCHANGED  
Detection: **ANALYZED — NO NEW DETECTOR**  
Workshop: **DESIGNED — NOT IMPLEMENTED**  
Phase 13E: **NOT STARTED**
