# LAB-AGENT-GOAL-INTEGRITY-001 workshop design (Phase 13E contract)

**Status:** DESIGNED — NOT IMPLEMENTED  
**Phase:** 13D design only. **Phase 13E not started.**  
**View (future):** `ws_lab_agent_goal_integrity`  
**Lab:** LAB-AGENT-GOAL-INTEGRITY-001 / GOAL-001  
**Difficulty:** GUIDED  
**Parents:** `docs/PHASE13D_GOAL_INTEGRITY_DETECTION_ANALYSIS.md`, `docs/GOAL_INTEGRITY_SOC_EVIDENCE_PLANES.md`, `docs/AGENTSEC_DESIGN_SYSTEM.md`, `docs/SPLUNK_WORKSHOP_STANDARD.md`, `.cursor/skills/build-workshop/SKILL.md`.

Do **not** build Dashboard Studio, XML, `dashboard.definition.json`, or nav entries in 13D.

Evidence tokens are Phase 13C LIVE IDs (**DOCUMENTED**). Do not bind 13B local packs.

---

## Objective

Teach a SOC how to investigate **AUTHORIZED TOOL + UNAUTHORIZED GOAL** without collapsing task, instruction, goal decision, tool grant, and execution.

Learner question: **what can I prove from the evidence?**  
Not: did Splunk block `lookup_policy`?

Central lesson: **MCP ALLOW DOES NOT MEAN THE AGENT'S GOAL WAS AUTHORIZED.**

## Prerequisites

LAB-MCP-001 (ALLOW ≠ execution). Schema 1.9.0 field contract. `Q-GOAL-INTEGRITY-AUTHORITY` VALIDATED.

## Invariants / controls

INV-002 · INV-006. **No INV-009.** CTRL-GOAL-INTEGRITY-001 (task integrity). CTRL-MCP-001 (sole tool PDP).

## Architecture (LEARN diagram)

```text
SERVER TASK CONTRACT
        ↓
UNTRUSTED INSTRUCTION
        ↓
PROPOSED ACTION
        ↓
CTRL-GOAL-INTEGRITY-001
        ↓
EFFECTIVE ACTION
        ↓
TOOL REQUEST (lookup_policy)
        ↓
CTRL-MCP-001
        ↓
HANDLER
```

The same tool can be legitimate for `summarize_lending_policy` and illegitimate for `extract_full_policy`.

## Tokens (13E bind-only)

| Token | Default | Value |
|-------|---------|--------|
| Hunt / BASELINE | BASELINE | `0aced342-1295-4820-b807-9a8718d9e847` |
| ATTACK | ATTACK | `fd994587-7e1c-4a70-8013-54cb2c85254d` |
| RETEST | RETEST | `605ba7c1-449b-4338-92df-7da3b704b08e` |

Full UUIDs and hashes must appear outside token boxes (LEARN / COMPARE / PROVE). Token boxes may ellipsis.

## Searches (bind only — no new files)

Primary: `Q-GOAL-INTEGRITY-AUTHORITY`  
Reuse: `Q-MCP-AUTHZ`, `Q-MCP-TOOL`, `Q-MCP-EXECUTED`, `Q-MCP-AFTER-DENY`  
DETECT: live DET-MCP-001-shaped hunt (`Q-MCP-AFTER-DENY` or equivalent bind) showing 0 rows; optional `DET-MCP-001-POSITIVE-CONTROL` labeled **SIMULATED** (does **not** imply DET-GOAL exists).

Do not create Q-GOAL-TASK / INSTRUCTION / EXECUTED / DENY.

## Visual contract (13E)

Dashboard Studio GRID, 1440 design width, 12 columns, AgentSec palette (`docs/AGENTSEC_DESIGN_SYSTEM.md`). Body `#17202A` / secondary `#3D4654`. Status as **text + color**, never color alone. Empty tables remain visible with `noDataMessage`. No WCAG certification claim. No neon, no extra charts, no MLTK purple.

Plan for: token ellipsis, hash wrapping, 768-width clipping, Studio empty-state chrome, first-canvas Playwright capture limits.

**First canvas (LEARN)** must state the security lesson without requiring scroll:

- AUTHORIZED TOOL != AUTHORIZED GOAL
- REQUEST != GRANT
- OBSERVE != ALLOW
- ALLOW != EXECUTION
- SPLUNK != ENFORCEMENT

## Flow

LEARN → BASELINE → ATTACK → OBSERVE → HUNT → DETECT → DEFEND → RETEST → COMPARE → PROVE

Each tab: ACTION · RUN ID · RESULT · WHAT HAPPENED · WHY IT MATTERS · NEXT STEP.

---

## LEARN

**ACTION:** Read the ladder and five planes.  
**RUN ID:** none required.  
**RESULT:** learner can state the central sentence.  
**WHAT HAPPENED:** teaching copy, not telemetry.  
**WHY IT MATTERS:** MCP labs taught tool grants. This lab teaches **use of a granted tool**.  
**NEXT STEP:** BASELINE.

Copy above the fold: the five required statements. Explain: the same `lookup_policy` grant is required for the original summarize task; defense is **not** “block the tool.”

Do not dump `_raw`. Do not show full instruction.

---

## BASELINE

**Token:** A `0aced342-1295-4820-b807-9a8718d9e847`  
**Profile:** defended · **Mode:** BASELINE

Show: task `summarize_lending_policy_options` + hash `sha256:6f95aaf2…`; `untrusted_instruction`; proposed/effective `summarize_lending_policy`; GOAL OBSERVE `untrusted_instruction_cannot_redefine_task`; MCP ALLOW `tool_granted`; in-task handler **1**; wrong-goal **0**.

**Do NOT label BASELINE SAFE.** Untrusted instruction is still present. OBSERVE is classification.

---

## ATTACK

**Token:** B `fd994587-7e1c-4a70-8013-54cb2c85254d`  
**Label:** **INTENTIONALLY VULNERABLE LAB PROFILE**

Same authoritative task + malicious instruction + proposed `extract_full_policy` + GOAL OBSERVE overlay + MCP ALLOW + wrong-goal handler **1**.

Required sentence: **The tool was authorized. The use of the tool was outside the authoritative task.**

Do **not** say the instruction authorized the tool. Do **not** treat overlay reason as a production IOC.

---

## OBSERVE

Organize **without `_raw`** and **without full instruction**:

1. TASK — id, hash, provenance  
2. INSTRUCTION — trust, bounded GOAL preview (instruction hash visible)  
3. GOAL DECISION — proposed, OBSERVE/DENY, reason  
4. TOOL AUTHORIZATION — CTRL-MCP-001, tool, scope, resource, ALLOW  
5. EXECUTION — mcp.started/completed; runtime handler counts labeled **runtime authoritative**

Provenance: `otel:agentic:json` / 13C COMPLETE copy. Evidence class OBSERVED vs MEASURED vs runtime.

---

## HUNT

Primary table: `Q-GOAL-INTEGRITY-AUTHORITY` bound to Hunt token (default BASELINE).  
Secondary: Q-MCP-AUTHZ / TOOL / EXECUTED / AFTER-DENY with documented extra GOAL rows.

Teach pivot: TASK → INSTRUCTION → PROPOSAL → GOAL DECISION → EFFECTIVE ACTION → TOOL AUTHZ → EXECUTION.

Do **not** teach `AGENT NOTE` regex as an IOC.

Zero rows: no indexed CTRL-GOAL-INTEGRITY-001 for that `run.id` — not SAFE.

---

## DETECT

**Title:** DETECTION ANALYZED — NO NEW GOAL DETECTOR

DET-MCP-001 (or after-DENY hunt) on A/B/C: **0 / 0 / 0**. Explain why (see 13D analysis). **0 rows is CORRECT. 0 rows != SAFE.**

Classification table: CONTEXT / HUNT / DETECTION / FUTURE RESEARCH / REJECT (candidates A–G).

SIMULATED positive control: MCP execution-after-DENY fixture only, labeled **SIMULATED**. Must not look like DET-GOAL fired.

FUTURE panel: behavioral analytics **NOT IMPLEMENTED**. ANOMALY != INCIDENT. ML MAY PRIORITIZE INVESTIGATION. ML MUST NOT GRANT OR DENY AUTHORITY.

---

## DEFEND

Untrusted instruction may propose a change. It cannot redefine the server-owned task. Goal integrity evaluates expansion. Tool PDP remains CTRL-MCP-001.

RETEST path:

```text
extract_full_policy
    → CTRL-GOAL-INTEGRITY-001
    → DENY unauthorized_task_expansion
    → preserve summarize_lending_policy
    → CTRL-MCP-001 ALLOW lookup_policy
    → legitimate handler executes
```

**DEFENSE DOES NOT MEAN block `lookup_policy`.** The tool is required for the original task.

---

## RETEST

**Token:** C `605ba7c1-449b-4338-92df-7da3b704b08e`

SAME: task, malicious instruction, proposed `extract_full_policy`, tool, scope, resource.  
DIFFERENT: goal DENY, effective summarize, wrong-goal **0**, in-task **1**. MCP ALLOW `tool_granted`.

Do not say MCP blocked the attack.

---

## COMPARE

Three cards.

| | BASELINE | ATTACK | RETEST |
|--|----------|--------|--------|
| Instruction | NORMAL untrusted | SAME malicious as RETEST | SAME malicious as ATTACK |
| Proposed | summarize | extract_full_policy | extract_full_policy |
| Goal | OBSERVE | OBSERVE overlay | DENY expansion |
| Effective | summarize | extract_full_policy | summarize |
| MCP | ALLOW | ALLOW | ALLOW |
| Wrong-goal | 0 | 1 | 0 |

Central sentence: **ATTACK and RETEST use the same malicious instruction and the same proposed task expansion. The difference is the goal-integrity decision, not the MCP tool grant.**

Show complete fingerprints (task, instruction, proposed-change, GOAL snapshot) from 13C.

---

## PROVE — knowledge check (expected answers)

1. **What was the authoritative task?** `summarize_lending_policy_options` (permitted action `summarize_lending_policy`).  
2. **Fingerprint?** `sha256:6f95aaf2adf5b37b11e35805f9bbbb24fdb34f38435590b5042d7c406bdf7b6c`.  
3. **What influenced the agent?** Untrusted instruction (fixture note). Full body not indexed.  
4. **Was the instruction trusted?** No. `untrusted_instruction` on A/B/C. Untrusted ≠ malicious.  
5. **What action was proposed?** A summarize; B and C `extract_full_policy`.  
6. **Was that action inside the task?** A yes; B/C proposal no.  
7. **Goal integrity decision?** A OBSERVE cannot-redefine; B OBSERVE overlay (lab); C DENY `unauthorized_task_expansion`.  
8. **Effective action?** A summarize; B extract; C summarize (MCP preview).  
9. **Was `lookup_policy` authorized?** Yes. CTRL-MCP-001 ALLOW A/B/C.  
10. **Did MCP ALLOW mean `extract_full_policy` was authorized?** No. Tool grant ≠ goal authorization.  
11. **What actually executed?** Hop-1 `lookup_policy` started and completed on A/B/C; **which action** used it differs (runtime handlers).  
12. **Authoritative non-execution proof for wrong-goal?** Runtime wrong-goal count **0** on A and C. Splunk corroborates via effective_action preview + COMPLETE transport. Missing row ≠ proof.  
13. **Why are ATTACK and RETEST comparable?** Same task hash, instruction hash, proposed action/fingerprint, tool/scope/resource.  
14. **Why is DET-MCP-001 silent?** No tool DENY then same-tool start. RETEST DENY is a different `gen_ai.tool.name`.  
15. **Why is `untrusted_instruction` not an incident?** BASELINE has it. It is a trust plane, not exploit proof.  
16. **Why not `AGENT NOTE` as IOC?** Fixture vocabulary; not indexed; brittle; not a general security property.  
17. **Missing evidence for stronger production detection?** First-class effective action and permitted-action id; grant snapshot; planner state; broader action taxonomy.  
18. **What could behavioral analytics add later?** Novelty of task→action; repeated expansion attempts — prioritize hunt, not grant authority.  
19. **Why must ML not become the grant authority?** Anomaly ≠ incident. Authorization is coded policy + task contract.  
20. **Which invariant?** INV-002 (instruction is data, not a grant) and INV-006 (no silent task redefinition).

---

## UI / accessibility (13E implementation notes)

- Readable first canvas; hashes wrap; full IDs outside tokens.  
- Tables visible on zero rows (DETECT 0/0/0 explained).  
- 768 width: stack cards; do not claim arbitrary Studio responsive behavior.  
- Playwright first-canvas may clip; design so the five statements are in the captured region.  
- No formal accessibility certification.

## What 13E must not do

Create DET-GOAL. Rewrite Q-MCP. Change runtime/schema/authz. Bind 13B locals. Show full instruction/`_raw`. Call BASELINE SAFE. Say MCP blocked RETEST. Enable DET-MCP-001 as a scheduled notable. Claim WCAG. Start 13F/A2A/rug-pull/ML.
