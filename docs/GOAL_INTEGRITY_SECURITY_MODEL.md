# Agent goal / instruction integrity security model

**Status:** DESIGN. Implemented in Phase 13B as `src/agentsec/goal/`.  
**Invariant:** INV-002 reused. INV-006 applied to task transitions. **No INV-009.**

---

## WHAT IS IT?

A **server-owned TaskContract** that names the objective and the in-task boundary. Untrusted bytes may propose a change. They must not become the contract.

## WHY DOES IT EXIST?

TOOL ALLOWED != USE OF TOOL FOR ANY PURPOSE ALLOWED.

## HOW DOES IT WORK?

```
SERVER-OWNED TASK CONTRACT
        ↓
AGENT REASONING  ← UNTRUSTED DATA (influence)
        ↓
PROPOSED TASK CHANGE  (data)
        ↓
CTRL-GOAL-INTEGRITY-001
        ↓
RESULTING tools/call
        ↓
CTRL-MCP-001  (tool PDP)
        ↓
HANDLER
```

UNTRUSTED DATA must not become an implicit authority path into the SERVER-OWNED TASK CONTRACT.

## WHERE DOES IT SIT IN AGENTSEC?

Dedicated lab `LAB-AGENT-GOAL-INTEGRITY-001`. Not RAG, not memory, not A2A, not MCP-006.

## TRUST BOUNDARY

`agent.task.contract` — orchestrator-owned task vs instruction fixture.

## WHAT COULD AN ATTACKER CONTROL?

The instruction string (AGENT NOTE). Not task id, not grants, not profile.

## WHAT CAN GO WRONG?

The runtime treats the note as a new objective and uses a **granted** tool for an **out-of-task** action (`extract_full_policy`).

## Control

**CTRL-GOAL-INTEGRITY-001** is justified.

| Decision | Meaning |
|----------|---------|
| OBSERVE / `untrusted_instruction_cannot_redefine_task` | Instruction classified as data; original task remains |
| DENY / `unauthorized_task_expansion` | Expansion rejected. **Not** `tool_not_granted` |
| OBSERVE / `vulnerable_profile_fail_open:untrusted_instruction_derived_task_authority` | LAB-ONLY overlay. Not production. |
| ERROR | Malformed / authority-like keys |

OBSERVE != ALLOW. DENY here is not CTRL-MCP-001.

## Isolation model (locked)

**AUTHORIZED TOOL + UNAUTHORIZED GOAL** (option B).

The section-5 candidate “obtain customer tier” was **rejected**: that retests CTRL-MCP-001 DENY. The proof uses `lookup_policy` for both in-task summarize and out-of-task extract.

Wait for explicit Phase 13B. Do not start Phase 13C from this file.
