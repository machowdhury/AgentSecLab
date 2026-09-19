# Goal integrity runtime contract

**Status:** Phase 13B IMPLEMENTED + LOCALLY VALIDATED.  
**Lab:** LAB-AGENT-GOAL-INTEGRITY-001  
**Attack:** GOAL-001  
**Schema:** 1.9.0  
**splunk.verified:** false

This file implements the 13A design in `docs/GOAL_INTEGRITY_SECURITY_MODEL.md`. It does not redesign it.

---

## WHAT IS IT?

An in-process runner that freezes a server-owned **TaskContract**, interprets an AGENT NOTE into a **ProposedTaskChange**, evaluates **CTRL-GOAL-INTEGRITY-001**, then calls **CTRL-MCP-001** for `lookup_policy`.

## WHY DOES IT EXIST?

To prove the same authoritative task and the same malicious input can produce the same proposed goal change while vulnerable vs defended profiles produce different task-integrity and execution outcomes.

## HOW DOES IT WORK?

1. `authoritative_task_contract()` is coded. Attackers cannot construct it.
2. `parse_goal_request` rejects authority-like keys with ERROR.
3. Closed interpreter: malicious sentence → `extract_full_policy`; otherwise `summarize_lending_policy`. Both still request `lookup_policy`.
4. CTRL-GOAL-INTEGRITY-001:
   - no expansion → OBSERVE `untrusted_instruction_cannot_redefine_task`
   - expansion + defended → DENY `unauthorized_task_expansion`
   - expansion + vulnerable → OBSERVE `vulnerable_profile_fail_open:untrusted_instruction_derived_task_authority` and mint a closed overlay
5. Overlay selects the **effective action**. It is not a tool grant.
6. Hop 1 always asks CTRL-MCP-001 for `lookup_policy` / `policy:read` / `lending-basics`.
7. Handler counts: `wrong_goal_lookup_policy_count` vs `in_task_lookup_policy_count`. `ToolRegistry.invoke_counts["lookup_policy"]` is authoritative that the handler began.

## WHERE DOES IT SIT?

`src/agentsec/goal/`. Workflow `/goal/evaluate`. Agents: orchestrator-000 (hop 0), goal-007 (hop 1).

## TRUST BOUNDARY

`agent.task.contract` then `acmebank.mcp.authorize`.

## WHAT COULD AN ATTACKER CONTROL?

`instruction` (and extra JSON keys, which ERROR).

## WHAT CAN GO WRONG?

Vulnerable overlay treats the proposal as the effective task. The granted tool still ALLOWs. Wrong-goal handler runs.

## TELEMETRY

Schema 1.9.0 fields on the goal control row. Goal hop `gen_ai.tool.name` is the **proposed action id**. MCP hop uses `lookup_policy`. This keeps DET-MCP-001 from correlating goal DENY with later in-task `mcp.started`.

## WHAT CONTROL COULD CHANGE THE RESULT?

Security profile. Same bytes. Defended DENY expansion; vulnerable overlay.

## WHAT TEST PROVES THE LOGIC?

`tests/security/test_goal_integrity.py` — ATTACK/RETEST hash equivalence + divergent handler counts.

CTRL-MCP-001 remains the only tool PDP. Overlay does not persist. `coded_policy()` is unchanged after ATTACK.
