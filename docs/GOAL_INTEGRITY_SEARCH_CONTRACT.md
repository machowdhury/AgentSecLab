# Goal integrity search contract

**Status:** Phase 13C **VALIDATED**.  
**Lab:** LAB-AGENT-GOAL-INTEGRITY-001 / GOAL-001  
**Schema:** 1.9.0 (SPL is schema-version agnostic)

Parents: `docs/PHASE13C_GOAL_INTEGRITY_SPLUNK_VALIDATION.md`, `docs/GOAL_INTEGRITY_SPLUNK_FIELD_CONTRACT.md`, `docs/MCP_SEARCH_CONTRACT.md`.

---

## Published

| ID | Type | Token | Persistence |
|----|------|-------|-------------|
| `Q-GOAL-INTEGRITY-AUTHORITY` | HUNT | `__RUN_ID__` | File under `learning/level_1/LAB-AGENT-GOAL-INTEGRITY-001/searches/`. Not a scheduled saved search. |

Security question: for this run, what authoritative task was assigned, what untrusted instruction was observed, what task change was proposed, what did CTRL-GOAL-INTEGRITY-001 decide, what became the effective action, what did CTRL-MCP-001 decide, and was execution observed?

## Reused (unmodified)

| ID | Classification |
|----|----------------|
| Q-MCP-WHO | REUSE WITH DOCUMENTED LIMITATION (extra GOAL row; tool = proposed action id) |
| Q-MCP-AUTHZ | REUSE WITH DOCUMENTED LIMITATION (GOAL + hop-1; empty MCP fields on GOAL row) |
| Q-MCP-TOOL | REUSE AS-IS |
| Q-MCP-EXECUTED | REUSE WITH DOCUMENTED LIMITATION (extra GOAL-hop row by action id) |
| Q-MCP-AFTER-DENY | REUSE AS-IS (0 rows; DENY tool ≠ mcp.started tool) |
| DET-MCP-001 | REUSE AS-IS (measured 0/0/0; not a goal detector) |

## Rejected / not published

Q-GOAL-TASK, Q-GOAL-INSTRUCTION, Q-GOAL-EXECUTED, DET-GOAL, rewrite of Q-MCP-DELEGATION, Dashboard Studio `ws_lab_agent_goal_integrity`, CIM force-map, scheduled saved search, `props.conf` change, `rex` aliases for `agentsec.instruction.hash` / `effective_action`.

Q-MCP-DELEGATION is **NOT APPLICABLE** (CTRL-DELEGATION-001 / MCP-006).

## Naming

`Q-GOAL-INTEGRITY-AUTHORITY` reconstructs four planes in one row. It does not detect `AGENT NOTE` or the lab overlay reason.

## Performance

Index + sourcetype + `run.id` + event names. `eval` / `eventstats` / `where` / `dedup` / `table`. No `join` / `transaction` / `map` / `append` / `rex`. `earliest=0` is lab-only. **LAB MEASURED ONLY.** **LAB VOLUME != PRODUCTION SCALE.**
