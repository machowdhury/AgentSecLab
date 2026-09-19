# Agent identity / delegation search contract

**Status:** Phase 12C **VALIDATED**.  
**Lab:** LAB-AGENT-DELEGATION-001 / A2A-001  
**Schema:** 1.8.0 (SPL is schema-version agnostic)

Parents: `docs/PHASE12C_AGENT_DELEGATION_SPLUNK_VALIDATION.md`, `docs/AGENT_DELEGATION_SPLUNK_FIELD_CONTRACT.md`, `docs/MCP_SEARCH_CONTRACT.md`.

---

## Published

| ID | Type | Token | Persistence |
|----|------|-------|-------------|
| `Q-AGENT-DELEGATION-AUTHORITY` | HUNT | `__RUN_ID__` | File under `learning/level_1/LAB-AGENT-DELEGATION-001/searches/`. Not a scheduled saved search. |

Security question: for this run, who called whom, what authority was claimed, what privileged operation was requested, what did CTRL-MCP-001 decide, and was execution observed?

## Reused (unmodified)

| ID | Classification |
|----|----------------|
| Q-MCP-WHO | REUSE WITH DOCUMENTED LIMITATION (extra IDENTITY row; agent = callee) |
| Q-MCP-AUTHZ | REUSE WITH DOCUMENTED LIMITATION (OBSERVE + hop-1; no caller/callee columns) |
| Q-MCP-TOOL | REUSE AS-IS |
| Q-MCP-EXECUTED | REUSE WITH DOCUMENTED LIMITATION (extra OBSERVE row by tool) |
| Q-MCP-AFTER-DENY | REUSE AS-IS |
| DET-MCP-001 | REUSE AS-IS (measured 0/0/0; not a identity detector) |

## Rejected / not published

Q-A2A-WHO, Q-A2A-CLAIM, Q-AGENT-IDENTITY-OBSERVE, Q-AGENT-DELEGATION-EXECUTED, DET-A2A, DET-DELEGATION, rewrite of Q-MCP-DELEGATION, Dashboard Studio `ws_lab_agent_delegation`, CIM force-map, scheduled saved search, `props.conf` change, `allowed_tools` eval.

Q-MCP-DELEGATION is **NOT APPLICABLE** (CTRL-DELEGATION-001 / MCP-006). Live 0 rows on A2A-001 ATTACK.

## Naming

`Q-AGENT-DELEGATION-AUTHORITY` is used because `Q-MCP-DELEGATION` already means MCP-006 ambient confused-deputy. This lab is amplification (neither agent owns `customer:read`).

## Performance

Index + sourcetype + `run.id` + event names. `eval` / `eventstats` / `where` / `dedup` / `table`. No `join` / `transaction` / `map` / `append`. `earliest=0` is lab-only. **LAB MEASURED ONLY.**
