# Release lab matrix

Effort numbers come from `learning/academy/curriculum.json` where present. Phase numbers are not the learner model.

| Title | Level | Domain | LIVE/REPLAY | Launch | ATTACK | RETEST | Path A | Path B | Splunk | Primary control | PDP | Detector |
|-------|-------|--------|-------------|--------|--------|--------|--------|--------|--------|-----------------|-----|----------|
| Direct Prompt Injection | L1 | Input | LIVE (+ REPLAY specimens on dashboard) | YES | YES | YES | YES | YES | YES | CTRL-INPUT-001 | input control; tools still CTRL-MCP-001 if invoked | DET-MCP-001 N/A as PI detector |
| Tool Authorization | L1 | MCP | LIVE | YES | YES | YES | YES | YES | YES | CTRL-MCP-001 | coded_policy() | DET-MCP-001 (disabled) |
| Scope Escalation | L1 | MCP | REPLAY | NO | historical | historical | YES | YES | YES | CTRL-MCP-001 | coded_policy() | reuse DET-MCP-001 |
| Parameter / Resource Authorization | L1 | MCP | REPLAY | NO | historical | historical | YES | YES | YES | CTRL-MCP-001 | coded_policy() | reuse |
| RAG / Retrieved Context | L2 | Context | LIVE | YES | YES | YES | YES | YES | YES | CTRL-RAG-CONTEXT-001 (OBSERVE class) | tool PDP CTRL-MCP-001 | no DET-RAG |
| Persistent Memory | L2 | Context | LIVE | YES | YES | YES | YES | YES | YES | CTRL-MEMORY-CONTEXT-001 | tool PDP CTRL-MCP-001 | no DET-MEMORY |
| Tool Result Trust | L2 | MCP | REPLAY | NO | historical | historical | YES | YES | YES | result-trust + CTRL-MCP-001 | coded_policy() | no new DET |
| Tool Catalog | L2 | MCP | REPLAY | NO | historical | historical | YES | YES | YES | catalog + CTRL-MCP-001 | coded_policy() | no new DET |
| Scanner + Runtime Evidence | L2 | Evidence | REPLAY | NO | historical | historical | YES | YES | YES | scanner ≠ PDP | CTRL-MCP-001 | no new DET |
| Goal / Instruction Integrity | L3 | Intent | LIVE | YES | YES | YES | YES | YES | YES | CTRL-GOAL-INTEGRITY-001 | then CTRL-MCP-001 | no DET-GOAL |
| Agent Identity / Delegation | L3 | Intent | LIVE | YES | YES | YES | YES | YES | YES | CTRL-IDENTITY / delegation | then CTRL-MCP-001 | no DET-A2A |
| Confused Deputy | L3 | MCP | REPLAY | NO | historical | historical | YES | YES | YES | CTRL-DELEGATION-001 + CTRL-MCP-001 | both | no DET-006 |
| Lending Assistant Investigation | Capstone | Integrated | LIVE | YES | YES | YES | YES | YES | YES | chain of above | CTRL-MCP-001 for tools | no DET-CAPSTONE |
| Mastery Check | Assessment | — | mixed questions | NO | — | — | some | review | some | — | not scored | not a detector |

**Prerequisites:** follow Home START / curriculum `prerequisites` fields. Estimated effort: see curriculum.json (LIVE hours listed there).

Learners do not edit source, shells, or grants unless a specific advanced doc says so. Published path: Studio → Attack Service → Search.
