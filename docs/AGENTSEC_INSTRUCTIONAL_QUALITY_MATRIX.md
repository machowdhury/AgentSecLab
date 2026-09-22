# AgentSec instructional quality matrix (Phase 17B)

PASS = the published learner surface answers the question without repository knowledge.  
NEEDS IMPROVEMENT = remaining P2/P3 only (no open P0/P1).  
NOT APPLICABLE = the lab does not have that beat (for example REPLAY has no LIVE launcher).

Do not treat this table as a LIVE experiment. Ratings are from repository markdown after 17B copy fixes.

| Lab | WHY | PREDICT | Attacker control | Server control | Trust boundary | PDP | Path A | Path B explains output | Execution reasoning | Defense ownership | RETEST equivalence | COMPARE | PROVE | CONNECT | LIVE/REPLAY |
|-----|-----|---------|------------------|----------------|----------------|-----|--------|------------------------|---------------------|-------------------|---------------------|---------|-------|---------|-------------|
| Direct Prompt Injection | PASS | PASS | PASS | PASS | PASS | PASS CTRL-INPUT-001 | PASS | PASS | PASS llm.started | PASS profile | PASS | PASS | PASS | PASS | PASS |
| Tool Authorization | PASS | PASS | PASS | PASS | PASS | PASS CTRL-MCP-001 | PASS | PASS | PASS handler | PASS coded grant | PASS | PASS | PASS | PASS | PASS |
| Scope Escalation (REPLAY) | PASS | NOT APPLICABLE | PASS | PASS | PASS | PASS CTRL-MCP-001 | PASS | PASS after 17B | PASS | PASS | PASS historical | PASS | PASS | PASS | PASS REPLAY |
| Resource Authorization (REPLAY) | PASS | NOT APPLICABLE | PASS | PASS | PASS | PASS CTRL-MCP-001 | PASS | PASS after 17B | PASS | PASS | PASS historical | PASS | PASS | PASS | PASS REPLAY |
| Tool Result Trust (REPLAY) | PASS | NOT APPLICABLE | PASS | PASS | PASS | OBSERVE then MCP PDP | PASS | PASS after 17B | PASS | PASS | PASS historical | PASS | PASS | PASS | PASS REPLAY |
| Confused Deputy (REPLAY) | PASS | NOT APPLICABLE | PASS | PASS | PASS | CTRL-DELEGATION-001 + MCP | PASS | PASS after 17B | PASS | PASS | PASS historical | PASS | PASS | PASS | PASS REPLAY |
| Tool Catalog (REPLAY) | PASS | NOT APPLICABLE | PASS | PASS | PASS | METADATA OBSERVE + MCP | PASS | PASS after 17B | PASS | PASS | PASS historical | PASS | PASS | PASS | PASS REPLAY |
| Scanner + Runtime (REPLAY) | PASS | NOT APPLICABLE | PASS | PASS | PASS | scanner ≠ PDP | PASS | PASS after 17B | PASS | PASS | PASS historical | PASS | PASS | PASS | PASS REPLAY |
| RAG / Retrieved Context | PASS | PASS | PASS | PASS | PASS | RAG OBSERVE; MCP PDP | PASS | PASS | PASS | PASS overlay vs grant | PASS | PASS | PASS | PASS | PASS |
| Persistent Memory | PASS | PASS | PASS | PASS | PASS | MEMORY OBSERVE; MCP on recall | PASS | PASS | PASS recall run | PASS | PASS two-run | PASS | PASS | PASS | PASS |
| Goal / Instruction Integrity | PASS after 17B | PASS after 17B | PASS | PASS | PASS | GOAL then MCP ALLOW both | PASS | PASS | PASS wrong-goal vs in-task | PASS | PASS MCP ALLOW both | PASS | PASS | PASS | PASS |
| Identity / Delegation | PASS | PASS | PASS | PASS | PASS | IDENTITY OBSERVE; MCP PDP | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| Capstone | PASS after 17B | PASS after 17B | PASS | PASS | PASS | MCP PDP; RAG/Memory OBSERVE | PASS reduced scaffold | PASS review key | PASS | PASS | PASS | PASS | PASS + Mastery next | PASS synthesis | PASS |
| Mastery Check | PASS | NOT APPLICABLE | PASS per card | PASS per card | PASS | PASS | PASS; NONE skips Search | PASS optional | PASS | NOT APPLICABLE | PASS compare cards | PASS | PASS claims | PASS | PASS LIVE vs REPLAY labels |

Common PASS meanings used above:

- Path A usable = index, sourcetype, quoted run.id, field family, Hint 1 then Hint 2.
- Path B explains output = not SPL alone; WHAT IT MEANS / DOES NOT MEAN.
- RETEST equivalence = same adversarial bytes, different server-owned configuration.
