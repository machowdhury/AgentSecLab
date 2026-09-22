# AgentSec security reasoning assessment

**Status:** IMPLEMENTED (Phase 17A). Reasoning, not trivia.

## Recurring model

SOURCE → TRUST BOUNDARY → INFLUENCE / REQUEST → AUTHORITY DECISION → EXECUTION → TELEMETRY → INVESTIGATION → CLAIM

Each domain has different evidence and controls. Do not collapse every lab into prompt injection.

## Domain differences the learner must keep

- **Prompt / input** — HTTP trust boundary; CTRL-INPUT-001 is the input PDP before generate.
- **Tool authorization** — CTRL-MCP-001 is the sole tool PDP. REQUEST != GRANT.
- **RAG** — retrieved content is data. Provenance != trust. CTRL-RAG-CONTEXT-001 OBSERVE. MCP still decides the tool.
- **Memory** — stored != trusted. Write run != recall run. CTRL-MEMORY-CONTEXT-001 OBSERVE.
- **Goal** — AUTHORIZED TOOL != AUTHORIZED GOAL. MCP ALLOW on RETEST is expected. Goal DENY is the lesson.
- **Identity** — IDENTITY CLAIM != AUTHENTICATION. OBSERVE is not ALLOW. WHO AUTHENTICATED = NOT PROVEN / NOT MODELED.
- **Capstone** — retrieve → persist → later recall → MCP. Goal/Identity 0 rows != those domains never fail.

## Attack / defense ownership

For each selected experiment the learner names:

- **ATTACKER CONTROLLED** — fixture / payload bytes the closed launcher sends.
- **SERVER OWNED** — profile, grants, tools, scopes, policy, ExperimentContext.
- **OBSERVABILITY ONLY** — Splunk. Changing a search does not change enforcement.

## Evidence quality

| Kind | Example | Alone? |
|------|---------|--------|
| Authoritative execution | runtime handler / LLM invoke count where the lab defines it | Yes for execution in that lab |
| Authorization | CTRL-MCP-001 / CTRL-INPUT-001 decision | Authorization only |
| Corroborative execution | indexed `mcp.started` / `llm.started` on a complete copy | No |
| Corroborative non-execution | missing `mcp.started` on a complete copy vs local `events.jsonl` | No |
| Not sufficient | empty dashboard, HEC 200, pytest, detector silence | No |

## Indefensible sentences (must be rewritten)

- “Splunk blocked the attack.”
- “The agent was authenticated.”
- “The RAG document was trusted.”
- “The memory was safe.”
- “MCP ALLOW means the goal was approved.”
- “No event means it did not execute.”
- “The RETEST proves prompt injection is solved.”
