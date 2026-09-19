# Goal integrity predecessor analysis

**Status:** Phase 13A DESIGN ONLY (recorded so Phase 13B can implement rather than invent).  
**Lab:** `LAB-AGENT-GOAL-INTEGRITY-001` / attack `GOAL-001`  
**Evidence class:** DOCUMENTATION. Runtime belongs to 13B.

Parents: `docs/AGENT_IDENTITY_SECURITY_MODEL.md`, `docs/MEMORY_SECURITY_MODEL.md`, `docs/RAG_CONTEXT_SECURITY_MODEL.md`.

---

## WHAT IS IT?

A check of whether AgentSec already models **what the agent is supposed to be doing** separately from **which tools it may call**.

## WHY DOES IT EXIST?

AgentSec already teaches:

| Existing lesson | Coverage |
|-----------------|----------|
| TOOL RESULT IS DATA | LAB-MCP-005 / INV-002 |
| RETRIEVED CONTEXT IS DATA | LAB-RAG-001 / INV-002 |
| MEMORY IS DATA | LAB-MEMORY-001 / INV-003 |
| IDENTITY CLAIM IS DATA | LAB-AGENT-DELEGATION-001 / INV-002 + INV-005 |
| DELEGATION CLAIM IS NOT A GRANT | same lab / INV-001 |

None of those freeze a **server-owned task contract**. Untrusted instructions can still look like a new objective while CTRL-MCP-001 correctly ALLOWs a granted tool.

## Classification

| Mechanism | Decision |
|-----------|----------|
| INV-002 (data cannot grant authority) | **REUSE** — untrusted instructions are data |
| INV-006 (workflow integrity) | **EXTEND in application** — task transitions must stay authorized; no new invariant id |
| INV-001 / INV-005 / CTRL-IDENTITY-001 | **NOT APPLICABLE** as the goal PDP |
| CTRL-MCP-001 | **REUSE** as the **only tool PDP** |
| CTRL-DELEGATION-001 / ambient_deputy | **DO NOT REUSE** / **DO NOT OVERLOAD** |
| INV-009 | **Do not create.** No INV-009. |
| LLM planner / prompt filter | **NOT APPLICABLE** for the security proof |
| Live A2A / OAuth / SPIFFE | **DEFER** |

## Decision locked for 13B

UNTRUSTED INSTRUCTIONS MUST NOT SILENTLY REDEFINE THE TASK.

DATA != INSTRUCTION AUTHORITY  
INSTRUCTION != TASK AUTHORITY  
GOAL INFLUENCE != GOAL AUTHORIZATION  
TASK AUTHORITY != TOOL AUTHORITY
