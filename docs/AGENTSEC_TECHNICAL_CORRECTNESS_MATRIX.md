# AgentSec technical correctness matrix

**Status:** Phase 17C. Schema **1.9.0**. After copy corrections.  
**Do not start Phase 17D from this file.**

| LAB | Material claim | Control | PDP | Authoritative execution | SPL | Expected (official / canonical) | Evidence class | Limitation | STATUS |
|-----|----------------|---------|-----|-------------------------|-----|---------------------------------|----------------|------------|--------|
| LAB-PI-001 | Untrusted input; vulnerable fail-open; defended DENY before LLM | CTRL-INPUT-001 | CTRL-INPUT-001 | Runtime LLM invoke count | Q-CONTROL-DECISION, Q-LLM-EXECUTED | ATTACK ALLOW + LLM; RETEST DENY + 0 LLM on complete copy | MEASURED 14D | One regex ≠ universal PI resistance | PASS |
| LAB-MCP-001 | REQUEST ≠ GRANT; ALLOW ≠ EXECUTION | CTRL-MCP-001 | CTRL-MCP-001 | handler_invoke_count | Q-MCP-AUTHZ, Q-MCP-EXECUTED | ATTACK ALLOW overlay + handler 1; RETEST DENY + handler 0 | MEASURED 14E | Overlay is lab label | PASS |
| LAB-RAG-CONTEXT | Retrieved content ≠ authority; OBSERVE ≠ ALLOW | CTRL-RAG-CONTEXT-001 OBSERVE; CTRL-MCP-001 | CTRL-MCP-001 | handler_invoke_count | Q-RAG-CONTEXT-AUTHORITY, Q-MCP-AUTHZ | CONTEXT OBSERVE both; MCP ALLOW vs DENY | MEASURED 15B | Exact-id fixtures; no vector DB; no DET-RAG | PASS |
| LAB-MEMORY-001 | WRITE ≠ RECALL; STORED ≠ TRUSTED | CTRL-MEMORY-CONTEXT-001 OBSERVE; CTRL-MCP-001 | CTRL-MCP-001 | handler_invoke_count on RECALL | Q-MEMORY-CONTEXT-AUTHORITY | Two ids; OBSERVE both; MCP ALLOW vs DENY | MEASURED 15C | Missing MCP ≠ independent prevention | PASS (17C REPLAY labels) |
| LAB-AGENT-GOAL-INTEGRITY-001 | AUTHORIZED TOOL ≠ AUTHORIZED GOAL | CTRL-GOAL-INTEGRITY-001; CTRL-MCP-001 | Task: GOAL. Tool: MCP | wrong-goal vs in-task handler counts | Q-GOAL-INTEGRITY-AUTHORITY, Q-MCP-AUTHZ | Goal OBSERVE vs DENY; MCP ALLOW both | MEASURED 15D | Do not say MCP blocked RETEST | PASS |
| LAB-AGENT-DELEGATION-001 | Claim ≠ authentication; claim ≠ grant | CTRL-IDENTITY-001 OBSERVE; CTRL-MCP-001 | CTRL-MCP-001 | handler_invoke_count | Q-AGENT-DELEGATION-AUTHORITY, Q-MCP-AUTHZ | IDENTITY OBSERVE both; MCP ALLOW vs DENY | MEASURED 15E | WHO AUTHENTICATED NOT MODELED | PASS |
| LAB-AGENTSEC-CAPSTONE-001 | retrieve → persist → later recall → tool PDP; not “prompt injection” | RAG OBSERVE, Memory OBSERVE, CTRL-MCP-001 | CTRL-MCP-001 | recall handler counts | Q-RAG, Q-MEMORY, Q-MCP-* | Three ids; Goal/Identity 0 rows = NOT PRESENT | MEASURED 16B | attack.id enum RAG-001; no DET-CAPSTONE | PASS (17C empty-row wording) |
| Mastery Check | Assessment answers match runtime | n/a (learning-only) | n/a | n/a | named Q-* | Incorrect claims remain incorrect | DOCUMENTED | Path B cannot be hidden; MA-PT1 Path B is a fragment | PASS (17C Path B) |
| REPLAY MCP-003–006 / catalog / scanner | Historical reconstruction | CTRL-MCP-001 ± RESULT/METADATA/DELEGATION | tool PDP still MCP | handler counts in packs | domain Q-* | REPLAY specimens | REPLAYED | No Attack Service | PASS as REPLAY |

## Path A / Path B

Path A starters use real index, sourcetype, and quoted run.id (memory pair / capstone triple where required). Hint 1 conceptual; Hint 2 stronger. Path B prose must follow query output: DENY does not become “attack prevented” without runtime execution evidence.
