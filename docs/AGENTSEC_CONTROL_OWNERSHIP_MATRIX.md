# AgentSec control ownership matrix

**Status:** Phase 17C canonical. Schema **1.9.0**. Runtime authorization **UNCHANGED**.  
**Evidence class:** OBSERVED (source tree) + DOCUMENTED (prior measured pairs).  
**Do not start Phase 17D from this file.**

Learning metadata is not policy. Splunk is not a PDP.

| Control | Component | Role | Decision type | Enforcement or observation | Inputs | Outputs | Security authority | Labs |
|---------|-----------|------|---------------|----------------------------|--------|---------|--------------------|------|
| `coded_policy()` | `src/agentsec/mcp/policy.py` | Grant snapshot | none | Configures the grant object consumed by CTRL-MCP-001 | Server-owned allowed tools/scopes/resources | Frozen `McpPolicy` | Grant definition, not a decision | Every MCP-using lab |
| CTRL-INPUT-001 | `src/agentsec/controls.py` | Input / LLM gate | ALLOW / DENY / ERROR | **Enforcement (PDP)** before Ollama | Loan HTTP input | `control.decision` | Authoritative for whether hop-0 LLM may be invoked | LAB-PI-001 |
| CTRL-MCP-001 | `src/agentsec/mcp/authorize.py` | Tool PDP | ALLOW / DENY / ERROR | **Enforcement (sole tool PDP)** before handler | Requested tool/scope/resource + coded grant + labeled overlay | `control.decision` | Authoritative for tool authorization. Overlay is a lab label, not a rewritten grant | MCP-001/003/004/005/006/catalog, RAG, Memory, Goal, Identity, Capstone |
| CTRL-RAG-CONTEXT-001 | `src/agentsec/rag/context_trust.py` | Retrieved-context classifier | OBSERVE / ERROR | Observation | Retrieved document identity, hash, provenance | OBSERVE `retrieved_context_is_data` | **Not a PDP.** Does not ALLOW/DENY a tool | LAB-RAG-CONTEXT; capstone retrieve |
| CTRL-MEMORY-CONTEXT-001 | `src/agentsec/memory/trust.py` | Recalled-memory classifier | OBSERVE / ERROR | Observation | Recalled memory.id, hash, provenance | OBSERVE `memory_context_is_data` | **Not a PDP.** Classify at recall; write-run trust is empty | LAB-MEMORY-001; capstone recall |
| CTRL-GOAL-INTEGRITY-001 | `src/agentsec/goal/trust.py` | Task PDP | OBSERVE / DENY / ERROR | **Enforcement for task expansion**; never authorizes a tool | Server-owned task + untrusted instruction + proposed action | OBSERVE or DENY `unauthorized_task_expansion` | Authoritative for whether the proposed goal/task expansion is accepted. **Not** the tool PDP | LAB-AGENT-GOAL-INTEGRITY-001 |
| CTRL-IDENTITY-001 | `src/agentsec/identity/trust.py` | Identity-claim classifier | OBSERVE / ERROR | Observation | Principal/caller/callee/claimed scope | OBSERVE `identity_claim_is_not_grant` | **Not a PDP.** OBSERVE means the claim was recorded. Not authentication | LAB-AGENT-DELEGATION-001 |
| CTRL-MCP-RESULT-001 | `src/agentsec/mcp/result_trust.py` | Result classifier | OBSERVE | Observation | Tool result bytes | OBSERVE untrusted_data | **Not a PDP.** Follow-on still CTRL-MCP-001 | LAB-MCP-005 (REPLAY) |
| CTRL-MCP-METADATA-001 | `src/agentsec/mcp/metadata_trust.py` | Catalog-text classifier | OBSERVE | Observation | Tool description / metadata | OBSERVE | **Not a PDP** | LAB-MCP-CATALOG (REPLAY) |
| CTRL-DELEGATION-001 | `src/agentsec/mcp/delegation.py` | Deputy grant check | ALLOW / DENY | Enforcement before hop-1 MCP | Caller vs deputy ambient | ALLOW/DENY | Pre-handler deputy gate for MCP-006. Distinct from CTRL-IDENTITY-001 | LAB-MCP-006 (REPLAY) |

## Ownership rules

1. OBSERVE is not ALLOW and not DENY.
2. CTRL-MCP-001 is the only tool PDP in LIVE labs.
3. Goal DENY is not MCP DENY. Official 15D RETEST still ALLOW `lookup_policy`.
4. Identity OBSERVE is not authentication.
5. Splunk copies `control.decision`. It does not evaluate the control.
