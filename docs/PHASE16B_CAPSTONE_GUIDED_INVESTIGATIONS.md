# Phase 16B — Guided investigations

Path A first. Path B is an answer key, not policy. Studio tokens are not fresh LIVE ids.

## CAP-I1–I16 (16B numbering)

1. Find the runs (Q-RUN-EVENTS)
2. Reconstruct sequence (Q-RUN-EVENTS)
3. Retrieved source (Q-RAG-CONTEXT-AUTHORITY)
4. Provenance and trust (Q-RAG-CONTEXT-AUTHORITY)
5. Did content persist (Q-MEMORY-CONTEXT-AUTHORITY + hash join)
6. WRITE to RECALL (Q-MEMORY-CONTEXT-AUTHORITY)
7. What recall influenced (Q-MEMORY-CONTEXT-AUTHORITY)
8. Requested privileged operation (Q-MCP-WHO)
9. Coded authority (Q-MCP-AUTHZ)
10. Which control authorized (Q-MCP-AUTHZ)
11. Did execution occur (Q-MCP-EXECUTED)
12. Is Goal Integrity required? (Q-GOAL-INTEGRITY-AUTHORITY — expect 0 rows; not required to explain)
13. Is Identity/Delegation required? (Q-AGENT-DELEGATION-AUTHORITY — expect 0 rows; not required to explain)
14. ATTACK vs RETEST (Q-MCP-AUTHZ)
15. Enforcement point (Q-MCP-AUTHZ)
16. Classify proof (Q-MCP-EXECUTED)

Official LIVE hunts (MEASURED): see `docs/PHASE16B_CAPSTONE_SPLUNK_VALIDATION.md`. Q-MEMORY must be bound with write **and** recall ids. CAP-I12/I13 returned 0 rows on the official ATTACK recall; that is instrumented absence in this packet.
