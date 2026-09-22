# Phase 15B — RAG guided investigations

Metadata: `learning/level_1/LAB-RAG-CONTEXT/investigations.json`  
Schema: `agentsec.guided_investigation.v1`  
`not_authorization: true`. Not a detector. Not policy.

Studio = syllabus. Splunk Search = notebook.

## Path A

Security question, investigation objective, `run.id`, index/sourcetype guidance, Hint 1, Hint 2, Open Splunk Search. The learner writes the SPL.

## Path B

Exact existing hunt SPL, copyable query, expected result shape, field teaching, what it means, what it does **not** mean, related control/invariant.

## Sequence

| Id | Tab | Hunt | Teaches |
|----|-----|------|---------|
| RAG-I1 | HUNT | Q-RAG-CONTEXT-AUTHORITY | Find retrieve evidence. Retrieval ≠ authorization. |
| RAG-I2 | HUNT | Q-RAG-CONTEXT-AUTHORITY | `untrusted_data`, OBSERVE, `retrieved_context_is_data`. OBSERVE != ALLOW. |
| RAG-I3 | HUNT | Q-RAG-CONTEXT-AUTHORITY | Influence: retrieve → `lookup_customer_tier` / `customer:read`. INFLUENCE != AUTHORITY. |
| RAG-I4 | HUNT | Q-MCP-AUTHZ | Who authorized: hop-1 CTRL-MCP-001. CONTEXT-001 did not grant the tool. |
| RAG-I5 | HUNT | Q-MCP-EXECUTED | ALLOW != EXECUTION. Handler count is authoritative. |
| RAG-I6 | COMPARE | Q-RAG-CONTEXT-AUTHORITY | Same content.hash (not hop-1 request hash). Same request. Different authorization. |
| RAG-I7 | PROVE | Q-RAG-CONTEXT-AUTHORITY | SUPPORTED / CORROBORATED / NOT PROVEN / INCORRECT. |

No new Q-RAG-* files. No DET-RAG. Overlay reason is a lab artifact, not a production IOC. AGENT NOTE regex is not a production IOC.
