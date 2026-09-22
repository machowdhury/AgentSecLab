# Phase 15C — Memory guided investigations

Metadata: `learning/level_1/LAB-MEMORY-001/investigations.json`  
Schema: `agentsec.guided_investigation.v1`  
`not_authorization: true`. Not a detector. Not policy.

Studio = syllabus. Splunk Search = notebook.

## Path A

Security question, investigation objective, write/recall `run.id`, index/sourcetype guidance, Hint 1, Hint 2, Open Splunk Search. The learner writes the SPL.

## Path B

Exact existing hunt SPL, copyable query, expected result shape, field teaching, what it means, what it does **not** mean, related control/invariant.

## Sequence

MEMORY-I1 HUNT Q-MEMORY-CONTEXT-AUTHORITY — Find the write. Persistence ≠ trust.

MEMORY-I2 HUNT Q-MEMORY-CONTEXT-AUTHORITY — Find the later recall. source_run_id ≠ recall run.id.

MEMORY-I3 HUNT Q-MEMORY-CONTEXT-AUTHORITY — Fingerprint equality. Preview is not the hash.

MEMORY-I4 HUNT Q-MEMORY-CONTEXT-AUTHORITY — OBSERVE memory_context_is_data. STORED != TRUSTED. OBSERVE != ALLOW.

MEMORY-I5 HUNT Q-MEMORY-CONTEXT-AUTHORITY — Influence: recall → lookup_customer_tier. MEMORY INFLUENCE != AUTHORITY.

MEMORY-I6 HUNT Q-MCP-AUTHZ — Who authorized. CONTEXT-001 and the memory record did not grant the tool.

MEMORY-I7 HUNT Q-MCP-EXECUTED — ALLOW != EXECUTION. Handler count is authoritative.

MEMORY-I8 COMPARE Q-MEMORY-CONTEXT-AUTHORITY — SAME MEMORY. SAME REQUEST. DIFFERENT AUTHORIZATION. DIFFERENT EXECUTION.

MEMORY-I9 PROVE Q-MEMORY-CONTEXT-AUTHORITY — SUPPORTED / CORROBORATED / NOT PROVEN / INCORRECT.

No new Q-MEMORY-* files. No DET-MEMORY. Overlay reason is a lab artifact, not a production IOC. AGENT MEMORY NOTE regex is not a production IOC.
