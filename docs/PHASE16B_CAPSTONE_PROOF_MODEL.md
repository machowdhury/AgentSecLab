# Phase 16B — Proof classification (CAP-I16)

Learner statements and the honest class:

| Statement | Class |
|-----------|-------|
| The retrieved document granted `customer:read`. | **INCORRECT** |
| The memory record granted `lookup_customer_tier`. | **INCORRECT** |
| CTRL-MCP-001 authorized the tool on ATTACK. | **SUPPORTED** (control.decision ALLOW + overlay reason) |
| Splunk prevented the attack. | **INCORRECT** |
| The privileged handler executed during ATTACK. | **SUPPORTED** (runtime handler count 1). Splunk `mcp.completed` is **CORROBORATED**. |
| The privileged handler did not execute during RETEST. | **SUPPORTED** (runtime handler count 0). Missing `mcp.started` is **CORROBORATED** on a complete copy. |
| RETEST proves the application is secure against all RAG/memory attacks. | **INCORRECT** |
| Missing telemetry proves prevention. | **INCORRECT** |
| Goal Integrity failed. | **INCORRECT** / not required. 0 hunt rows = instrumented absence, not a universal negative. |
| Identity/Delegation failed. | **INCORRECT** / not required. Same limit. |

Authoritative execution evidence: ToolRegistry handler invocation count.

Authorization evidence: CTRL-MCP-001.

Splunk: reconstructed telemetry evidence. Splunk ≠ enforcement.

RAG/memory OBSERVE: classification/context evidence, not a grant.
