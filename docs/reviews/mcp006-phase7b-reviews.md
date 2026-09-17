# Phase 7B reviews — MCP-006 runtime

**Date:** 2026-09-14  
**Pytest:** 344 passed, 2 deselected (MEASURED).  
**Skills:** architecture-review, logic-proof. Adversarial AppSec / IAM / agent-security.

## Architecture

Problem: delegated vs ambient authority on a two-agent MCP invoke.  
Components: `delegation.py`, `delegation_pipeline.py`, schema 1.4.0, existing McpServer/CTRL-MCP-001.  
Simplest: no new HTTP API, no IAM, no A2A network, hop 0/1 reuse.  
Uncertain: Splunk 1.4.0 indexing (out of 7B).

## Logic proof

Authorization before execution: MEASURED (RETEST 0 `mcp.started`).  
Ambient cannot leak into defended: MEASURED (DENY).  
Identity server-owned: MEASURED (HTTP extra fields rejected; coded ids).  
Client grants fail: MEASURED.  
Cross-run isolated: MEASURED.  
ATTACK/RETEST same request: MEASURED.  
Error fail-safe: MEASURED.  
Handler counts: MEASURED.  
MCP-001 still active: MEASURED (`tool_granted` / `scope_not_granted` on hop 1).

Could missing context become ALLOW? No.  
Could telemetry report DENY after execute? No.

## Security review

### BLOCKER
None remaining. Identity-on-ERROR hops now emit the evaluated caller id (unknown-999), not a hardcoded credit label.

### HIGH
None remaining.

### MEDIUM
| Id | Finding | Disposition |
|----|---------|-------------|
| M1 | Same tool as MCP-005 follow-on | Accepted teaching contrast |
| M2 | Grant lists still not indexed | Honest; runtime/manifest |
| M3 | No `gen_ai.tool.call.id` | Documented |
| M4 | MCP-006 is a dedicated runner, not HTTP auto-select | Intentional so MCP-002/005 stay intact |

### LOW
| Id | Finding | Disposition |
|----|---------|-------------|
| L1 | Hop 0 `gen_ai.tool.name` is request not execution | Documented |
| L2 | Trust boundary reused `acmebank.mcp.authorize` | Smaller schema |

## Fixes applied in 7B

- Schema 1.4.0 minimum bump
- Hop 1 always defended membership against selected policy (not MCP-002 fail-open)
- Frozen DelegationTicket + bind_deputy_call
- Grant snapshot runtime abort if mutated
- ERROR hops attribute the evaluated caller, not always credit-002
