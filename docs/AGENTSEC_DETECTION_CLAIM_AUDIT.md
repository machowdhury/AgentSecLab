# AgentSec detection claim audit

**Status:** Phase 17C. Schema **1.9.0**. **NO NEW DETECTOR.**  
**Do not start Phase 17D from this file.**

## Inventory

| ID | Packaged? | Saved search | disabled | What it detects | What it does not detect |
|----|-----------|--------------|----------|-----------------|-------------------------|
| DET-MCP-001 | YES | `AgentSec - MCP Execution After Authorization Deny` | **Yes** (`disabled=1`) | Same `run.id` + `gen_ai.tool.name`: CTRL-MCP-001 DENY then later `event.name=agentsec.mcp.started` with `sequence > deny_sequence` | DENY alone; ALLOW; fail-open ALLOW; `mcp.failed` after ALLOW; ERROR; zero MCP rows; Goal DENY with a different tool name on start; RAG/memory/identity/goal “compromise” |
| DET-MCP-001-POSITIVE-CONTROL | SIMULATED fixture | none | n/a | makeresults teaching row | Not indexed evidence |
| DET-MCP-001-SCOPE-POSITIVE-CONTROL | SIMULATED | none | n/a | Same invariant, `scope_not_granted` | Not DET-MCP-003 |
| DET-MCP-001-RESOURCE-POSITIVE-CONTROL | SIMULATED | none | n/a | Same invariant, resource context | Not DET-MCP-004 |
| DET-RAG / DET-MEMORY / DET-GOAL / DET-A2A / DET-CAPSTONE / DET-MCP-003–006 / DET-MCP-CATALOG / DET-SCANNER-* | **NOT CREATED** | none | n/a | n/a | Named in copy only to reject them |

Hunt twin of DET-MCP-001: `Q-MCP-AFTER-DENY` (adds completed/failed; has `__RUN_ID__`).

## DET-MCP-001: what 0 rows means

On validated LIVE/REPLAY BASELINE / ATTACK / RETEST the expected result is **0 / 0 / 0**.

0 rows may mean: **the DENY-then-start invariant was not violated by indexed evidence for that run.id and tool.**

0 rows must **not** automatically mean: SAFE, ATTACK BLOCKED, NO EXECUTION, NO COMPROMISE, CONTROL EFFECTIVE.

Preferred ATTACK paths are usually ALLOW (fail-open or overlay). Silence on ATTACK is **correct** for this detector and is not “no attack.”

RETEST that DENYs without `mcp.started` is also silent. That silence is not independent proof of prevention.

Goal RETEST: Goal DENY uses a different `gen_ai.tool.name` than hop-1 `lookup_policy` start → still 0. Do not teach DET-MCP-001 as a goal detector.

## Academy copy

Labs that say **DETECTION ANALYZED — NO NEW DETECTOR** are correct. Phase 17C did not publish a detector. Saved search count remains one AgentSec detector stanza.
