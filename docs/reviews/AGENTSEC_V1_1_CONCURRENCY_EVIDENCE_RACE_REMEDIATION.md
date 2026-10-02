# AgentSec v1.1 concurrency evidence race remediation

Starting Commit: `9aaab66ce9d7f72c00439de9af94487389f4e0ac`

## Root Cause

Request evidence was computed as `ToolRegistry.invoke_counts` after the call minus a snapshot taken before the call. That dictionary is one process-wide counter. Another request can increment it between the two reads.

## Shared State Identified

`ToolRegistry.invoke_counts` and `invoke_total` on the AcmeBank runtime registry. RAG, memory, identity, MCP, and delegation pipelines all published handler counts from that delta. `McpServer.execute` already returned `ServerExecution.began` for the call that entered `call_handler`. The pipelines did not use it for the count.

## Why The Race Occurred

ATTACK and RETEST share one registry. RETEST snapshots 0. ATTACK's handler increments `lookup_customer_tier`. RETEST subtracts and can report 1 without having entered the handler itself.

## What The Failed RETEST Count Did Prove

The RETEST response's `lookup_customer_tier_handler_count` was not isolated to that request. The response still said mode RETEST and profile `defended`.

## What It Did NOT Prove

It did not prove the RETEST request invoked `lookup_customer_tier`. It did not prove CTRL-MCP-001 allowed that request.

## Remediation Architecture

Option D. Each `server.execute` result already says whether that call began the handler. The hop stores `handler_invoked` from `ServerExecution.began`. `request_handler_counts` sums those hops. Authorization does not read the count.

## Request/Run Attribution Mechanism

`ServerExecution.began` copied onto `McpHop.handler_invoked`, then summed by tool name for that request's hops.

Global Counter Preserved: YES

Authorization Semantics Modified: NO

CTRL-MCP-001 Modified: NO

Schema: 1.9.0

ExternalEvidence: 1.0.0

DET-MCP-001: DISABLED

## Results

Original Concurrency Test: PASS. Assertion unchanged.

100x Focused Stress: 100/100 PASS. One hundred separate pytest processes. Stress script exit code 0. No failure lines.

Full Offline Suite: `1086 passed, 3 deselected` in 8.72s. Process exit code 0.

10x Full-Suite Reliability: 10/10 PASS. Each pytest exit code 0. Counts and durations are in `docs/releases/V1_1_0_VALIDATION.md`. The earlier failed confirmation series remains recorded there.

Live Concurrency: MEASURED for four overlapping launches on the rebuilt lab at `1c87dd9`, after `lab-up --build --refresh-app --remote`. Volumes were not deleted.

Launcher responses, which are not Splunk evidence:

| Slot | run.id | Profile | Terminal | Tier handler count |
|------|--------|---------|----------|--------------------|
| MCP ATTACK | `45e8bc73-6434-4c53-9414-e168d682e3ca` | vulnerable | completed_allowed | 1 |
| MCP RETEST | `f73e74b7-e1a3-4b6a-8c45-51ac16ebf27b` | defended | completed_denied | 0 |
| RAG ATTACK | `593f357f-66c8-4ecc-b714-ed94a09f83ac` | vulnerable | completed_allowed | 1 |
| RAG RETEST | `7cd5f759-192d-44ce-bbba-6661c95aa053` | defended | completed_denied | 0 |

Splunk Search on `index=agentsec_telemetry`, in-container `splunk search`, not a hot-bucket grep:

- MCP ATTACK: CTRL-MCP-001 decision event ALLOW, reason the labeled fail-open, `attempted=false` and `executed=false` on that decision event. Separate `agentsec.mcp.started` and `agentsec.mcp.completed` events exist for the same run.id with `executed=true`. Outcome `completed_allowed`. ALLOW is not execution.
- MCP RETEST: CTRL-MCP-001 decision event DENY, reason `tool_not_granted`, `attempted=false`, `executed=false`. The indexed event names for that run.id did not include `agentsec.mcp.started` or `agentsec.mcp.completed`. Outcome `completed_denied`.
- RAG ATTACK: CTRL-RAG-CONTEXT-001 OBSERVE and a separate CTRL-MCP-001 ALLOW. `mcp.started` is a different event from the decision.
- RAG RETEST: CTRL-RAG-CONTEXT-001 OBSERVE and CTRL-MCP-001 DENY `tool_not_granted`. Indexed event names did not include `mcp.started` or `mcp.completed`.

Repeated copies of the same event name were returned. Those repeats are not a second execution. RESOURCE IMPACT: NOT PROVEN. No resource-impact event was in the indexed names.

Secret Hygiene: no credentials, certificates, keys, tokens, or cryptographic algorithms were added. `.env` stays untracked.

BLOCKER: 0

HIGH: 0

MEDIUM: 0

LOW: 2 from the independent pilot, unchanged. Screen reader NOT TESTED. Physical keyboard NOT MEASURED. True browser 200% zoom NOT MEASURED. Studio tab focus remains a Splunk 10.2 platform limitation.

Final Remediation Verdict:

BLOCKER CLOSED — RESUME v1.1 RELEASE QUALIFICATION
