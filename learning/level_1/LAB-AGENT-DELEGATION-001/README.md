# LAB-AGENT-DELEGATION-001 Agent identity / delegation investigation

**Level:** 1  
**Difficulty:** GUIDED  
**Schema:** `agentsec.security_event` 1.9.0  
**Invariant:** INV-001 (delegated authorization), INV-002 (data cannot independently authorize), INV-005 (agent identity integrity)  
**Attack:** A2A-001 (privileged delegation claim for a tool neither agent is granted)  
**Control:** CTRL-IDENTITY-001 (OBSERVE only) + CTRL-MCP-001 (sole tool PDP)  
**Status:** Phase 15E LIVE purple-team loop. Studio `ws_lab_agent_delegation` is REPLAY syllabus. Fresh LIVE run.ids come from Attack Service. DET-MCP-001 reused, disabled. **No DET-A2A.** Detection: **DETECTION ANALYZED — NO NEW DETECTOR**.

This lab teaches one idea: **a caller/delegation claim is data. It does not mint authority.**

IDENTITY CLAIM != AUTHENTICATION  
DELEGATION CLAIM != AUTHORIZATION  
CALLER ID != GRANT  
AGENT ID STRING != CRYPTOGRAPHIC IDENTITY  
A + B != NEW AUTHORITY  
OBSERVE != ALLOW  
REQUEST != GRANT  
ALLOW != EXECUTION  
SPLUNK != ENFORCEMENT

WHO AUTHENTICATED = NOT PROVEN / NOT MODELED.

## Learner objectives

After this lab you should be able to:

1. Identify principal `applicant-web`, caller `acme-agent-advisor-005`, callee `acme-agent-fulfillment-006`.
2. Explain why those identifiers are attribution, not cryptographic authentication.
3. Identify the privileged delegation claim (`customer:read` / `lookup_customer_tier` / `cust-001`).
4. Explain why the claim is not a grant.
5. Observe CTRL-IDENTITY-001 `OBSERVE` `identity_claim_is_not_grant` on ATTACK and RETEST.
6. Prove ATTACK overlay fail-open at CTRL-MCP-001 with `lookup_customer_tier` handler 1.
7. Prove RETEST CTRL-MCP-001 `DENY` `tool_not_granted` with handler 0.
8. Measure that ATTACK and RETEST share the same request fingerprint.
9. State what Splunk can corroborate and what it cannot prove.
10. Explain why DET-MCP-001 silence is not SAFE, and why DET-A2A was not created.

## Prerequisite knowledge

- LAB-PI-001
- LAB-MCP-001 (`ws_lab_mcp_001`) — ALLOW ≠ execution
- Phase 12B runtime (`docs/PHASE12B_AGENT_DELEGATION_RUNTIME_VALIDATION.md`)
- Phase 12C Splunk (`docs/PHASE12C_AGENT_DELEGATION_SPLUNK_VALIDATION.md`)

Not required: OAuth, OIDC, JWT validation, SPIFFE/SPIRE, real A2A transport, ML.

## Lab architecture

```text
PRINCIPAL
 → CALLER
 → CALLEE
 → DELEGATION CLAIM
 → CTRL-IDENTITY-001 (OBSERVE)
 → REQUESTED TOOL / SCOPE / RESOURCE
 → CTRL-MCP-001 (tool PDP)
 → HANDLER / EXECUTION
 → OTel
 → Splunk (observe only)
```

Coded grants for both agents: `lookup_policy` / `policy:read` / `lending-basics` only.

## Canonical REPLAY specimens (Phase 12C)

These Investigate specimen ids are **REPLAY**. Fresh LIVE run.ids come from Attack Service.

- BASELINE `b419465c-84d8-4639-8449-34dd99841ba9` — defended, IDENTITY OBSERVE, MCP ALLOW tool_granted, lookup_policy 1, lookup_customer_tier 0. Not SAFE.
- ATTACK `f846be88-1f9d-4dde-ac80-193c01b47660` — **INTENTIONALLY VULNERABLE LAB PROFILE**, IDENTITY OBSERVE, overlay, MCP ALLOW, lookup_customer_tier 1
- RETEST `271695f5-4739-44f2-8bf4-0749d04f4b03` — defended, IDENTITY OBSERVE, MCP DENY tool_not_granted, lookup_customer_tier 0

Privileged request fingerprint: `sha256:56179e463b2faf18c056389ebff32a61e346dd0b4010fb82e8826c4508790dfd`

## How to run the workshop

Open Splunk → AgentSec → **Agent Identity / Delegation**. Tabs match LEARN → PROVE.

Launch LIVE ATTACK / RETEST from Attack Service `http://127.0.0.1:5001/labs/LAB-AGENT-DELEGATION-001`. Copy the fresh run.id into Splunk Search. Studio tables stay on 12C REPLAY.

Rebuild: `python3 scripts/build_lab_agent_delegation_dashboard.py`

No DET-A2A. Phase 15E LIVE loop. Do not implement real A2A, OAuth, OIDC, SPIFFE, or a schema bump.
