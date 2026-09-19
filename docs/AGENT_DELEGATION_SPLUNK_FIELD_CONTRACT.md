# Agent identity / delegation Splunk field contract

**Status:** Phase 12C **VALIDATED** (live Splunk CLI, 2026-09-18).  
**Schema:** `agentsec.security_event` **1.8.0**  
**Index:** `agentsec_telemetry`  
**Sourcetype:** `otel:agentic:json`  
**Lab:** LAB-AGENT-DELEGATION-001 / A2A-001

Parents: `docs/SCHEMA_1_8_0.md`, `docs/PHASE12C_AGENT_DELEGATION_SPLUNK_VALIDATION.md`.

Do not invent aliases. If an expected 1.8.0 name is missing, that is a STOP — not a `eval` rewrite. On these specimens the identity field **names matched**.

---

## Observed indexed names

| Conceptual | Indexed name | IDENTITY-001 hop 0 | CTRL-MCP-001 hop 1 | Notes |
|------------|--------------|--------------------|--------------------|-------|
| schema | `agentsec.schema.version` | OBSERVED `1.8.0` | OBSERVED `1.8.0` | |
| run | `agentsec.run.id` | OBSERVED | OBSERVED | mvcount 3 |
| sequence | `agentsec.sequence` | OBSERVED | OBSERVED | |
| event | `event.name` | OBSERVED `agentsec.control.decision` | OBSERVED | not `agentsec.event.name` |
| service | `service.name` | OBSERVED `acmebank` | OBSERVED | |
| principal | `agentsec.principal.id` | OBSERVED `applicant-web` | OBSERVED | |
| caller | `agentsec.identity.caller_agent_id` | OBSERVED | OBSERVED | attribution, not authn |
| callee | `agentsec.identity.callee_agent_id` | OBSERVED | OBSERVED | |
| claim trust | `agentsec.identity.claim.trust` | OBSERVED `untrusted_claim` | **NOT APPLICABLE** (empty) | not emitted on hop 1 |
| claimed scope | `agentsec.delegation.claimed_scope` | OBSERVED | OBSERVED | not `allowed_scope` |
| delegator | `agentsec.delegator.agent.id` | **NOT APPLICABLE** | OBSERVED (caller) | hop ≥ 1 only |
| hop agent | `gen_ai.agent.id` | OBSERVED callee | OBSERVED callee | do not treat as caller |
| control | `agentsec.control.id` | `CTRL-IDENTITY-001` | `CTRL-MCP-001` | |
| control type | `agentsec.control.type` | `identity_claim_trust` | `mcp_allowlist` | |
| decision | `agentsec.control.decision` | `OBSERVE` | ALLOW or DENY | OBSERVE ≠ ALLOW |
| reason | `agentsec.control.reason` | `identity_claim_is_not_grant` | `tool_granted` / overlay / `tool_not_granted` | overlay is LAB-ONLY |
| tool | `gen_ai.tool.name` | OBSERVED | OBSERVED | |
| method | `mcp.method.name` | **empty** | `tools/call` | |
| requested scope | `agentsec.mcp.requested_scope` | OBSERVED | OBSERVED | |
| allowed scope | `agentsec.mcp.allowed_scope` | **empty** | OBSERVED `policy:read` | coded hop scope, not Agent A snapshot |
| resource | `agentsec.mcp.resource.id` | **empty** | OBSERVED BASELINE; **NOT INDEXED** on privileged hop | do not alias |
| attempted/executed | `agentsec.operation.attempted` / `.executed` | `"false"` | control-event `"false"`; `mcp.started` has `"true"` | |
| outcome | `agentsec.operation.outcome` | empty | `prevented` on RETEST DENY | |
| claim hash | `agentsec.content.hash` | OBSERVED canonical claim | different MCP payload hash | compare IDENTITY hash only |
| attack | `agentsec.attack.id` | `A2A-001` | `A2A-001` | |
| workflow | `gen_ai.workflow.name` | `identity_delegation_lab` | same | |
| entry | `agentsec.workflow.entry` | `/identity/delegate` | same | |
| profile / mode | `agentsec.security.profile` / `agentsec.testbed.mode` | OBSERVED | OBSERVED | |

## NOT INDEXED / NOT EXTRACTED

`authenticated`, `verified_identity`, `trusted_identity`, `cryptographic_passport_valid`, `session.id`, `invocation.id`, `agentsec.mcp.allowed_tools`, `gen_ai.tool.call.id`, `agentsec.event.name`, `delegation.id`.

WHO AUTHENTICATED = **NOT PROVEN / NOT MODELED**.

## Multivalue

Class **B** (one physical event, repeated extracted values). `dc(_raw)` equals local `events.jsonl`. Typical `mvcount` 2–3. Normalize with `mvindex(mvdedup('field'),0)`. **Do not change `props.conf`.**

## Correlation keys

`agentsec.run.id` is the specimen key. ATTACK/RETEST request equality uses CTRL-IDENTITY-001 `agentsec.content.hash` plus caller/callee/tool/claimed_scope. Do not join on `gen_ai.agent.id` alone (always callee).
