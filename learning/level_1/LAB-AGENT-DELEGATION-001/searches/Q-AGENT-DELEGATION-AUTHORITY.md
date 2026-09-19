# Q-AGENT-DELEGATION-AUTHORITY

| Item | Value |
|------|--------|
| Query ID | `Q-AGENT-DELEGATION-AUTHORITY` |
| Security question | For this run: who called whom, what authority was claimed, what privileged operation was requested, what did CTRL-MCP-001 decide, and was execution observed? |
| Validation status | **VALIDATED** (live Splunk CLI, 2026-09-18, schema 1.8.0 LAB-AGENT-DELEGATION-001 specimens) |
| Validation date | 2026-09-18 |
| SPL file | `Q-AGENT-DELEGATION-AUTHORITY.spl` |
| Lab | LAB-AGENT-DELEGATION-001 / A2A-001 |

Existing Q-MCP-WHO tables `gen_ai.agent.id` (the callee on both hops) and does not name caller vs callee. Q-MCP-AUTHZ shows CTRL-IDENTITY-001 OBSERVE plus hop-1 CTRL-MCP-001, but not `claim.trust`, `claimed_scope`, or the identity claim hash. Q-MCP-EXECUTED emits an extra OBSERVE row grouped by tool. Q-MCP-DELEGATION requires CTRL-DELEGATION-001 and returns **zero rows** on these specimens.

This hunt is the LAB-AGENT-DELEGATION-001 INV-001 reconstruction. It is **not** a detector. OBSERVE is not ALLOW. An identity string is not authentication. A claimed scope is not a grant. Splunk does not authorize tools.

Name: **Q-AGENT-DELEGATION-AUTHORITY** (not Q-MCP-DELEGATION, not Q-A2A-*). MCP-006 already owns `Q-MCP-DELEGATION` for ambient confused-deputy / CTRL-DELEGATION-001. This lab is amplification: neither agent is coded `customer:read`.

Do **not** dump `_raw`. `identity_claim_hash` is `agentsec.content.hash` on CTRL-IDENTITY-001 (canonical A2A-shaped claim). Hop-1 MCP `content.hash` is a different payload and is not the claim fingerprint.

## Required fields (indexed names)

`event.name`, `agentsec.run.id`, `agentsec.principal.id`, `agentsec.identity.caller_agent_id`, `agentsec.identity.callee_agent_id`, `agentsec.identity.claim.trust`, `agentsec.delegation.claimed_scope`, `agentsec.control.id`, `agentsec.control.decision`, `agentsec.control.reason`, `gen_ai.tool.name`, `agentsec.mcp.requested_scope`, `agentsec.mcp.allowed_scope`, `agentsec.content.hash`, `agentsec.hop.index`, `agentsec.security.profile`, `agentsec.testbed.mode`

Optional on hop-1 CTRL-MCP-001: `agentsec.mcp.resource.id` (OBSERVED on BASELINE `lending-basics`; **NOT INDEXED** on the privileged `lookup_customer_tier` control hop). The hunt surfaces that honestly as `mcp.resource.id_not_indexed_on_this_control_hop`.

There is **no** indexed `authenticated`, `verified_identity`, `trusted_identity`, `session.id`, `invocation.id`, `agentsec.mcp.allowed_tools`, `gen_ai.tool.call.id`, or `agentsec.event.name`. WHO AUTHENTICATED = **NOT PROVEN / NOT MODELED**.

## SPL

See `Q-AGENT-DELEGATION-AUTHORITY.spl`. Bind `__RUN_ID__`.

## Line-by-line explanation

1. Scope `index=agentsec_telemetry sourcetype=otel:agentic:json` and one bound `agentsec.run.id`. Include control, `mcp.started`, `mcp.completed`, and `mcp.failed`. `earliest=0` is lab validation only.
2. Collapse INDEXED_EXTRACTIONS+KV_MODE duplicate copies with `mvindex(mvdedup(…),0)`.
3. Identify `CTRL-IDENTITY-001` for principal, caller, callee, `untrusted_claim`, claimed scope, OBSERVE `identity_claim_is_not_grant`, and the claim SHA-256.
4. Identify hop `1` CTRL-MCP-001 for requested tool/scope, coded `allowed_scope`, decision, and reason.
5. Observe hop `1` `mcp.started` / `mcp.completed` / `mcp.failed` without claiming the handler definitely never ran.
6. `eventstats` by `run_id` (not `join` / `transaction` / `map` / `append`) collapses one specimen into one row.
7. `mcp_resource_observation` reports the indexed resource id when present; otherwise the documented absence on that control hop. Absence is not prevention.
8. Zero rows means this copy has no indexed CTRL-IDENTITY-001 row for that `run.id`. That is not “safe.”

## Expected result

| Specimen | Identity | Claim hash | MCP | Execution observation |
|----------|----------|------------|-----|------------------------|
| A BASELINE | OBSERVE `identity_claim_is_not_grant`; `policy:read`; caller advisor-005 → callee fulfillment-006 | BASELINE hash | ALLOW `tool_granted`; `lookup_policy` | `mcp.completed_observed` |
| B ATTACK | OBSERVE; `customer:read`; same caller/callee | ATTACK hash | ALLOW `vulnerable_profile_fail_open:caller_identity_derived_authority` | `mcp.completed_observed` |
| C RETEST | OBSERVE; **same claim hash as B** | ATTACK hash | DENY `tool_not_granted` | `no_indexed_followon_execution_event` |

ATTACK must **not** look like the identity claim authenticated or granted the tool. CTRL-IDENTITY-001 stays OBSERVE on A/B/C. Coded hop-1 `allowed_scope` stays `policy:read`. B is an **INTENTIONALLY VULNERABLE LAB PROFILE**. Overlay reason is lab vocabulary, not a production IOC.

Do **not** summarize A as SAFE / AUTHENTICATED / TRUSTED.

## Actual result

**VALIDATED** (Splunk CLI CSV). See `docs/PHASE12C_AGENT_DELEGATION_SPLUNK_VALIDATION.md`.

| Spec | identity_decision | mcp_decision | execution_observation | Notes |
|------|-------------------|--------------|------------------------|-------|
| A | OBSERVE | ALLOW `tool_granted` | `mcp.completed_observed` | resource `lending-basics`; OBSERVE is not ALLOW |
| B | OBSERVE | ALLOW overlay reason | `mcp.completed_observed` | `mcp.resource.id` not indexed on hop-1; INTENTIONALLY VULNERABLE LAB PROFILE |
| C | OBSERVE | DENY `tool_not_granted` | `no_indexed_followon_execution_event` | claim hash equals B; runtime handler count 0 is authoritative |
| Unknown UUID | *(no row)* | | | zero rows ≠ SAFE |

## Validated run.id / test data

| Spec | `run.id` |
|------|----------|
| A BASELINE | `b419465c-84d8-4639-8449-34dd99841ba9` |
| B ATTACK | `f846be88-1f9d-4dde-ac80-193c01b47660` |
| C RETEST | `271695f5-4739-44f2-8bf4-0749d04f4b03` |

ATTACK/RETEST identity claim hash (CTRL-IDENTITY-001 `agentsec.content.hash`): `sha256:56179e463b2faf18c056389ebff32a61e346dd0b4010fb82e8826c4508790dfd`.

BASELINE hash (different request): `sha256:93f1e257a7d6c7660aa8b1d1b980f1509b7da69e215b385ac79c222e1058b3eb`.

Do **not** reuse Phase 12B local-only IDs as Splunk proof.

## Performance notes

Index + sourcetype + `run.id` + event-name predicates. Commands: `eval`, `eventstats`, `where`, `dedup`, `table`. No `join`, `transaction`, `map`, or `append`. Cardinality is one `run.id` (~9–10 events). `earliest=0` is **lab validation only**. Performance is **LAB MEASURED ONLY**. Do not claim production scalability.

## Known limitations

- `identity_claim_hash` proves canonical-claim equality. First-class `agentsec.mcp.resource.id` is missing on the privileged control hop; that is PARTIALLY SUPPORTED for resource identity, not a STOP (schema optional; runtime did not emit it).
- `mcp_coded_allowed_scope` is the **server-owned coded scope on that hop**, not a per-agent grant snapshot. Splunk cannot independently prove Agent A also lacked `customer:read` (**TELEMETRY GAP** `allowed_tools`).
- OBSERVE is not authentication. Empty `authenticated` / `verified_identity` is expected.
- `no_indexed_followon_execution_event` is corroboration. Runtime handler count remains authoritative for non-execution.
- Overlay reason string is a lab teaching signal.

## No-data semantics

Zero rows means this Splunk copy has no CTRL-IDENTITY-001 event for the bound `run.id`. That is not DENY, not prevention, not SAFE, and not proof Splunk authorized anything.
