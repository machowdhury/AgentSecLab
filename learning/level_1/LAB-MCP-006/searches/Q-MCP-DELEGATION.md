# Q-MCP-DELEGATION

| Item | Value |
|------|--------|
| Query ID | `Q-MCP-DELEGATION` |
| Security question | What did CTRL-DELEGATION-001 decide, for which caller/deputy/tool, which authority source was used, and what downstream MCP decision and execution were indexed? |
| Validation status | **VALIDATED** (live Splunk CLI, 2026-09-14, schema 1.4.0 MCP-006 specimens) |
| Validation date | 2026-09-14 |
| SPL file | `Q-MCP-DELEGATION.spl` |
| Lab | LAB-MCP-006 |

Existing Q-MCP-WHO / Q-MCP-AUTHZ show hop-0 and hop-1 control rows but do not label caller vs deputy, do not isolate CTRL-DELEGATION-001 from CTRL-MCP-001, and do not table `agentsec.delegation.authority.source`. Q-MCP-EXECUTED answers whether `mcp.started` was indexed for a tool; it does not reconstruct the delegation decision.

This hunt is the MCP-006 INV-001 reconstruction. It is **not** a detector. Splunk does not authorize the deputy.

## Required fields (indexed names)

`event.name`, `agentsec.run.id`, `gen_ai.tool.name`, `gen_ai.agent.id`, `agentsec.principal.id`, `agentsec.delegator.agent.id`, `agentsec.control.id`, `agentsec.control.decision`, `agentsec.control.reason`, `agentsec.delegation.authority.source`, `agentsec.mcp.requested_scope`, `agentsec.mcp.allowed_scope`, `agentsec.mcp.resource.id`, `agentsec.hop.index`, `agentsec.security.profile`, `agentsec.testbed.mode`

There is **no** indexed `agentsec.mcp.allowed_tools`, `agentsec.deputy.agent.id`, or `gen_ai.tool.call.id`. Hop-0 `allowed_scope` is the coded **delegated scope wire** (`policy:read`), not a tool grant list.

## SPL

See `Q-MCP-DELEGATION.spl`. Bind `__RUN_ID__`.

## Line-by-line explanation

1. Scope `index=agentsec_telemetry sourcetype=otel:agentic:json` and one `agentsec.run.id`. Include control, `mcp.started`, `mcp.completed`, and `mcp.failed`.
2. Collapse INDEXED_EXTRACTIONS+KV_MODE duplicate copies with `mvindex(mvdedup(…),0)`.
3. Identify hop-0 `CTRL-DELEGATION-001` as caller, requested tool/scope/resource, delegation decision/reason, and `delegation.authority.source`.
4. Identify hop-1 `CTRL-MCP-001` as deputy (`gen_ai.agent.id`) and delegator (`agentsec.delegator.agent.id`) when that hop exists.
5. Observe hop-1 `mcp.started` / `mcp.completed` / `mcp.failed` without claiming the handler never ran.
6. `deputy_observation=deputy_not_on_indexed_hop1` when hop 1 was never indexed (RETEST DENY). Do **not** parse `content.preview` for deputy.
7. `mcp_decision_observation=no_downstream_mcp_control_event` when CTRL-MCP-001 is absent.
8. `execution_observation=no_indexed_mcp_execution_event` is Splunk corroboration only.
9. Keep one row per `run.id`. Runs without CTRL-DELEGATION-001 return **zero rows**.

## Expected result

| Specimen | authority source | CTRL-DELEGATION-001 | downstream MCP | execution observation |
|----------|------------------|---------------------|----------------|------------------------|
| A BASELINE | `delegated` | ALLOW `delegation_granted` | ALLOW `tool_granted` | `mcp.completed_observed` |
| B ATTACK | `ambient_deputy` | ALLOW `vulnerable_profile_fail_open:ambient_deputy_authority` | ALLOW `tool_granted` | `mcp.completed_observed` |
| C RETEST | `delegated` | DENY `delegated_authority_not_granted` | `no_downstream_mcp_control_event` | `no_indexed_mcp_execution_event` |

ATTACK must **not** look like the caller was delegated `lookup_customer_tier`. Coded hop-0 `allowed_scope` stays `policy:read`. `authority.source=ambient_deputy` is the structured source used by the decision, not proof of the ambient grant set membership. Execution on ATTACK is not proof the caller was authorized.

## Actual result

**VALIDATED** (Splunk CLI CSV). See `docs/MCP006_SPLUNK_VALIDATION.md`.

| Spec | authority source | Notes |
|------|------------------|-------|
| A | `delegated` | caller `acme-agent-credit-002`; deputy `acme-agent-compliance-004`; MCP ALLOW; `mcp.completed_observed` |
| B | `ambient_deputy` | same caller; deputy on hop 1; MCP ALLOW `tool_granted`; coded hop-0 scope still `policy:read`; `mcp.completed_observed` |
| C | `delegated` | same request as B; DENY `delegated_authority_not_granted`; `deputy_not_on_indexed_hop1`; `no_indexed_mcp_execution_event` |

## Validated run.id / test data

A `1cf98c4d-1bd8-4df5-be70-b82419e2c2b2`, B `d7524a4e-8da6-4171-8867-d2a2168128ac`, C `50f7ec04-7524-41c0-95a8-3b1ef4d91dc4`.

## Performance notes

Index + sourcetype + run.id + four event names + `eventstats` by `run_id` + `dedup`. No `join`, `transaction`, `map`, `append`, or subsearch. `earliest=0` is lab-only.

## Known limitations

- No first-class `allowed_tools` field. Delegated **tools** remain runtime/manifest. Hop-0 preview may contain `delegated_tools` but is bounded at 200 characters and is **not** used by this hunt.
- `coded_delegated_scope` is coded **scope** (`policy:read`), not the tool allow-list.
- Deputy identity is first-class only on hop 1 (`gen_ai.agent.id` + `agentsec.delegator.agent.id`). RETEST has no hop 1; `deputy_not_on_indexed_hop1` is not a missing-identity incident by itself. Runtime `request.json` / `manifest.json` remain authoritative for the DENY-path deputy.
- `delegation_authority_source` is what the control **consulted**. It is not an indexed snapshot of ambient grant membership.
- `vulnerable_profile_fail_open:ambient_deputy_authority` is a stable lab reason string. Prefer the structured `authority.source` field over parsing reason text.
- Zero rows means this copy has no CTRL-DELEGATION-001 for that `run.id`. That is not “safe,” not DENY, and not proof the handler never ran.
- `execution_observation=no_indexed_mcp_execution_event` is Splunk corroboration. Authoritative non-execution remains the runtime handler count.

## No-data semantics

Zero rows: no indexed `CTRL-DELEGATION-001` for this `run.id` (wrong id, export loss, or a run that is not MCP-006). That is **not** blocked, **not** “no confused deputy,” and **not** proof delegated authority was refused.

Do not write “handler definitely never ran” from Splunk alone.
