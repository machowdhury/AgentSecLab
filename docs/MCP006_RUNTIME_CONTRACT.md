# MCP-006 runtime contract (LAB-MCP-006)

**Status:** Phase 7B **IMPLEMENTED + LOCALLY VALIDATED**. Not Splunk-validated. Not a workshop. Not a detector.  
**Schema:** `agentsec.security_event` **1.4.0** (additive over 1.3.0).  
**Controls:** CTRL-DELEGATION-001 (new) + CTRL-MCP-001 (reuse on hop 1).  
**Evidence class:** pytest and local bundles are **MEASURED** / **OBSERVED**. Splunk: **NOT ATTEMPTED**.

Parents: `docs/MCP006_LAB_SPECIFICATION.md`, `docs/MCP006_DELEGATION_MODEL.md`, `docs/SCHEMA_1_4_0.md`.

## WHAT IS IT?

Credit (`acme-agent-credit-002`) asks Compliance (`acme-agent-compliance-004`) to run a harmless MCP tool. Defended path spends **delegated** authority (`{lookup_policy}`). Vulnerable path substitutes Compliance’s **ambient** grant (`{lookup_policy, lookup_customer_tier}`), labeled `vulnerable_profile_fail_open:ambient_deputy_authority`.

## WHY DOES IT EXIST?

“May the deputy call this tool?” is the wrong question. The lab proves INV-001: a more-privileged deputy must not use ambient authority for a caller who was not delegated that operation.

## HOW DOES IT WORK?

```text
LAB RUNNER (not HTTP identity fields)
  coded caller = credit-002
  coded deputy = compliance-004
        │
        ▼
hop 0  CTRL-DELEGATION-001
        ALLOW delegation_granted              (tool in delegated set)
        ALLOW …:ambient_deputy_authority      (vulnerable + tool in ambient only)
        DENY  delegated_authority_not_granted (defended + not delegated)
        ERROR unknown_*/missing/malformed/control_evaluation
        │
        ▼  (ALLOW only)
frozen DelegationTicket
        │
        ▼
hop 1  McpServer(policy = delegated | ambient per ticket.authority_source)
        profile = defended  (no MCP-002 fail-open)
        CTRL-MCP-001 tool → scope → resource
        │
        ▼  (ALLOW only)
handler (AllowTicket)
```

HTTP `POST /mcp/invoke` is **not** the MCP-006 identity path. Extra JSON identity/grant fields remain `unknown_fields`. Direct `lookup_customer_tier` on that endpoint remains MCP-002 for `acme-agent-mcp-001`.

## WHERE DOES IT SIT?

`run_mcp_006_invoke` in `src/agentsec/mcp/delegation_pipeline.py`. Workflow `mcp_tool_lab` / `/mcp/invoke`. Not the LLM `/process` path. Not `acme-agent-mcp-001`.

## TRUST BOUNDARY

CTRL-DELEGATION-001 then `acmebank.mcp.authorize`. Splunk does not authorize. The LLM does not authorize.

## AUTHORITY SETS (coded constants)

| Set | Tools | Scopes |
|-----|-------|--------|
| Caller / delegated | `{lookup_policy}` | `{policy:read}` |
| Deputy ambient | `{lookup_policy, lookup_customer_tier}` | `{policy:read, customer:read}` |

`coded_policy()` for MCP-001–005 is **unchanged** `{lookup_policy}`.

Hop 1 always uses **defended** membership against the **selected per-request policy object**. Vulnerable does not disable CTRL-MCP-001.

## CHECK / USE

`DelegationTicket` is frozen. Hop 1 calls `bind_deputy_call(ticket)`. Mutating the request after ALLOW cannot change the tool/scope/deputy executed.

## TELEMETRY

Hop 0: caller agent, CTRL-DELEGATION-001, `gen_ai.tool.name` = requested tool, `authority.source` on ALLOW/DENY.  
Hop 1 (ALLOW only): deputy agent, `delegator.agent.id` = credit-002, CTRL-MCP-001, maybe `mcp.started`.  
No `gen_ai.tool.call.id`. Grant lists still not a first-class event field.

## NON-GOALS

SPL, DET-MCP-006, Dashboard Studio, Phase 7C, Cisco, network A2A, LLM authorization.
