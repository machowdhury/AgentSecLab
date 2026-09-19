# MCP-003 runtime contract (LAB-MCP-003)

**Status:** Phase 4B **IMPLEMENTED + LOCALLY VALIDATED**. Not Splunk-validated. Not a workshop. Not a new detection.  
**Schema:** `agentsec.security_event` **1.1.0** (version not bumped). `agentsec.attack.id` enum **additively** includes `MCP-003`.  
**Control:** CTRL-MCP-001 (extended). No CTRL-MCP-003.  
**Evidence class:** pytest and local bundles are **MEASURED** / **OBSERVED**. Splunk: **NOT ATTEMPTED**.

Parents: `docs/MCP003_LAB_SPECIFICATION.md`, `docs/MCP003_SCOPE_MODEL.md`.

---

## WHAT IS IT?

A granted MCP tool (`lookup_policy`) is still unauthorized when `requested_scope` is a **catalog-valid** token the agent was never granted (`policy:restricted:read`).

LAB-MCP-001 answers: may this agent call this **tool**?  
LAB-MCP-003 answers: may this agent call this tool **at this scope**?

## WHY DOES IT EXIST?

Tool allow-lists are easy to over-read. Scope is a second authorization question. The handler is still a harmless fixture. This is not RCE.

## HOW DOES IT WORK?

```text
POST /mcp/invoke  {tool, arguments, requested_scope, user_id?}
        │  extra JSON → ERROR unknown_fields (no handler)
        ▼
1. tool exists                  else ERROR unknown_tool
2. tool granted                 else DENY tool_not_granted
                                (vulnerable: MCP-002 fail-open)
3. requested_scope type/shape   else ERROR missing_requested_scope
4. requested_scope ∈ valid_scopes
                                else ERROR unknown_scope
5. requested_scope ∈ allowed_scopes
                                else DENY scope_not_granted
                                (vulnerable: MCP-003 fail-open)
6. arguments validate           else ERROR malformed_arguments
7. ALLOW
8. handler begins (ticket only after 1–7)
```

Matching is **exact set membership**. No strip, lowercase, prefix, regex, or wildcard. Colon tokens are opaque labels.

## WHERE DOES IT SIT?

Same `POST /mcp/invoke` path as LAB-MCP-001. Same agent `acme-agent-mcp-001`. Same CTRL-MCP-001. LAB-MCP-001 specimens (`lookup_policy`+`policy:read`, `lookup_customer_tier` ungranted) are unchanged.

## TRUST BOUNDARY

`acmebank.mcp.authorize` before `mcp.tool.execute`. Authorize reads **only** the request `requested_scope` field plus coded policy and `ToolSpec.valid_scopes`. Tool arguments are data. HTTP cannot set `allowed_scope` or `security.profile`.

## SCOPE MODEL

| Role | Tokens |
|------|--------|
| `lookup_policy` `valid_scopes` | `{policy:read, policy:restricted:read}` |
| Agent grant `allowed_scopes` | `{policy:read}` |
| `lookup_customer_tier` `valid_scopes` | `{customer:read}` (still **not** granted) |

`required_scope` remains the primary documented token and **must** be a member of `valid_scopes`.

## UNKNOWN_SCOPE

A syntactically present string that is **not** in `ToolSpec.valid_scopes` is:

- decision **ERROR**
- reason **`unknown_scope`**
- `attempted=false`, `executed=false`, `outcome=prevented`
- handler count **0**
- **no** `mcp.started`

This includes: `policy:write`, `Policy:read`, `policy:read ` (trailing space), ` policy:read`, `policy:*`, `*`, `policy`, and the comma-list `policy:read,policy:restricted:read`.

Missing / whitespace-only / non-string `requested_scope` remains **ERROR** `missing_requested_scope` at the HTTP/server gate (before catalog membership).

DENY is reserved for a **known** catalog token that is not in the agent grant.

## VULNERABLE vs DEFENDED

| Condition | defended | vulnerable |
|-----------|----------|------------|
| Granted tool + `policy:read` | ALLOW `tool_granted` | ALLOW `tool_granted` |
| Granted tool + `policy:restricted:read` | **DENY** `scope_not_granted` | **ALLOW** `vulnerable_profile_fail_open:scope_not_granted` |
| Known ungranted tool | DENY `tool_not_granted` | ALLOW MCP-002 fail-open (`allowed_tools` in reason) |
| Unknown scope token | ERROR `unknown_scope` | ERROR `unknown_scope` (no fail-open) |

MCP-002 and MCP-003 fail-open **reasons differ**. Fail-open does **not** rewrite `allowed_scope` (stays `policy:read`).

## ARGUMENT-TRUST BOUNDARY

These do **not** grant `policy:restricted:read`:

- `arguments.scope` / `arguments.allowed_scope` / `arguments.role` / `arguments.authorization`
- extra JSON `allowed_scope`
- extra JSON `security.profile`

Extra keys on `arguments` for `lookup_policy` are **ERROR** `malformed_arguments` after a successful tool+scope decision would otherwise ALLOW `policy:read`. Missing top-level `requested_scope` is **ERROR** `missing_requested_scope` even if arguments contain a scope key.

## TESTS THAT PROVE IT

`tests/security/test_mcp_scope_escalation.py`, `tests/unit/test_mcp_authorize.py`, `tests/integration/test_mcp_003_api.py`, `tests/telemetry/test_mcp_003_events.py`. Authoritative non-execution: `ToolRegistry.invoke_counts`.
