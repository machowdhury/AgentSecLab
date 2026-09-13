# MCP Runtime Contract (LAB-MCP-001)

**Status:** Phase 3B **IMPLEMENTED** (deterministic runtime + tests). Splunk SPL and Dashboard Studio are **not** in this phase.  
**Schema:** `agentsec.security_event` **1.1.0** (additive over 1.0.0).  
**Evidence class:** pytest is MEASURED. Live Splunk is NOT ATTEMPTED.

---

## WHAT IS IT?

A **dedicated MCP agent** (`acme-agent-mcp-001`) sends a JSON-RPC 2.0 **`tools/call`** to an in-process MCP **server**. The server evaluates **CTRL-MCP-001** (allow-list) **before** any tool handler begins.

Two harmless tools exist:

| Tool | Registered | Granted to mcp_policy_agent | Scope |
|------|------------|-----------------------------|--------|
| `lookup_policy` | yes | **yes** | `policy:read` |
| `lookup_customer_tier` | yes | **no** | `customer:read` |

Unknown names are **not** registered. There is no shell tool.

## WHY DOES IT EXIST?

LAB-PI-001 taught DENY **before LLM**. LAB-MCP-001 teaches DENY **before tool execution**, without pretending a prompt regex is MCP.

## HOW DOES IT WORK?

```text
POST /mcp/invoke  {tool, arguments, requested_scope, user_id?}
        │  extra JSON → ERROR (no handler)
        ▼
MCP client encodes JSON-RPC tools/call
        ▼
MCP server (authoritative)
  1. coded identity + policy (never from JSON)
  2. tool in registry? else ERROR
  3. argument schema? else ERROR
  4. CTRL-MCP-001 ALLOW / DENY / ERROR
  5. ONLY ON ALLOW: mint ticket → handler begins
        ▼
tool result is DATA (untrusted_data)
```

Transport is **in-process**. Messages are real MCP-shaped JSON-RPC `tools/call`. This is **not** stdio or Streamable HTTP, and there is no `initialize` handshake.

## WHERE DOES IT SIT?

`POST /mcp/invoke` on AcmeBank. **Not** wired through the four loan agents. `POST /process` is unchanged except every event now carries schema **1.1.0**.

## TRUST BOUNDARY

Server-side authorization is authoritative. The client only encodes RPC. HTTP cannot set `agent.id`, `allowed_scope`, `security.profile`, or `control.decision`.

## PROFILE SEMANTICS

| Case | defended | vulnerable |
|------|----------|------------|
| `lookup_policy` + `policy:read` | ALLOW, handler runs | ALLOW, handler runs |
| `lookup_customer_tier` (known, not granted) | **DENY**, handler does not begin | **ALLOW** with `vulnerable_profile_fail_open:CTRL-MCP-001…`, handler runs |
| unknown tool | **ERROR**, no handler | **ERROR**, no handler |
| malformed args / extra HTTP fields | **ERROR**, no handler | **ERROR**, no handler |
| control evaluation exception | **ERROR**, no handler | **ERROR**, no handler |
| handler exception after ALLOW | `mcp.started` + `mcp.failed`, `executed=true`, **not** prevention | same |

## GOVERNED OPERATION

**MCP tool handler invocation.** `operation.executed=true` on `mcp.*` means the handler **began**.

DENY / pre-invoke ERROR: `attempted=false`, `executed=false`, `outcome=prevented`, **no** `mcp.started`.

## RESULT TRUST

`agentsec.mcp.result.trust=untrusted_data`. Results do not modify `allowed_tools`. MCP-005 is not implemented.

## TESTS THAT PROVE IT

Spy `ToolRegistry.invoke_counts`. DENY/ERROR keep the count at zero. See `tests/security/test_mcp_control_before_handler.py`.
