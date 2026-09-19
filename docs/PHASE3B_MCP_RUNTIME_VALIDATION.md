# Phase 3B MCP runtime validation

**Phase:** 3B LAB-MCP-001 runtime  
**Schema:** `agentsec.security_event` **1.1.0**  
**Date:** 2026-09-11  
**Pytest:** **104 passed**, 2 deselected (`live_ollama`, `live_splunk`) — this session, `.venv/bin/python -m pytest tests -m "not live_ollama and not live_splunk"`  
**Evidence class:** MEASURED (pytest). Splunk: NOT ATTEMPTED.

Do not treat this file as Splunk or Dashboard proof.

---

## MCP implementation

Dedicated agent `acme-agent-mcp-001`. HTTP `POST /mcp/invoke`. JSON-RPC 2.0 `tools/call`. In-process server. CTRL-MCP-001 **before** handler. Spy registry is authoritative for execution.

## Protocol path

```text
MCP Policy Agent → McpClient.tools_call → McpServer.authorize
  → (ALLOW ticket only) McpServer.execute → ToolRegistry.call_handler
```

Not copied from AgentWatch `mcp_gateway.py`. Not prompt regex.

## Schema decision

Bump **1.0.0 → 1.1.0** (additive). Loan field meanings unchanged. Loan events now emit version 1.1.0.

## Field classification

See `docs/MCP_EVENT_MODEL.md`. Installed `opentelemetry-semantic-conventions==0.65b0` provides incubating `gen_ai.tool.name` and `mcp.method.name`. Scopes are AgentSec fields.

## Authorization model

Coded policy: `allowed_tools={lookup_policy}`, `allowed_scope=policy:read`.  
Unknown → ERROR. Known ungranted → DENY (defended) / labeled ALLOW (vulnerable).  
HTTP extras cannot grant.

---

## Primary specimens (pytest, tmp artifacts)

| Spec | Profile | testbed.mode | Tool | Decision | Handler |
|------|---------|--------------|------|----------|---------|
| **A BASELINE** | defended | BASELINE | `lookup_policy` | ALLOW | **yes** (`invoke_count=1`) |
| **B ATTACK** | vulnerable | ATTACK | `lookup_customer_tier` | labeled ALLOW fail-open | **yes** |
| **C RETEST** | defended | RETEST | `lookup_customer_tier` | DENY | **no** (`invoke_total=0`) |

Tests: `tests/security/test_mcp_control_before_handler.py`, `tests/security/test_mcp_untrusted_json.py`, `tests/telemetry/test_mcp_events.py`, `tests/integration/test_mcp_api.py`.

---

## Failure cases

| Case | Decision | Handler | Events |
|------|----------|---------|--------|
| **D** unknown `unknown_tool_xyz` | ERROR `unknown_tool` | 0 | no `mcp.started` |
| **E** extra/missing args | ERROR `malformed_arguments` | 0 | no `mcp.started` |
| **F** handler raises after ALLOW | ALLOW then `mcp.failed` | 1 | `executed=true`, `outcome=error` |
| **G** exploding authorize_fn | ERROR `control_evaluation_failure` | 0 | no `mcp.started` |

---

## Non-execution proof

`ToolRegistry.invoke_counts` / `invoke_total`. DENY and pre-invoke ERROR leave counts unchanged. Missing `mcp.started` in telemetry is corroboration only.

## Identity / scope spoof

HTTP unknown fields (including `allowed_scope`, `gen_ai.agent.id`, `security.profile`, `control.decision`) → schema ERROR, handler 0, profile remains server-owned. RPC `params` extras are ignored; coded policy still DENYs `lookup_customer_tier` in defended.

## Evidence bundle

Required files present. `splunk.verified=false`. `result.trust=untrusted_data`. MCP manifest `mcp.handler.invoked.count` matches spy.

## Limitations

- In-process JSON-RPC, not stdio/HTTP MCP transport.
- Splunk SPL / Q-MCP-* : see Phase 3C (`docs/PHASE3C_MCP_SPLUNK_VALIDATION.md`). Dashboard Studio still out of 3B/3C.
- No MCP-003+.
- Stub tools only; not OS exploitation.
- CTRL-MCP-001 is a lab allow-list, not production IAM.
