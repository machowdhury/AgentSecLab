# MCP Runtime 101

**Status:** Phase 3B implemented. Splunk hunts are **not** written yet.  
**Parents:** `docs/MCP_RUNTIME_CONTRACT.md`, `docs/MCP_EVENT_MODEL.md`.  
**Tests:** `tests/security/test_mcp_control_before_handler.py` (MEASURED this session).

---

## WHAT IS IT?

The first **real** AgentSec MCP path: an agent asks for a **named tool** with **arguments**. An MCP **server** checks a **coded allow-list**, then maybe runs a **harmless fixture function**.

It is not “the prompt contained `execute_shell_command(`.” That was AgentWatch theater.

## WHY DOES IT EXIST?

You already saw untrusted text stopped **before the LLM**. Tools are a different dangerous operation: **running code the model (or a caller) asked for**.

If the control runs after the handler, “DENY” is a lie.

## HOW DOES IT WORK?

1. You POST `{tool, arguments, requested_scope}` to `/mcp/invoke`.
2. AcmeBank uses a **coded** agent id (`acme-agent-mcp-001`). The body cannot change that.
3. The client wraps the request as JSON-RPC `tools/call`.
4. The **server** checks: known tool? args valid? granted?
5. **ALLOW** → handler begins (`mcp.started`, `executed=true`).
6. **DENY / ERROR** → handler count stays zero. No `mcp.started`.

`lookup_policy` is granted. `lookup_customer_tier` is **known but not granted** — that is the workshop attack, so you can tell **authorization failure** from **unknown tool** (ERROR).

In `vulnerable`, the ungranted tool is an **intentional labeled fail-open**. Unknown tools stay ERROR.

## WHERE DOES IT SIT IN AGENTSEC?

Next to the loan pipeline, not inside it. Four loan agents still do not call tools.

Schema **1.1.0** is shared. Loan events still mean what they meant in 1.0.0.

## WHAT IS THE TRUST BOUNDARY?

`acmebank.mcp.authorize` then `mcp.tool.execute`. Splunk cannot ALLOW a tool.

## WHAT COULD AN ATTACKER CONTROL?

`tool`, `arguments`, `requested_scope`, `user_id`. Not profile, not allow-list, not `run.id`, not the decision field.

## WHAT CAN GO WRONG?

- Fail-open unknown tools (AgentWatch `MCP-GW-PASS`).
- Client-only checks.
- DENY after `mcp.started`.
- Treating handler failure as prevention.
- Treating a fixture result as new authority.

## WHAT TELEMETRY SHOULD EXIST?

`control.decision` plus `mcp.started` / `completed` / `failed`. Scopes: `agentsec.mcp.requested_scope` vs `allowed_scope`. Tool name: **`gen_ai.tool.name`** (OTel incubating, installed in SDK 1.44.0). Method: **`mcp.method.name=tools/call`**.

## HOW WILL SPLUNK SHOW IT?

Phase 3C: `Q-MCP-*` in `learning/level_1/LAB-MCP-001/searches/`. Hunt `event.name` + `agentsec.run.id`. Do not hunt `session.id`. See `docs/learning-notes/mcp-splunk-investigation.md`.

## WHAT CONTROL COULD CHANGE THE RESULT?

`AGENTSEC_SECURITY_PROFILE=defended|vulnerable` on **CTRL-MCP-001**. Same unauthorized tool, different decision.

## WHAT TEST PROVES THE LOGIC?

The registry **counter**. If DENY and the counter moved, the lab is wrong — regardless of Splunk.

---

## What I should now be able to explain

1. Why LAB-MCP-001 uses a structured `tools/call` instead of scanning the loan prompt.
2. Why `lookup_customer_tier` is a better first attack than `unknown_tool_xyz`.
3. Where the allow-list is coded, and why HTTP `allowed_scope` is rejected.
4. What `vulnerable_profile_fail_open:CTRL-MCP-001…` is teaching.
5. Why `mcp.started` with `executed=true` can never be a DENY for that invoke.
6. Why a handler exception is `mcp.failed` / `outcome=error`, not prevention.
7. Which fields are OTel incubating vs AgentSec (`requested_scope` / `allowed_scope`).
8. Why schema 1.1.0 does not change the meaning of loan `llm.*` events.
9. How you would prove non-execution without Splunk.
10. Why the tool JSON result still cannot add `lookup_customer_tier` to the grant.
