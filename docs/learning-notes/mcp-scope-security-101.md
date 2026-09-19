# MCP scope security 101

**Status:** Phase 4A design notes. Phase 4B runtime: `docs/learning-notes/mcp-scope-runtime.md`.  
**Parents:** `docs/MCP003_SCOPE_MODEL.md`, `docs/MCP003_LAB_SPECIFICATION.md`.

---

## WHAT IS IT?

**Scope** is the slice of authority an agent may use **with a tool that is already allowed**.

Example: the agent may call `lookup_policy`, but only with `policy:read`. Asking for `policy:restricted:read` is a different authorization question than asking for a different tool.

LAB-MCP-001 asked: *May this agent call this tool?*  
LAB-MCP-003 asks: *May this agent call this tool with this requested scope?*

---

## WHY DOES IT EXIST?

Tool allow-lists are easy to over-read. “The agent can use lookup_policy” sounds like “any use of that tool is fine.” Attackers (and confused clients) send a **wider scope** on the same call.

AgentWatch Range assigned the **same** MCP scope string to every running agent and never compared a structured requested token to a per-agent grant. AgentSec makes that comparison explicit.

---

## HOW DOES IT WORK?

1. The HTTP body carries **`requested_scope`** as a first-class field. Not inferred from the prompt, policy id, headers, extra JSON, LLM text, or tool result.
2. The server owns **`allowed_scopes`**. The client cannot set them.
3. The tool catalog lists **valid** scope tokens the tool may name. That is not the agent grant.
4. Comparison is **exact set membership**. No prefix, regex, or wildcard.
5. Order: tool exists → tool granted → scope valid → scope granted → args → ALLOW → handler.
6. If the scope is too wide, **defended** DENYs **before** the handler. **Vulnerable** fail-opens with a labeled reason and **does not rewrite** `allowed_scope`.

---

## WHERE DOES IT SIT IN AGENTSEC?

Same path as LAB-MCP-001: `POST /mcp/invoke` → CTRL-MCP-001 → (maybe) `lookup_policy`. No new control id. No new schema version. Harmless fixtures only — not shell, not OS privilege.

---

## WHAT IS THE TRUST BOUNDARY?

`acmebank.mcp.authorize` before `mcp.tool.execute`. The handler never decides scope.

---

## WHAT COULD AN ATTACKER CONTROL?

`tool`, `arguments`, `requested_scope`, `user_id`, extra JSON. They might put a fake `allowed_scope` in the body or hide a scope inside arguments. Those must not widen the grant.

---

## WHAT CAN GO WRONG?

- Treating “tool granted” as “every scope granted.”
- Using `startsWith("policy:")` so `policy:read` also allows `policy:restricted:read`.
- Fail-open that **copies requested into allowed**, hiding the mismatch in Splunk.
- Checking scope **inside** the handler after work already started.
- Inferring scope from `policy_id=restricted-…`.

---

## WHAT TELEMETRY SHOULD EXIST?

On the control event:

- `agentsec.mcp.requested_scope`
- `agentsec.mcp.allowed_scope` (coded grant)
- `agentsec.control.decision` / `reason`
- `gen_ai.tool.name`

Schema 1.1.0 already has these. No `effective_scope`.

---

## HOW WILL SPLUNK SHOW IT?

Reuse **Q-MCP-SCOPE** (requested vs allowed) and **Q-MCP-AUTHZ** / **Q-MCP-EXECUTED**.  
**DET-MCP-001** fires only if a **DENY** is followed by `mcp.started`. The vulnerable ATTACK is an ALLOW, so that detector stays quiet — hunt the mismatch instead.

Splunk does not ALLOW or DENY the tool.

---

## WHAT CONTROL COULD CHANGE THE RESULT?

Defended exact membership: catalog-valid but ungranted → `DENY` `scope_not_granted`, handler count 0.

---

## WHAT TEST PROVES THE LOGIC?

Same tool, same arguments:

- `requested_scope=policy:read` + defended → ALLOW, handler 1.
- `requested_scope=policy:restricted:read` + vulnerable → labeled fail-open ALLOW, handler 1, allowed still `policy:read`.
- Same excessive request + defended → DENY, handler 0, no `mcp.started`.

Spy the handler. Do not trust Splunk absence alone.

---

## What I should now be able to explain

1. Why a granted tool can still be an unauthorized **scope**.
2. Why AgentSec uses an explicit `requested_scope` instead of reading the prompt.
3. Why exact membership is safer here than prefix matching.
4. Why fail-open must keep `allowed_scope` unchanged.
5. Why LAB-MCP-001 ATTACK (wrong **tool**) is not LAB-MCP-003 ATTACK (wrong **scope**).
6. Why DET-MCP-001 does not alert on the vulnerable scope fail-open.
7. Why DENY with `scope_not_granted` must happen before `mcp.started`.
8. Why Splunk Q-MCP-SCOPE observes mismatch but does not enforce policy.
9. Which invariant is primary (INV-001) and how INV-008 applies to missing/unknown scope.
10. Why this lab uses a harmless `lookup_policy` fixture instead of a shell tool.
