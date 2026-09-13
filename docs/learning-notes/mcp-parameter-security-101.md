# MCP parameter security 101

**Status:** Phase 5A design notes. No MCP-004 runtime.  
**Parents:** `docs/MCP004_PARAMETER_MODEL.md`, `docs/MCP004_LAB_SPECIFICATION.md`.

---

## WHAT IS IT?

**Parameter / resource authorization** asks whether an agent that may already **call a tool at a granted scope** may operate on **this object** named in the arguments.

Example: the agent may call `lookup_policy` at `policy:read`, but only for `policy_id=lending-basics`. Asking for `executive-restricted` is a different question than asking for a different tool or a wider scope.

LAB-MCP-001: *May this agent call this tool?*  
LAB-MCP-003: *May this agent call this tool at this requested scope?*  
LAB-MCP-004: *May this agent perform that permitted operation on this resource?*

## WHY DOES IT EXIST?

Tool and scope allow-lists are easy to over-read. “The agent can look up policies” sounds like “any `policy_id` is fine.” That is the IDOR pattern: same API, different object.

AgentWatch Range never parsed tool arguments. AgentSec already rejects malformed keys/types, then **runs the handler** for any leftover string id. MCP-004 makes catalog vs grant explicit **before** the handler.

## HOW DOES IT WORK?

1. HTTP still sends `tool`, `arguments`, `requested_scope`. Authority is **not** in the JSON grant fields.
2. The server owns `allowed_policy_ids`. The client cannot set them.
3. The tool catalog lists **known** resource ids. That is not the agent grant.
4. Schema check: is `policy_id` a present string with no extra keys?
5. Catalog check: is that exact string a known resource?
6. Grant check: is it in `allowed_policy_ids`?
7. Exact equality. No trim, case fold, prefix, or wildcard.
8. Defended DENYs known-ungranted **before** the handler. Vulnerable fail-opens with a **new** labeled reason and does **not** rewrite the grant.

## WHERE DOES IT SIT IN AGENTSEC?

Same path: `POST /mcp/invoke` → CTRL-MCP-001 → (maybe) `lookup_policy`. No new control id. No schema edit in this phase. Harmless fixtures only.

## WHAT IS THE TRUST BOUNDARY?

`acmebank.mcp.authorize` before `mcp.tool.execute`. The handler must use the **same** resource id the control authorized (ticket). Splunk does not authorize.

## WHAT COULD AN ATTACKER CONTROL?

`tool`, `arguments` (including `policy_id`), `requested_scope`, `user_id`, extra JSON. They might send another known id, an unknown id, a grant field, or malformed types. Those must not widen `allowed_policy_ids`.

## WHAT CAN GO WRONG?

- Treating tool granted as every resource granted.
- Treating a valid JSON string as authorized.
- Calling unknown `does-not-exist` a DENY (or ungranted a malformed).
- Checking existence only inside the handler (`found: false` after ALLOW).
- Silent trim/case-fold so `lending-basics ` becomes ALLOW.
- Fail-open that copies requested into allowed.
- Logging full arguments because “we needed the policy id.”

## WHAT TELEMETRY SHOULD EXIST?

Decision + reason on the control event. Preview + hash of the request blob (already). **Proposed later:** `agentsec.mcp.resource.id` and `agentsec.mcp.allowed_resource.ids`. Not implemented in 5A.

## HOW WILL SPLUNK SHOW IT?

Later: reuse Q-MCP-AUTHZ / EXECUTED / AFTER-DENY. Q-MCP-PARAMS shows the blob, not the grant. A hunt **Q-MCP-RESOURCE-AUTHZ** is justified once structured fields exist. DET-MCP-001 still hunts DENY then `mcp.started`. No DET-MCP-004.

## WHAT CONTROL COULD CHANGE THE RESULT?

`AGENTSEC_SECURITY_PROFILE` on CTRL-MCP-001. Defended DENYs known-ungranted resources. Vulnerable labels fail-open for that case only. Unknown and malformed stay ERROR.

## WHAT TEST PROVES THE LOGIC?

Not written yet. When implemented: spy `handler_invoke_count==0` on RETEST; fail-open reason distinct from MCP-002/003; ticket id equals handler id; `does-not-exist` is ERROR not DENY.

---

## What I should now be able to explain

1. Why tool authorization is not scope authorization, and why neither is resource authorization.
2. Why a syntactically valid `policy_id` can still be unauthorized.
3. Why arguments identify a resource but do not grant it.
4. Why `executive-restricted` is DENY and `does-not-exist` is ERROR.
5. Why malformed JSON is not this lab’s ATTACK.
6. Why authorization must finish before `mcp.started`.
7. Why fail-open must not rewrite `allowed_policy_ids`.
8. Why preview/hash is not a resource-grant hunt.
9. Why DET-MCP-001 can be reused, and when `run+tool` grouping would get ambiguous.
10. Why Splunk observes these decisions and does not authorize the tool.
