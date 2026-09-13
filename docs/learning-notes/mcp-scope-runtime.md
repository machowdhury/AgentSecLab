# MCP scope runtime

**Status:** Phase 4B LAB-MCP-003 runtime (IMPLEMENTED + locally validated).  
**Parents:** `docs/MCP003_RUNTIME_CONTRACT.md`, `docs/PHASE4B_MCP003_RUNTIME_VALIDATION.md`.

---

## WHAT IS IT?

Runtime that checks **scope** after the tool is already granted. `lookup_policy` may run at `policy:read`. It may not run at `policy:restricted:read` unless the lab’s vulnerable profile **labels** a fail-open.

## WHY DOES IT EXIST?

LAB-MCP-001 taught “registered ≠ granted” for **tool names**. This lab teaches the next sentence: granted tool ≠ granted **at every scope** the tool can name.

## HOW DOES IT WORK?

1. HTTP accepts only `{tool, arguments, requested_scope, user_id}`. Extra keys are ERROR.
2. `requested_scope` is used **exactly** as sent. No trim, no lowercase.
3. CTRL-MCP-001: tool exists → granted → token in `ToolSpec.valid_scopes` → token in coded `allowed_scopes` → then arguments → ALLOW → handler.
4. Unknown catalog token → ERROR `unknown_scope` (not DENY).
5. Known token not in the grant → DENY `scope_not_granted`, or vulnerable `vulnerable_profile_fail_open:scope_not_granted`.
6. `allowed_scope` in telemetry stays the coded grant (`policy:read`).

## WHERE DOES IT SIT IN AGENTSEC?

Same server as LAB-MCP-001. Same schema 1.1.0. New attack id `MCP-003` on the enum only. No new SPL.

## WHAT IS THE TRUST BOUNDARY?

Authorize before handler. Arguments cannot supply scope. Clients cannot set `allowed_scope` or profile.

## WHAT COULD AN ATTACKER CONTROL?

The `requested_scope` string, extra JSON, and argument keys. None of those rewrite the grant.

## WHAT CAN GO WRONG?

Silent trim (`"policy:read "` becoming allowed), prefix matching, collapsing MCP-002 and MCP-003 fail-open, rewriting `allowed_scope` on fail-open, checking scope inside the handler.

## WHAT TELEMETRY SHOULD EXIST?

Control event: tool, method, requested_scope, allowed_scope, decision, reason, operation flags. Schema 1.1.0.

## HOW WILL SPLUNK SHOW IT?

Phase 4C: reuse Q-MCP-SCOPE / Q-MCP-AUTHZ / Q-MCP-EXECUTED / DET-MCP-001. See `docs/learning-notes/mcp-scope-splunk.md`. Runtime `export.json` still marks `splunk.verified=false`; Splunk proof is independent CLI.

## WHAT CONTROL COULD CHANGE THE RESULT?

Defended exact membership DENYs restricted scope before the handler.

## WHAT TEST PROVES THE LOGIC?

Spy `invoke_counts`. A: handler 1. B: handler 1 with labeled reason and allowed still `policy:read`. C: handler 0, no `mcp.started`. D–H: ERROR `unknown_scope`, handler 0.

---

## What I should now be able to explain

1. Why `unknown_scope` is ERROR and `scope_not_granted` is DENY.
2. Why trailing whitespace is not normalized into a grant.
3. Why a comma-separated string is one unknown token, not two scopes.
4. Why MCP-002 and MCP-003 fail-open reasons must differ.
5. Why fail-open must leave `allowed_scope=policy:read`.
6. Why arguments containing `scope` cannot authorize.
7. Why handler count, not missing Splunk rows, proves non-execution.
8. Why DET-MCP-001 would not fire on the vulnerable ATTACK.
9. Why schema stayed 1.1.0.
10. Why LAB-MCP-001 `lookup_customer_tier` behavior is still the tool-grant lesson.
