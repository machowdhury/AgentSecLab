# MCP resource runtime

**Status:** Phase 5B LAB-MCP-004 runtime (IMPLEMENTED + locally validated).  
**Parents:** `docs/MCP004_RUNTIME_CONTRACT.md`, `docs/PHASE5B_MCP004_RUNTIME_VALIDATION.md`, `docs/SCHEMA_1_2_0.md`.

---

## WHAT IS IT?

Runtime that checks **resource identity** after the tool and scope are already granted. `lookup_policy` may run at `policy:read` against `lending-basics`. It may not run against `executive-restricted` unless the lab’s vulnerable profile **labels** a fail-open.

## WHY DOES IT EXIST?

LAB-MCP-001 taught “registered ≠ granted” for **tool names**. LAB-MCP-003 taught “granted tool ≠ granted at every **scope**.” This lab teaches the next sentence: granted tool + granted scope ≠ granted against every **resource** that tool can name.

That is the IDOR-shaped lesson in MCP clothing: the operation is allowed; **this object** is not.

## HOW DOES IT WORK?

1. HTTP accepts only `{tool, arguments, requested_scope, user_id}`. Extra keys are ERROR. Duplicate JSON keys are ERROR before authorize.
2. `policy_id` is used **exactly** as sent. No trim, no lowercase, no wildcards.
3. CTRL-MCP-001: tool exists → granted → scope present → known to tool → granted to agent → arguments structurally valid → resource extracted → in catalog → in grant → ALLOW ticket → handler.
4. Unknown catalog id → ERROR `unknown_resource` (not DENY, not fail-open).
5. Known id not in the grant → DENY `resource_not_granted`, or vulnerable `vulnerable_profile_fail_open:resource_not_granted`.
6. `allowed_resource.ids` in telemetry stays the coded grant (`lending-basics`).
7. The handler reads `ticket.resource_id`, not a later mutation of the request dict.

## WHERE DOES IT SIT IN AGENTSEC?

Same server as LAB-MCP-001 / LAB-MCP-003. Schema **1.2.0**. New attack id `MCP-004`. No new SPL. No Studio. No DET-MCP-004.

## WHAT IS THE TRUST BOUNDARY?

Authorize before handler. Arguments identify a resource; they do not define the grant. Clients cannot set `allowed_policy_ids` or profile.

## WHAT COULD AN ATTACKER CONTROL?

The `policy_id` string, extra JSON, extra argument keys, duplicate keys, case/whitespace/wildcard variants. None of those rewrite `allowed_policy_ids`.

## WHAT CAN GO WRONG?

Silent trim (`"lending-basics "` becoming allowed), last-wins duplicate keys, handler `POLICY_FIXTURES.get(untrusted_id)` as ACL, collapsing MCP-002/003/004 fail-open, rewriting `allowed_resource.ids` on fail-open, treating unknown ids as DENY.

## WHAT TELEMETRY SHOULD EXIST?

Control event: tool, method, requested_scope, allowed_scope, **resource.id**, **allowed_resource.ids**, decision, reason, operation flags. Schema 1.2.0. Preview/hash unchanged. No full arguments.

## HOW WILL SPLUNK SHOW IT?

Not in this phase. Runtime `export.json` marks `splunk.verified=false`. Existing Q-MCP-* / DET-MCP-001 were not modified. Resource fields exist so a later hunt *could* bind them; 5B does not write that SPL.

## WHAT CONTROL COULD CHANGE THE RESULT?

Defended exact membership DENYs `executive-restricted` before the handler. Only profile/mode changes between ATTACK and RETEST.

## WHAT TEST PROVES THE LOGIC?

Spy `invoke_counts`. A: handler 1, resource=grant=`lending-basics`. B: handler 1 with labeled MCP-004 reason and allowed still `lending-basics`. C: handler 0, no `mcp.started`. Ticket mutation after ALLOW still executes `lending-basics`. Duplicate keys never reach the handler.

---

## What I should now be able to explain

1. Why `unknown_resource` is ERROR and `resource_not_granted` is DENY.
2. Why trailing whitespace / case folding cannot become `lending-basics`.
3. Why MCP-002, MCP-003, and MCP-004 fail-open reasons must differ.
4. Why fail-open must leave `allowed_resource.ids=lending-basics`.
5. Why the client cannot send `allowed_policy_ids` to widen the grant.
6. Why the handler must use `ticket.resource_id`, not re-parse the body.
7. Why duplicate JSON keys are rejected before authorization.
8. Why handler count, not missing Splunk rows, proves non-execution.
9. Why schema bumped to 1.2.0 (closed schema + new investigation fields).
10. Why DET-MCP-001 still holds for one invoke per run, and what breaks if two `lookup_policy` calls share a `run_id`.
