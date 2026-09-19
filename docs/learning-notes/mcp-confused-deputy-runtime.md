# Confused deputy runtime (LAB-MCP-006)

**Status:** Phase 7B implemented. Locally validated. Not Splunk-validated.  
**Parents:** `docs/MCP006_RUNTIME_CONTRACT.md`, `docs/learning-notes/mcp-confused-deputy-security-101.md`.

## WHAT IS IT?

A real in-process delegation path: Credit asks Compliance to call an MCP fixture tool. CTRL-DELEGATION-001 runs on hop 0 **before** hop 1 CTRL-MCP-001 and **before** any handler.

## WHY DOES IT EXIST?

Design-only docs cannot prove INV-001. The runtime actually executes or refuses the deputy handler and counts it.

## HOW DOES IT WORK?

1. Lab runner codes caller=`acme-agent-credit-002`, deputy=`acme-agent-compliance-004`.
2. CTRL-DELEGATION-001 checks whether the **tool** is in the **delegated** set.
3. Defended miss → DENY `delegated_authority_not_granted`; no hop 1.
4. Vulnerable miss that is in **ambient** → ALLOW `vulnerable_profile_fail_open:ambient_deputy_authority`.
5. ALLOW freezes a `DelegationTicket`. Hop 1 uses that ticket only.
6. Hop 1 CTRL-MCP-001 uses a **per-request** policy object (delegated or ambient) with **defended** membership. It is not MCP-002 fail-open.
7. Handler runs only after that ALLOW.

## WHERE DOES IT SIT?

`src/agentsec/mcp/delegation.py` + `delegation_pipeline.py`. Schema **1.4.0**. Not `/process`. Not `acme-agent-mcp-001`.

## TRUST BOUNDARY

Caller → CTRL-DELEGATION-001 → MCP authorize → handler.

## WHAT COULD AN ATTACKER CONTROL?

HTTP still only `{tool, arguments, requested_scope, user_id}`. Identity and grants in JSON are `unknown_fields`. The lab ATTACK is the runner selecting `lookup_customer_tier` under profile=vulnerable.

## WHAT CAN GO WRONG?

Using deputy ambient as effective authority on the defended path (tests deny this). Mutating global `ALLOWED_TOOLS` (runtime raises). Skipping MCP-001 after delegation ALLOW (hop 1 still runs it). Treating handler failure as prevention (it is `outcome=error`).

## WHAT TELEMETRY SHOULD EXIST?

Hop 0 decision + `agentsec.delegation.authority.source` (`delegated` \| `ambient_deputy`). Hop 1 deputy + delegator. `mcp.started` only after both ALLOWs.

## HOW WILL SPLUNK SHOW IT?

Not in 7B. `splunk.verified=false`.

## WHAT CONTROL COULD CHANGE THE RESULT?

Profile defended vs vulnerable on the **same** `lookup_customer_tier` request.

## WHAT TEST PROVES THE LOGIC?

`tests/security/test_mcp_delegation.py` ATTACK handler 1 vs RETEST handler 0, same tool/scope/args; hop 1 reason `tool_granted` not MCP-002 fail-open; grant snapshot unchanged.

## What I should now be able to explain

1. Where CTRL-DELEGATION-001 sits relative to the handler?
2. Why hop 1 uses profile=defended even on ATTACK?
3. What `authority.source=ambient_deputy` means?
4. Why HTTP `lookup_customer_tier` is still MCP-002, not this lab?
5. How the ticket stops TOCTOU after ALLOW?
6. Why schema 1.4.0 was required?
7. Why DET-MCP-001 stays silent on ATTACK B?
8. What still is not Splunk-proven?
9. How BASELINE/ATTACK/RETEST handler counts differ?
10. Why grant lists are still a runtime/manifest answer?
