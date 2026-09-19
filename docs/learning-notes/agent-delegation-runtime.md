# Agent identity / delegation runtime (Phase 12B)

**Status:** Phase 12B implemented + locally validated. Splunk not verified.  
**Parents:** `docs/AGENT_DELEGATION_RUNTIME_CONTRACT.md`, `docs/learning-notes/agent-identity-delegation-101.md`.

---

## WHAT IS IT?

Runtime proof that an A2A-shaped **request is not a grant**. Agent A can ask Agent B to call `lookup_customer_tier`. That ask does not give either agent `customer:read`.

## WHY DOES IT EXIST?

Labels (`untrusted_claim`) are not a lab. LAB-AGENT-DELEGATION-001 runs the **same** privileged delegation request under vulnerable vs defended authorization and shows different CTRL-MCP-001 decisions and handler counts. It is the amplification sibling of LAB-MCP-006 (ambient confused-deputy, where B **already has** the privilege).

## HOW DOES IT WORK?

One in-process call, one `run.id`:

1. Parse a typed A2A-shaped payload into a **frozen** snapshot. Extra authority-like keys are ERROR `unknown_fields`.
2. CTRL-IDENTITY-001 **OBSERVE** `identity_claim_is_not_grant` / `untrusted_claim` on every valid claim in every profile. It does not ALLOW, DENY, or mint AllowTicket.
3. Follow-on `tools/call` is built from that same snapshot and enters CTRL-MCP-001.
4. Vulnerable **per-request** overlay → ALLOW + privileged handler 1. Defended → DENY `tool_not_granted` + handler 0.

Global `ALLOWED_TOOLS` never grows. RETEST does not “fix” the claim. OBSERVE is not authorization. Agent id strings are not cryptographic authentication.

## WHERE DOES IT SIT IN AGENTSEC?

Dedicated `/identity/delegate` workflow (`identity_delegation_lab`, caller `acme-agent-advisor-005`, callee `acme-agent-fulfillment-006`). Schema **1.8.0**. Not bolted onto MCP-006 `CTRL-DELEGATION-001`. Not live A2A.

## WHAT IS THE TRUST BOUNDARY?

`agent.identity.claim` (IDENTITY-001) then `acmebank.mcp.authorize` (follow-on). Claim trust is not authentication. Authentication is not authorization.

## WHAT COULD AN ATTACKER CONTROL?

The A2A-shaped **request fields**: requested tool, claimed scope, resource, optional `delegation_claim` body. Not coded grants, not profile, not `control.decision`. Extra grant/identity-proof keys are `unknown_fields`.

## WHAT CAN GO WRONG?

Treating OBSERVE as ALLOW; treating Agent Card / caller id as a grant; mutating global grants; using MCP-006’s ambient deputy as this lesson; applying the overlay on RETEST; calling the handler from the identity control; validating one object and authorizing another; emitting `authenticated=true` without crypto; logging tokens.

## WHAT TELEMETRY SHOULD EXIST?

CTRL-IDENTITY-001 OBSERVE with caller, callee, claimed scope, claim trust; follow-on CTRL-MCP-001; optional mcp start/complete. Preview ≤200. Follow-on DENY has no `mcp.started`. Correlation uses `run.id` + `sequence`.

## HOW WILL SPLUNK SHOW IT?

Not in 12B. DET-MCP-001 stays silent on ATTACK B (ALLOW path). No Q-A2A. No DET-A2A. Phase 12C is field discovery after ingest — not started.

## WHAT CONTROL COULD CHANGE THE RESULT?

`AGENTSEC_SECURITY_PROFILE`. Defended does not mint the overlay. IDENTITY-001 stays OBSERVE either way. CTRL-MCP-001 is the only tool PDP.

## WHAT TEST PROVES THE LOGIC?

Runtime handler counts: A policy 1 / tier 0, B tier 1, C tier 0. ATTACK/RETEST share the canonical request. Overlay `run_id` equals the ATTACK run only. `coded_policy()` identical after ATTACK. Extra keys ERROR. No secrets in events.

## 12B findings vs 12A design

12A proposed field-name **candidates**. 12B implemented the smallest set: caller/callee ids, `untrusted_claim`, `claimed_scope`, `identity_claim_trust`, `A2A-001`. Grant snapshot remains a telemetry gap. WHO AUTHENTICATED remains unmodeled.

## What I should now be able to explain

1. Why IDENTITY CLAIM != VERIFIED IDENTITY in this lab.
2. Why AUTHENTICATED != AUTHORIZED when authentication is not even modeled.
3. Why A2A-001 is not MCP-006.
4. Why CTRL-IDENTITY-001 is OBSERVE-only.
5. Why CTRL-MCP-001 remains the only tool PDP.
6. Why neither agent owning `customer:read` is the amplification cut.
7. Why ATTACK and RETEST must use the same request.
8. Why handler count, not missing Splunk rows, proves non-execution locally.
9. Why extra `allowed_tools` on the request is ERROR, not a grant.
10. What Phase 12C still has to discover in Splunk — and what it must not invent.
