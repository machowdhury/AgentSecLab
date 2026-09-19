# Agent identity security model

**Status:** Phase 12A **DESIGN**. Runtime **ABSENT**. Schema **1.7.0 unchanged**.  
**Primary invariant:** INV-001. Supporting: INV-005, INV-004. **No INV-009.**  
**Evidence class:** **DOCUMENTED**.

Parents: `docs/IDENTITY_DELEGATION_PREDECESSOR_ANALYSIS.md`, `docs/SECURITY_INVARIANTS.md`.

---

## WHAT IS IT?

**Agent identity security** asks which **name** an actor is using, whether that name was **verified**, and whether that name is being mistaken for a **grant**.

Identity is a label. Authentication is a check that the label belongs to this caller **for this request**. Authorization is a **server-owned** decision that a **principal + agent + tool + scope + resource** is permitted. Delegation is a **validated, attenuated** right for one party to ask another to act **within** that permission.

```text
IDENTITY CLAIM        != VERIFIED IDENTITY
AUTHENTICATED         != AUTHORIZED
A2A REQUEST           != DELEGATED GRANT
DELEGATION            != AUTHORITY EXPANSION
AGENT A AUTHORITY     != AGENT B AUTHORITY
REQUEST               != GRANT
ALLOW                 != EXECUTION
OBSERVATION           != AUTHORIZATION
SPLUNK                != POLICY DECISION POINT
```

## WHY DOES IT EXIST?

Multi-agent systems introduce a new lie: “a trusted internal agent asked, therefore the tool is allowed.” OWASP ASI03 names this family **Identity & Privilege Abuse** (un-scoped inheritance, cross-agent trust, synthetic identity). A2A Agent Cards advertise identity and **declared** security schemes; they do not authorize tools.

MCP-006 already taught: B’s ambient grant is not A’s delegated grant. This model teaches: **A’s identity is not B’s grant**, and **a request cannot mint a privilege nobody holds**.

## HOW DOES IT WORK? (planned)

```text
USER / PRINCIPAL
        |
        |  validated, attenuated delegation (coded in first lab)
        v
     AGENT A  (caller)     coded tools: {lookup_policy}
        |
        |  A2A-shaped request (identity claim + requested operation)
        v
     AGENT B  (callee)     coded tools: {lookup_policy}
        |
        v
 CTRL-IDENTITY-001   OBSERVE  (claim is data, not a grant)
        |
        v
 CTRL-MCP-001        ALLOW / DENY  (server-owned)
        |
        v
     HANDLER only after ALLOW
```

Trust boundary sits **before** CTRL-MCP-001. CTRL-IDENTITY-001 never executes a tool and never mints AllowTicket.

## WHERE DOES IT SIT IN AGENTSEC?

After memory 11A–11E. Completes learning-architecture Level 2 **identity/A2A design**. Does not reopen MCP-006.

| Lab | Untrusted object | Observation | Authz |
|-----|------------------|-------------|-------|
| LAB-MCP-006 | Ambient deputy grant used for caller | CTRL-DELEGATION-001 **decides** | CTRL-MCP-001 |
| **LAB-AGENT-DELEGATION-001** | Caller / A2A claim as authority | **CTRL-IDENTITY-001 OBSERVE** | **CTRL-MCP-001** |

## WHAT IS THE TRUST BOUNDARY?

Proposed: `agent.identity.claim` (A2A-shaped caller/callee/principal/claimed scope).

| Fact | Example | Grants tools? |
|------|---------|---------------|
| Identity string | `acme-agent-advisor-005` | No |
| Authentication (later) | mTLS / OAuth / SPIFFE SVID | No — only “who presented” |
| Claimed delegation | “please use customer:read” | No |
| Authorization | CTRL-MCP-001 / coded `allowed_tools` | Yes — server-owned |

## WHAT COULD AN ATTACKER CONTROL?

In the first lab: the **A2A-shaped requested operation** (tool + scope), not coded agent ids, not `allowed_tools`, not tokens.

Not: global policy, RAG, memory, scanner, Splunk, LLM-as-PDP.

## WHAT CAN GO WRONG?

- Treating caller identity as a grant
- Treating Agent Card skills as `allowed_tools`
- Treating “authenticated” as “authorized”
- Collapsing WHO REQUESTED / WHO WAS AUTHORIZED / WHO EXECUTED
- Re-running MCP-006 and calling it A2A
- Logging bearer tokens / JWTs

## WHAT TELEMETRY SHOULD EXIST? (12B, not now)

Smallest honest set: principal id, caller agent id, callee agent id, claimed scope, coded allowed scope for the **executing** agent, CTRL-IDENTITY-001 OBSERVE, CTRL-MCP-001 decision, mcp.* / handler count.

## HOW WILL SPLUNK SHOW IT?

Later workshop. Hunt reconstructs the chain. DET-MCP-001 stays silent on the preferred ATTACK (ALLOW path). Zero rows ≠ SAFE.

## WHAT CONTROL COULD CHANGE THE RESULT?

Defended CTRL-MCP-001 DENY `tool_not_granted` for `lookup_customer_tier` because **neither** agent is coded that tool. The A2A request stays the same.

## WHAT TEST PROVES THE LOGIC? (12B)

Same adversarial request on ATTACK and RETEST. Vulnerable overlay ALLOW + handler 1. Defended DENY + handler 0. Overlay does not survive into RETEST.

## SCHEMA

**1.7.0 unchanged in 12A.** **SCHEMA BUMP JUSTIFIED** (proposed **1.8.0**) for 12B identity-claim fields. See `docs/DELEGATION_EVENT_MODEL_REVIEW.md`.

## INVARIANT DECISION

**No INV-009.** See threat model. INV-001 is the property. INV-005 stops identity-as-authentication-theater from becoming a grant. INV-004 keeps attribution honest.
