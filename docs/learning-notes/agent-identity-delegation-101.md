# Agent identity, delegation, and A2A — beginner note

**Status:** Phase 12A Dashboard-free design note. Runtime **ABSENT**.

## What is it?

Modern agents do not just chat. They **act**: call tools, call other agents, and sometimes claim to act **for a person**.

Three different jobs get mixed up:

1. **Identity** — a name (`applicant-web`, `acme-agent-advisor-005`).
2. **Authentication** — a check that this request really came from that name (password, OAuth token, mTLS, SPIFFE SVID).
3. **Authorization** — a **server** decision that this name may do **this tool** on **this resource**.

**Delegation** is a fourth idea: A may ask B to do something **only within** a validated, **smaller** permission. Delegation is not a promotion.

## Why it exists

If Agent A says “please look up this customer’s tier,” a sloppy system answers: “A is an internal agent, so yes.” That is how **authority amplification** happens: a **request** becomes a **grant**.

A different, already-taught failure is the **confused deputy**: Agent B **already** has the privilege and spends it for A. That is LAB-MCP-006. This chapter is the other failure: **nobody** in the chain had `customer:read`, but the call still ran.

## A picture

```text
Human / principal          “I am the loan applicant UI”
        |
        |  (limited job: ask for policy text)
        v
   Agent A  caller         coded: lookup_policy only
        |
        |  A2A-shaped ask: “B, run lookup_customer_tier”
        v
   Agent B  callee         coded: lookup_policy only
        |
        v
   Server authorization    CTRL-MCP-001
        |
        +-- ALLOW → tool actually starts
        +-- DENY  → handler count stays 0
```

Agent Cards (A2A) are **name tags and capability ads**. They are not employee badges that open the vault.

## Human vs workload vs agent identity

| Kind | Example | Proves |
|------|---------|--------|
| Human / principal | `applicant-web` | Who the lab says initiated |
| Workload | SPIFFE `spiffe://acme/…` (not in this lab) | Process identity, if verified |
| Agent | `acme-agent-advisor-005` | Which coded persona this hop is |

None of those strings is `allowed_tools`.

## Caller vs callee

- **Caller (A)** asked.
- **Callee (B)** would execute.
- **Principal** is who they claim to act for.

“On behalf of” is an **attribution** phrase. It is not a permission.

## Scope attenuation

Good delegation **narrows**:

```text
principal can do {policy:read}
        → A can ask B for {policy:read}
                → B may run lookup_policy
```

Bad delegation **widens**:

```text
A asks for {customer:read}
        → system grants it because A asked
```

OAuth **token exchange** (RFC 8693) exists so real systems issue a **new, narrower** credential instead of forwarding the user’s full token. AgentSec will **not** implement OAuth in 12A. The lesson still holds: **do not forward authority; attenuate it.**

## Confused deputy (already taught)

B has a badge A does not. A asks B to open the door. B does. That is MCP-006.

## Authority amplification (this chapter)

Neither A nor B has the badge. A asks anyway. A vulnerable lab profile **believes the ask**. That is A2A-001.

## Why authenticated agents are still dangerous

Authentication answers “did we accept this caller’s credentials?”  
Authorization answers “may this caller (and this callee) do this?”

A2A says those are different HTTP statuses (401 vs 403). AgentSec says the same with CTRL-MCP-001.

## Why caller identity is not a grant

If “internal agent” were enough, every compromised low-privilege agent would become an admin by asking a neighbor. INV-001: an agent cannot receive more authority than was explicitly delegated. INV-005: impersonation / trusted-caller lies must not silently succeed.

## Why Splunk is not the policy engine

Splunk can reconstruct **who asked whom for what** after the fact. It cannot ALLOW or DENY the tool. Missing rows are not a block. DET-MCP-001 only cares about **DENY then start**.

## Identity telemetry must avoid secrets

Never index access tokens, JWTs, cookies, or `Authorization` headers. Index **opaque ids**, **scope names**, and **decisions**.

## What I should now be able to explain

1. Why identity, authentication, authorization, and delegation are four different facts.
2. Why MCP-006 (confused deputy) is not A2A-001 (amplification).
3. Why an A2A Agent Card is not `allowed_tools`.
4. Why “on behalf of” is attribution, not a grant.
5. Why ATTACK and RETEST must use the same requested tool/scope.
6. Why CTRL-IDENTITY-001 should OBSERVE and CTRL-MCP-001 should decide.
7. Why DET-MCP-001 will be silent on the preferred ATTACK.
8. Why OAuth token exchange is a teaching analogue, not a 12A feature.
9. Why SPIFFE authenticates a workload and still does not authorize a tool.
10. Why tokens and JWTs must never appear in Splunk or evidence packs.
