# A2A authentication and delegation workshop

## What it is

A REPLAY / STATIC workshop over a synthetic evidence packet. It teaches the difference between a claimed agent name, a simulated authentication result, a bounded simulated delegation evaluation, a tool authorization decision, execution evidence, and downstream impact.

It is not a runtime authenticator or a delegation service.

## Why it exists

Agent-to-agent systems create an easy reasoning error: if Agent A knows Agent B's name, or if a packet says Agent A authenticated, the request can look authorized. That is false. Authentication answers an identity question. Delegation describes bounded authority. CTRL-MCP-001 separately decides whether the tool request is allowed.

## How it works

The packet uses the existing advisor and fulfillment agent identifiers. It includes synthetic authentication references, a simulated grant for `lookup_policy` and `lending-basics`, and three modes:

- ATTACK requests `lookup_customer_tier` and `cust-001`, records MISMATCH, and shows the labeled vulnerable CTRL-MCP-001 ALLOW.
- RETEST makes the same request, records MISMATCH, and shows CTRL-MCP-001 DENY.
- BASELINE requests `lookup_policy` and `lending-basics`, records MATCH, and shows CTRL-MCP-001 ALLOW.

The workshop contrasts that packet with the historical `/identity/delegate` corpus. Historical caller and callee values remain claim-only evidence.

## Where it sits in AgentSec

`L7 → Identity/NHI Workshop → A2A Authentication & Delegation Workshop → L8`

It is a checkpoint, not a new level and not an Attack Service lab.

## Trust boundary

The important boundary is between evidence and authority. A simulated authentication row and a simulated delegation row are evidence for learner reasoning. Neither is a runtime policy decision. Splunk displays evidence downstream. CTRL-MCP-001 remains the tool PDP.

## What an attacker could control

In a real A2A system, an attacker might influence claimed agent identifiers, requested tools, requested resources, or untrusted delegation-shaped data. This workshop does not implement that runtime attack. Its ATTACK mode is a static teaching packet showing a deliberately vulnerable tool-policy outcome.

## What can go wrong

- Treating an agent id as authentication.
- Treating authentication as authority.
- Treating delegation MATCH as tool ALLOW.
- Treating CTRL-MCP-001 ALLOW as execution.
- Treating `agentsec.mcp.started` as successful resource change.
- Merging simulated evidence with historical claim-only events.
- Collapsing tool scope and resource scope.

## Telemetry that should exist

A production design would need separate authentication, delegation, tool-decision, execution, completion, and resource-outcome records with correlation and time semantics. This workshop does not add those runtime events or change schema 1.9.0.

## How Splunk shows it

The Academy view presents the static packet and uses one investigation search only for the historical claim-only contrast. Searching or displaying the packet does not turn simulated evidence into measured runtime authentication.

## What control could change the result

CTRL-MCP-001 changes the tool authorization result. The ATTACK and RETEST packet uses the same out-of-scope request and the same delegation MISMATCH, but different tool-policy behavior. Authentication and delegation evidence stay the same.

## What test proves the logic

Focused repository tests verify the exact mode triples, tool and resource dimensions, simulated labels, synthetic references, control boundaries, replay-only curriculum placement, unchanged schema and ExternalEvidence versions, absence from the LIVE launch catalog, and disabled detector state.

Those tests do not prove runtime authentication, real delegation, Splunk execution, or resource impact.

## What I should now be able to explain

1. Why is an agent identifier only a claim until a verifier produces authentication evidence?
2. Why does successful authentication not authorize a tool?
3. What fields make a delegation bounded?
4. Why are delegated tool and delegated resource separate dimensions?
5. Why can MISMATCH and CTRL-MCP-001 ALLOW appear together in ATTACK?
6. Why are ATTACK and RETEST comparable but BASELINE a different request?
7. What does `agentsec.mcp.started` prove, and what does it not prove?
8. Why must the historical corpus stay separate from the simulated packet?
9. Why is Splunk evidence rather than authority?
10. Which claims remain NOT PROVEN after the workshop?
