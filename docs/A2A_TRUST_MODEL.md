# A2A trust model

**Status:** Phase 12A **DESIGN**. Runtime **ABSENT**. **No A2A networking.** Schema **1.7.0 unchanged**.  
**Evidence class:** **DOCUMENTED** from A2A Protocol v1.0.1 and AgentSec OBSERVED facts.

Parents: `docs/AGENT_IDENTITY_SECURITY_MODEL.md`, https://github.com/a2aproject/A2A/blob/v1.0.1/docs/specification.md

---

## WHAT IS A2A HERE?

The **Agent2Agent (A2A) Protocol** is an interoperable way for agents to discover each other (Agent Card), authenticate at the **HTTP** layer using **declared** schemes, and exchange tasks/messages.

It is **not**:

- a tool allow-list
- a delegation grant
- AgentSec’s four in-process loan hops
- LAB-MCP-006 credit→compliance invoke

AgentSec `agents.py` is explicit: sequential agents are **not A2A**.

## Agent Card != grant

An Agent Card describes identity, skills, endpoint, and `securitySchemes` / `security` (OpenAPI-style). A2A v1.0.1: the client authenticates using a **declared** scheme; the **server** still authorizes the operation (401 vs 403). Servers MUST NOT leak unauthorized resources.

Teaching:

```text
AGENT CARD          = discovery + declared auth requirements
EXTENDED AGENT CARD = authenticated metadata (still not a grant)
A2A MESSAGE         = a request
AUTHENTICATED       = credentials accepted
AUTHORIZED          = server policy allowed the operation
```

Skills on a card are **advertisements**. CTRL-MCP-001 remains the tool PDP in AgentSec.

## First lab: A2A-shaped, not A2A transport

Phase 12B (if approved) will implement an **in-process** coded request object:

```text
principal_id
caller_agent_id     # Agent A
callee_agent_id     # Agent B
claimed_scope
requested_tool
requested_resource
```

That object is **not** taken from client JSON identity keys. It is **not** a JSON-RPC A2A client. It is the smallest honest stand-in so learners can see caller ≠ callee ≠ grant.

Live A2A (JSON-RPC / gRPC / HTTP bindings, Agent Card HTTP, JWS card signatures, mTLS) is **DEFER**.

## Trust rules (locked for design)

1. Caller agent id is **coded**, not parsed from prompt text or Agent Card body as authority.
2. Callee does not inherit caller privileges.
3. Caller does not inherit callee privileges.
4. Claimed scope is **telemetry + observation**, never `allowed_scope`.
5. Missing identity context → ERROR/DENY in `defended` (INV-008). Vulnerable overlay is the only fail-open.
6. Splunk does not authorize A2A or MCP.
7. Do not emit `cryptographic_passport_valid=True`. Authentication is **not proven** in the first lab; say so.

## Relationship to OAuth / SPIFFE

| Technology | A2A role | AgentSec 12A |
|------------|----------|--------------|
| OAuth 2.x / OIDC | Declared Agent Card schemes; MCP 2026-07-28 resource server | REFERENCE. Do not implement AS, tokens, or DCR. |
| RFC 8693 | How real systems attenuate “on behalf of” | Teaching analogue: new token, narrower scope, `act` chain. |
| SPIFFE/SPIRE | Workload **authentication** (SVID) | DEFER. Authenticated workload ≠ authorized tool. Never index SVID/JWT. |

## What “trust” means in this lab

Trust is **not** a score. Observation control may classify:

`untrusted_claim` — the A2A-shaped request was seen.

That is **not** `untrusted_data` from RAG/memory (different enums; do not overload). It is **not** ALLOW.

## Negative tests (design)

- Extra keys `allowed_tools`, `agent_id`, `Authorization`, `access_token` → ERROR (reuse extra-field reject / new identity extra-key set).
- Unknown caller/callee id → ERROR `unknown_caller` / `unknown_callee`.
- Prompt `did:acme:` / `Delegation-Chain:` → **ignored** as identity (AgentWatch contrast).

## Stop

Do not implement A2A transport, Agent Card HTTP, or Cisco a2a-scanner from this file.
