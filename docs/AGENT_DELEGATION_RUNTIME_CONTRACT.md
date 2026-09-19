# Agent identity / delegation runtime contract

**Status:** Phase 12B **IMPLEMENTED**. Phase 12C Splunk **VALIDATED** (`docs/PHASE12C_AGENT_DELEGATION_SPLUNK_VALIDATION.md`). Do not treat 12B local run IDs as Splunk proof.  
**Lab:** LAB-AGENT-DELEGATION-001  
**Attack:** A2A-001  
**Schema:** `agentsec.security_event` **1.8.0**  
**Evidence class:** pytest **MEASURED**. Splunk field discovery: **OBSERVED** in Phase 12C (different live run IDs).

Parents: `docs/DELEGATION_LAB_SPECIFICATION.md`, `docs/SCHEMA_1_8_0.md`.

---

## WHAT IS IT?

An in-process deterministic A2A-shaped request model that proves a caller/delegation **claim cannot mint authority neither agent possesses**.

It is not HTTP A2A, JSON-RPC A2A, gRPC, Agent Cards, OAuth, OIDC, token exchange, SPIFFE, or SPIRE.

## Security properties proven

```text
IDENTITY CLAIM != VERIFIED IDENTITY
AUTHENTICATED != AUTHORIZED
A2A REQUEST != DELEGATED GRANT
DELEGATION != AUTHORITY EXPANSION
REQUEST != GRANT
ALLOW != EXECUTION
AN AGENT REQUEST CANNOT MINT AUTHORITY THAT NEITHER AGENT POSSESSES.
```

## Actors (coded)

| Role | Id | Coded grants |
|------|----|----------------|
| Principal | `applicant-web` | n/a (user) |
| Agent A / caller | `acme-agent-advisor-005` | `{lookup_policy}` / `policy:read` / `{lending-basics}` |
| Agent B / callee | `acme-agent-fulfillment-006` | `{lookup_policy}` / `policy:read` / `{lending-basics}` |

Neither agent is coded `lookup_customer_tier` or `customer:read`.

This is **not** MCP-006. MCP-006 is ambient confused-deputy (B **has** `customer:read`). A2A-001 is amplification (neither has it). `authority.source=ambient_deputy` and CTRL-DELEGATION-001 are unused here.

## Request model

Typed frozen `A2ADelegationRequest`:

`principal`, `caller_agent`, `callee_agent`, `requested_tool`, `requested_scope`, `resource`, optional `delegation_claim`.

Unknown fields, including authority-like keys (`allowed_tools`, `grant`, `roles`, `permissions`, `identity_verified`, …), are **ERROR `unknown_fields`**. They are not ignored and never become grants.

The frozen snapshot evaluated by CTRL-IDENTITY-001 is the same object used to construct the follow-on MCP request (check/use).

## Control path

```text
A2A-shaped request parse
        |
        v
CTRL-IDENTITY-001
     OBSERVE  (untrusted_claim / identity_claim_is_not_grant)
        |
        v
follow-on tools/call from the frozen snapshot
        |
        v
CTRL-MCP-001
    ALLOW / DENY / ERROR
        |
        v
handler only after ALLOW  (AllowTicket)
```

CTRL-IDENTITY-001 **never** ALLOW/DENY tools, never mints AllowTicket, never declares identity verified, never authenticates cryptographically.

WHO AUTHENTICATED = **NOT PROVEN / NOT MODELED**. Agent id strings are attribution.

## Specimens

| Mode | Profile | Request | Identity | MCP | Handlers |
|------|---------|---------|----------|-----|----------|
| A BASELINE | defended | `lookup_policy` / `policy:read` / `lending-basics` | OBSERVE | ALLOW `tool_granted` | policy 1, tier 0 |
| B ATTACK | vulnerable | `lookup_customer_tier` / `customer:read` / `cust-001` | OBSERVE | ALLOW `vulnerable_profile_fail_open:caller_identity_derived_authority` | tier 1 |
| C RETEST | defended | **same as ATTACK** | OBSERVE | DENY `tool_not_granted` | tier 0 |

Teaching: **SAME DELEGATION REQUEST. DIFFERENT AUTHORIZATION. DIFFERENT EXECUTION.**

BASELINE is not labeled SAFE.

## One failure point

ATTACK mints a **per-request** `IdentityDerivedOverlay` closed to `lookup_customer_tier` / `customer:read` / `cust-001`.

Reason: `vulnerable_profile_fail_open:caller_identity_derived_authority`.

The overlay:

- is LAB only
- does not mutate `coded_policy()`
- does not persist
- does not write into memory
- does not change Agent A or B coded grants
- does not survive into RETEST
- is not a general authorization API
- disables the generic MCP-004 resource fail-open while present so A2A-001 has **one** labeled mechanism

## Execution semantics

ALLOW is not execution. `mcp.started` means the handler began. Handler **count** is authoritative for local non-execution. DENY before handler: count 0. Handler exception after ALLOW is execution failure, not prevention.

## Telemetry

Enough to reconstruct principal, caller, callee, claimed scope, claim trust, requested tool/scope/resource, CTRL-MCP-001 decision, handler start/complete/fail, `run.id`. Default evidence stores preview + hash, not full request bodies. No tokens.

## Invariants

INV-001 primary (no authority expansion). INV-005 identity ≠ grant. INV-002 A2A claim is data. **No INV-009.**
