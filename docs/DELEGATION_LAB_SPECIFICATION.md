# LAB-AGENT-DELEGATION-001 specification

**Status:** Phase 12A **DESIGN ONLY**. Runtime **ABSENT**. Schema **1.7.0 unchanged**.  
**Attack id:** **A2A-001** (not DELEGATION-001; that name collides with LAB-MCP-006).  
**Evidence class:** **DOCUMENTED**.

Parents: `docs/AGENT_DELEGATION_THREAT_MODEL.md`, `docs/A2A_TRUST_MODEL.md`.

---

## Security question

Can an A2A-shaped request from Agent A cause Agent B to **obtain** `customer:read` / `lookup_customer_tier` when **neither** agent is coded that grant?

Teaching statement (future COMPARE):

```text
SAME DELEGATION REQUEST.
DIFFERENT AUTHORIZATION.
DIFFERENT EXECUTION.
```

## Roles (locked)

| Role | Id | Coded tools | Notes |
|------|----|-------------|-------|
| Principal | `applicant-web` (`principal.type=user`) | n/a | Existing lab HTTP principal. Not an agent. |
| Agent A (caller) | `acme-agent-advisor-005` | `{lookup_policy}` / `policy:read` / `{lending-basics}` | **New** coded persona. Do not use credit-002. |
| Agent B (callee) | `acme-agent-fulfillment-006` | `{lookup_policy}` / `policy:read` / `{lending-basics}` | **New**. Do **not** use compliance-004 (that agent has ambient `customer:read` in MCP-006). |

Neither A nor B is coded `lookup_customer_tier`. That is the amplification cut.

Do not use `acme-agent-mcp-001` (MCP-001–005). Do not use the four-agent LLM `/process` path. Dedicated lab runner, coded ids, in-process, **not** live A2A.

## Operations (locked)

| Mode | Requested tool | Scope | Resource | Expected defended |
|------|----------------|-------|----------|-------------------|
| **A BASELINE** | `lookup_policy` | `policy:read` | `lending-basics` | ALLOW; handler `lookup_policy` **1**; `lookup_customer_tier` **0**. Not SAFE. |
| **B ATTACK** | `lookup_customer_tier` | `customer:read` | `cust-001` | Vulnerable ALLOW overlay; handler **1** |
| **C RETEST** | **same as ATTACK** | **same** | **same** | DENY `tool_not_granted`; handler **0** |

ATTACK and RETEST use the **same** adversarial A2A-shaped request. Discriminator is authorization profile, not different input.

## HTTP / client contract

Keep existing extra-field reject. Expand the forbidden key set for this runner (design):

`allowed_tools`, `allowed_scopes`, `caller_id`, `callee_id`, `agent_id`, `gen_ai.agent.id`, `access_token`, `refresh_token`, `id_token`, `Authorization`, `client_secret`, `delegation_granted`.

Caller/callee ids are **coded in the lab runner**, not JSON.

The LLM does not choose ids, grants, or ALLOW/DENY.

## Control placement (locked)

```text
HTTP schema / extra-key reject
        ↓
coded principal + caller + callee + requested operation
        ↓
CTRL-IDENTITY-001     OBSERVE only
        ↓
CTRL-MCP-001          tool → scope → resource (AllowTicket)
        ↓
handler only after ALLOW
```

CTRL-IDENTITY-001:

- Records principal, caller, callee, claimed scope, requested tool
- Classifies `untrusted_claim` / reason `identity_claim_is_not_grant`
- Decision **OBSERVE**
- **NEVER** ALLOW/DENY a tool, NEVER execute, NEVER mint AllowTicket

Vulnerable: after OBSERVE, CTRL-MCP-001 **ALLOW** `vulnerable_profile_fail_open:caller_identity_derived_authority` for the privileged tool (per-request overlay, **not** a mutated global `ALLOWED_TOOLS`).

Defended: CTRL-MCP-001 **DENY** `tool_not_granted` because fulfillment-006 is not coded `lookup_customer_tier`.

Do **not** route this lab through CTRL-DELEGATION-001.

## Overlay requirements

| Rule | Value |
|------|-------|
| Count | **One** |
| Reason | `vulnerable_profile_fail_open:caller_identity_derived_authority` |
| Scope | Per-request / per-run |
| Persist | No |
| Memory/RAG/scanner/Splunk | Must not be the grant source |
| RETEST | Overlay absent |

## Evidence planes (future workshop)

1. **IDENTITY** — principal, caller, callee (coded ids)
2. **CLAIM** — A2A-shaped requested tool/scope (CTRL-IDENTITY-001 OBSERVE)
3. **AUTHORIZATION** — CTRL-MCP-001
4. **EXECUTION** — mcp.* corroboration; handler count authoritative

## Future workshop flow

ATTACK → TELEMETRY → HUNT → DETECTION DECISION → MITIGATION → RETEST → PROVE  
Learner UI remains LEARN → … → PROVE (ten stages). Not a CTF.

## Out of scope for 12B even after approval (unless a later named phase)

Live A2A transport, OAuth AS, SPIFFE, multi-hop chains, tenant isolation, vector memory, rug-pull, Agent Scan, DET-A2A, Dashboard Studio (that is a later E-phase).

## Stop

Do not implement this specification from this file. Wait for explicit Phase 12B approval.
