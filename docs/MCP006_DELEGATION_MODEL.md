# MCP-006 delegation model

**Status:** Phase 7B **IMPLEMENTED**. Schema **1.4.0**. Splunk not started.  
**Parents:** `docs/MCP006_PREDECESSOR_ANALYSIS.md`, `docs/MCP_ARCHITECTURE.md`.  
**Evidence class:** **DOCUMENTED**. Current AgentSec facts marked **OBSERVED**.

---

## WHAT IS IT?

Delegated authorization for a **two-agent** lab invoke: a **caller** asks a **deputy** to perform a harmless MCP tool. The deputy may already be allowed to perform that tool **for itself**. That is **ambient deputy authority**. The question is whether the **caller** was granted the right to ask for it.

---

## First principle

| Concept | Meaning in this lab |
|---------|---------------------|
| **Identity** | Server-owned ids: principal, caller agent, deputy agent |
| **Authentication** | Not modeled as a crypto protocol. Ids are coded, not parsed from content |
| **Authorization** | Deterministic grant membership (existing CTRL-MCP-001) |
| **Delegation** | Whether **this caller** may ask **this deputy** for **this operation** |
| **Execution** | Tool handler begins (`mcp.started`) |
| **Attribution** | Telemetry names who asked, who executed, what was decided |

Knowing “credit sent this request” is **not** “credit may have customer-tier looked up.”  
The deputy being allowed to look up customer tier **for itself** is **not** “credit inherits that tool.”

---

## Confused deputy (working definition)

A confused deputy occurs when a component with **legitimate ambient authority** is induced to exercise that authority **on behalf of a caller** that does **not** possess the required **delegated** authority.

The failure is in **authorization logic**, not in an LLM becoming confused.

---

## Roles (locked)

| Role | AgentSec id | Name | Why this pair |
|------|-------------|------|----------------|
| **Initiating principal** | `user_id` (default `applicant-web`) | Lab HTTP principal | Existing `agentsec.principal.*`. Not an agent. |
| **Caller agent** | `acme-agent-credit-002` | Credit Agent | Already in `PIPELINE_ORDER`. Less privileged peer. Easy story: credit wants a lookup **on behalf of** a scoring step. |
| **Delegating agent** | **same as caller** | Credit Agent | Smallest model: the caller **is** the delegator. No third orchestrator. |
| **Executing deputy** | `acme-agent-compliance-004` | Compliance Agent | Last pipeline agent; “privileged internal” story without a new persona. Ambient grant includes the extra tool. |

Do not use `acme-agent-mcp-001` as either party. That agent remains LAB-MCP-001–005.

Do not use the four-agent **LLM** `/process` path. MCP-006 stays on dedicated MCP workflow `mcp_tool_lab` / `POST /mcp/invoke` with **coded** caller/deputy (lab runner), like MCP-005’s coded fixture selection. In-process, not network A2A.

**Why not risk-003?** Risk already “scores.” Credit asking compliance for a lookup is the clearer social/authority story.

---

## Authority sets (locked)

| Set | Who | Tools (coded) | Scopes / resources |
|-----|-----|---------------|--------------------|
| **CALLER AUTHORITY** | Credit, for **its own** direct MCP (not this lab’s execute path) | `{lookup_policy}` | `policy:read` / `{lending-basics}` |
| **DELEGATED AUTHORITY** | What credit may **ask compliance to do** | `{lookup_policy}` only | `policy:read` / `{lending-basics}` |
| **DEPUTY AMBIENT AUTHORITY** | What compliance may do **for itself** | `{lookup_policy, lookup_customer_tier}` | policy as above, plus `customer:read` / fixture `cust-001` |

**EFFECTIVE DELEGATED AUTHORITY** for a deputy operation in **defended** profile:

```text
effective = DELEGATED AUTHORITY  (caller → this deputy → this operation)
```

Not:

```text
effective = DEPUTY AMBIENT AUTHORITY
```

Vulnerable profile is the labeled lie: consult **deputy ambient** instead of **delegated**, reason `vulnerable_profile_fail_open:ambient_deputy_authority`.

Do not implement IAM algebra (union, intersection across many agents, time-bounded tokens).

---

## Harmless operations (locked)

| Mode | Tool | Scope | Arguments |
|------|------|-------|-----------|
| BASELINE (permitted delegation) | `lookup_policy` | `policy:read` | `{policy_id: lending-basics}` |
| ATTACK / RETEST (excessive) | `lookup_customer_tier` | `customer:read` | `{customer_id: cust-001}` |

Same tools already exist. Fixture ids only. No funds, shell, or PII.

`lookup_customer_tier` is also MCP-005’s follow-on tool. **Different invariant:** MCP-005 is result-as-grant on **one** agent. MCP-006 is **two** agents and ambient vs delegated. Teaching must say that out loud. Do not reuse `result_derived_grant`.

---

## HTTP / client contract (locked)

Keep `ALLOWED_MCP_INVOKE_FIELDS = {tool, arguments, requested_scope, user_id}` (**OBSERVED**).

Clients **cannot** supply: `allowed_tools`, `allowed_scopes`, `allowed_resources`, `delegated_permissions`, `effective_authority`, `deputy_authority`, `agent_id`, `caller_id`, `deputy_id`, `delegator`, `gen_ai.agent.id`. Extra keys → existing extra-field reject (ERROR, not ATTACK success).

Caller/deputy ids are **coded in the LAB-MCP-006 runner**, not taken from JSON.

The LLM does not choose ids, grants, or ALLOW/DENY.

---

## CTRL-DELEGATION-001

**Placement (locked):** after delegation context is established (coded caller, coded deputy, requested tool/scope/resource), **before** CTRL-MCP-001, **before** any handler.

```text
HTTP schema
    ↓
coded caller + deputy + requested operation
    ↓
CTRL-DELEGATION-001
    ↓
ALLOW / DENY / ERROR
    ↓
CTRL-MCP-001 (tool → scope → resource) using the policy object selected for this request
    ↓
handler
    ↓
CTRL-MCP-RESULT-001 (unchanged; not this lab’s variable)
```

A delegation ALLOW does **not** skip MCP-001–004–005.

Vulnerable: CTRL-DELEGATION-001 **ALLOW** `vulnerable_profile_fail_open:ambient_deputy_authority`, then CTRL-MCP-001 is evaluated against **deputy ambient** `McpPolicy` (per-request object, **not** a mutated global).

Defended: if the requested operation ∉ DELEGATED AUTHORITY → **DENY** `delegated_authority_not_granted`, `attempted=false`, `executed=false`, `outcome=prevented`, handler **0**. CTRL-MCP-001 is **not** consulted for that invoke (same as MCP-002 DENY-before-handler). Downstream MCP DENY after valid delegation is a **separate** teaching specimen (I).

---

## Canonical reasons (locked)

| Case | decision | reason |
|------|----------|--------|
| Permitted delegation | ALLOW | `delegation_granted` |
| Vulnerable ambient misuse | ALLOW | `vulnerable_profile_fail_open:ambient_deputy_authority` |
| Defended excessive request | DENY | `delegated_authority_not_granted` |
| Unknown caller id | ERROR | `unknown_caller` |
| Unknown deputy id | ERROR | `unknown_deputy` |
| Missing required context | ERROR | `missing_delegation_context` |
| Malformed delegation object | ERROR | `malformed_delegation` |
| Control exception | ERROR | `delegation_control_error` |

Do not reuse `scope_not_granted`, `resource_not_granted`, or `result_derived_grant`.

---

## Check / use (DelegationTicket)

After ALLOW, freeze:

`principal_id, caller_agent_id, deputy_agent_id, tool, requested_scope, resource_id, authority_source, decision`

The handler may run only with **ticket** tool/scope/resource. Changing identity or operation after the check is a TOCTOU fail → ERROR, no handler. Same idea as MCP-004 AllowTicket.

---

## Cross-run isolation

Grants are coded constants. Vulnerable path selects which **per-request** policy object to consult. No global `_AGENT_USED_SCOPE`. No ATTACK run mutates credit or compliance grants. A following defended run must see the original coded sets.

---

## Handler proof

Runtime `invoke_counts` **per tool** remain authoritative.

- BASELINE: `lookup_policy` count **1**; `lookup_customer_tier` **0**
- ATTACK: `lookup_customer_tier` **1**
- RETEST: `lookup_customer_tier` **0**

Isolate the deputy operation by tool name (operations differ). Splunk missing `mcp.started` corroborates only on a complete copy.

---

## What 7B implemented

Runtime: `src/agentsec/mcp/delegation.py`, `src/agentsec/mcp/delegation_pipeline.py`. Schema 1.4.0. Local validation: `docs/PHASE7B_MCP006_RUNTIME_VALIDATION.md`. No SPL, detector, or Studio.
