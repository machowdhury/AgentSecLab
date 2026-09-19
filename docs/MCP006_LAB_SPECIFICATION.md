# LAB-MCP-006 specification (design only)

**Status:** Phase 7B **IMPLEMENTED**. See `docs/MCP006_RUNTIME_CONTRACT.md`.  
**Parents:** `docs/MCP006_DELEGATION_MODEL.md`, `docs/MCP006_THREAT_MODEL.md`, `docs/MCP006_EVENT_MODEL_REVIEW.md`.  
**Evidence class:** pytest **MEASURED**. Local packs **OBSERVED**. Splunk **NOT ATTEMPTED**.

Supersedes the `docs/MCP_LAB_PLAN.md` MCP-006 sketch (payload identity spoof as the whole attack). Identity spoof remains a **negative test**.

---

## Lab identity

| Item | Value |
|------|--------|
| Lab | LAB-MCP-006 |
| Attack | MCP-006 — confused deputy / delegated authority |
| Controls | **CTRL-DELEGATION-001** (new) + **CTRL-MCP-001** (reuse) |
| Initiating principal | existing `user_id` / `agentsec.principal.id` (default `applicant-web`) |
| Caller / delegator | `acme-agent-credit-002` (Credit Agent) |
| Deputy | `acme-agent-compliance-004` (Compliance Agent) |
| Permitted delegated tool | `lookup_policy` |
| Excessive tool | `lookup_customer_tier` |
| Method | `tools/call` (deputy hop only) |
| Workflow | `mcp_tool_lab` / `POST /mcp/invoke` with **coded** identities in the lab runner |
| Primary invariant | INV-001 |

LAB-MCP-001 remains the tool-grant lab. LAB-MCP-003 remains the scope lab. LAB-MCP-004 remains the resource lab. LAB-MCP-005 remains the result-trust lab. Do not retcon any of them.

Do **not** use `acme-agent-mcp-001` as caller or deputy. That agent stays LAB-MCP-001–005.

Do **not** put this lab on the LLM `/process` four-agent path.

---

## Security property

**Question:** When credit asks compliance to perform an MCP operation, whose authority governs — the caller’s **delegated** grant, or the deputy’s **ambient** grant?

| Concept | LAB-MCP-001 | LAB-MCP-003 | LAB-MCP-004 | LAB-MCP-005 | LAB-MCP-006 |
|---------|-------------|-------------|-------------|-------------|-------------|
| Variable | tool name | requested scope | `policy_id` | result fixture | **whose grant the deputy consults** |
| Held constant | — | same tool + args | same tool + scope | same first tool | same caller, deputy, request (ATTACK=RETEST) |
| Fail-open | ungranted tool | granted tool + excessive scope | ungranted resource | result treated as authority | deputy uses **ambient** instead of **delegated** |

Teaching comparison:

| Mode | Caller may ask | Deputy itself may execute | Which grant is used | Result |
|------|----------------|---------------------------|---------------------|--------|
| BASELINE | yes (`lookup_policy`) | yes | delegated | ALLOW + execute |
| ATTACK | no (`lookup_customer_tier`) | yes | ambient (vulnerable) | ALLOW + execute |
| RETEST | no | yes | delegated (defended) | DENY + no execute |

---

## Why this agent pair

Credit and compliance already exist in `PIPELINE_ORDER` (**OBSERVED** `src/agentsec/agents.py`). Credit is an earlier, less-privileged scoring hop. Compliance is the last internal hop — easy to believe it may look up customer-tier fixtures **for its own work**. The authority gap is obvious in one sentence:

> Credit may ask compliance to look up **lending policy**. Credit may **not** ask compliance to look up **customer tier**, even though compliance can do that for itself.

Risk-003 is a weaker story (already “scores”). Intake-001 is too far from a privileged lookup.

---

## Harmless operations (locked)

| Mode | Tool | Scope | Arguments |
|------|------|-------|-----------|
| BASELINE | `lookup_policy` | `policy:read` | `{policy_id: lending-basics}` |
| ATTACK and RETEST | `lookup_customer_tier` | `customer:read` | `{customer_id: cust-001}` |

Fixture ids only. No funds, shell, filesystem, credentials, or real PII.

`lookup_customer_tier` is also MCP-005’s follow-on tool. **Same handler, different invariant.** MCP-005: one agent, result-as-grant. MCP-006: two agents, ambient vs delegated. Do not reuse `result_derived_grant`. Do not overlay grants from result text.

---

## Canonical A / B / C

ATTACK and RETEST use the **same** request. Only profile / control behavior differs.

| Id | `testbed.mode` | Profile | Caller | Deputy | Request | Expected |
|----|----------------|---------|--------|--------|---------|----------|
| **A** | BASELINE | defended | credit-002 | compliance-004 | `lookup_policy` + `policy:read` + `lending-basics` | CTRL-DELEGATION-001 ALLOW `delegation_granted`. Hop 1 CTRL-MCP-001 ALLOW. `lookup_policy` handler **1**. `lookup_customer_tier` **0**. |
| **B** | ATTACK | vulnerable | same | same | `lookup_customer_tier` + `customer:read` + `cust-001` | CTRL-DELEGATION-001 ALLOW `vulnerable_profile_fail_open:ambient_deputy_authority`. Hop 1 CTRL-MCP-001 ALLOW against **per-request** deputy ambient policy. `lookup_customer_tier` handler **1**. |
| **C** | RETEST | defended | same | same | **same as B** | CTRL-DELEGATION-001 DENY `delegated_authority_not_granted`. Hop 1 **does not start**. Handler **0**. `attempted=false`, `executed=false`, `outcome=prevented`. |

Vulnerable is **not** “authorization off.” It consults deputy ambient instead of the delegated set.

---

## BASELINE / ATTACK / RETEST matrix

| | BASELINE | ATTACK | RETEST |
|--|----------|--------|--------|
| Profile | defended | vulnerable | defended |
| Caller | credit-002 | credit-002 | credit-002 |
| Deputy | compliance-004 | compliance-004 | compliance-004 |
| Requested operation | permitted | excessive | **same excessive** |
| Caller / delegated authority | sufficient | insufficient | insufficient |
| Deputy ambient authority | sufficient | sufficient | sufficient |
| Delegation decision | ALLOW `delegation_granted` | ALLOW fail-open ambient | DENY `delegated_authority_not_granted` |
| MCP (hop 1) begins | YES | YES | NO |
| Handler count (requested tool) | 1 (`lookup_policy`) | 1 (`lookup_customer_tier`) | 0 |

---

## Authorization order (server, later implementation)

**OBSERVED today** (`src/agentsec/mcp/pipeline.py`, `authorize.py`): HTTP schema → CTRL-MCP-001 (tool → scope → resource) → handler → CTRL-MCP-RESULT-001.

**Designed MCP-006 order:**

```text
HTTP schema (existing extra-field reject)
    ↓
coded caller + coded deputy + requested operation  (lab runner; not JSON identity)
    ↓
CTRL-DELEGATION-001          ← hop 0, agent = caller
    ↓
ALLOW / DENY / ERROR
    ↓
[DENY/ERROR: no hop 1, handler 0]
    ↓
hop 1 deputy
    ↓
CTRL-MCP-001 tool → scope → resource (existing)
    ↓
handler (ticket-bound)
    ↓
CTRL-MCP-RESULT-001 (unchanged; not this lab’s variable)
```

Delegation ALLOW does **not** skip MCP-001–004. MCP-005 still labels results as data.

---

## Trace / hop model (locked)

Inspected current MCP-005: hop 0 first tool, hop 1 follow-on, same `acme-agent-mcp-001` both hops.

MCP-006 **reuses hop index**, not the same-agent follow-on:

```text
RUN  (mcp_tool_lab)
  hop 0  gen_ai.agent.id = acme-agent-credit-002
         no delegator (schema: forbidden on hop 0)
         CTRL-DELEGATION-001
         gen_ai.tool.name = requested tool  (request, not execution)
         no mcp.started on hop 0
  hop 1  (only if delegation ALLOW)
         gen_ai.agent.id = acme-agent-compliance-004
         agentsec.delegator.agent.id = acme-agent-credit-002
         CTRL-MCP-001
         mcp.started / completed | failed
```

Do **not** force a separate “delegation span kind” unless 7B finds hop.started + control.decision insufficient. Do not put MCP-006 on `/process`.

`gen_ai.tool.name` on hop 0 is the **requested** operation. Execution is only `event.name=agentsec.mcp.started` on hop 1. Teaching must say that so learners do not treat hop 0 tool name as handler proof.

---

## Identity model

| Identity | Source | Client may set? |
|----------|--------|-----------------|
| Principal | coded / existing `user_id` field (already allowed) | `user_id` yes; not agent identity |
| Caller | lab runner coded `CREDIT_ID` | **no** |
| Deputy | lab runner coded `COMPLIANCE_ID` | **no** |
| Delegator | same as caller in this lab | **no** |

HTTP allow-list remains `{tool, arguments, requested_scope, user_id}` (**OBSERVED**). Extra keys including `agent_id`, `deputy_id`, `allowed_tools`, `delegated_permissions` → existing reject. Not ATTACK success.

The LLM does not decide identity, grants, or ALLOW/DENY.

---

## Delegation object (smallest)

Server-owned **DelegationTicket** after ALLOW (idea from MCP-004 AllowTicket). Conceptual fields:

| Field | Necessary? | Notes |
|-------|------------|-------|
| principal_id | yes | existing principal |
| caller_agent_id | yes | coded |
| deputy_agent_id | yes | coded |
| tool | yes | requested = executed |
| requested_scope | yes | existing MCP field |
| resource_id | yes | fixture id; MCP-004 shape |
| authority_source | yes | `delegated` vs `ambient_deputy` |
| decision | yes | ALLOW / DENY / ERROR |

Redundant / do not add as HTTP or extra schema pile: `delegator_agent_id` (equals caller here), client `allowed_*`, `effective_authority`, a third orchestrator id.

Telemetry: prefer reuse of `gen_ai.agent.id` + `delegator.agent.id` + hop index over a stack of `agentsec.delegation.*.id` fields. See event-model review.

---

## Error vs DENY

| Condition | Decision | Handler |
|-----------|----------|---------|
| Well-formed; caller not delegated the op | DENY `delegated_authority_not_granted` | 0 |
| Unknown caller / unknown deputy | ERROR | 0 |
| Missing delegation context | ERROR `missing_delegation_context` | 0 |
| Malformed object | ERROR `malformed_delegation` | 0 |
| Control exception | ERROR `delegation_control_error` | 0 |
| Duplicate JSON keys / extra fields | existing HTTP reject; no control.decision | 0 |
| Valid delegation then MCP-001 DENY | Delegation ALLOW; MCP DENY | 0 |
| Valid delegation then handler failure | MCP ALLOW; `mcp.failed` | attempted; not prevention |

Malformed must never become ATTACK success or ambient ALLOW.

---

## Canonical event sequences (design; not emitted in 7A)

**A — legitimate delegation**  
run.started → hop 0 started (credit) → CTRL-DELEGATION-001 ALLOW `delegation_granted` (authority.source=`delegated`) → hop 0 completed hop_allowed → hop 1 started (compliance, delegator=credit) → CTRL-MCP-001 ALLOW → mcp.started `lookup_policy` → mcp.completed → hop 1 completed → run.completed.

**B — vulnerable confused deputy**  
Same as A except requested tool `lookup_customer_tier`, CTRL-DELEGATION-001 ALLOW `vulnerable_profile_fail_open:ambient_deputy_authority` (authority.source=`ambient_deputy`), hop 1 executes that tool.

**C — defended RETEST**  
run.started → hop 0 started → CTRL-DELEGATION-001 DENY `delegated_authority_not_granted` → hop 0 completed hop_denied → pipeline.stopped / run.completed. **No hop 1. No mcp.started.**

**D — spoofed caller identity**  
Extra JSON identity key → HTTP/schema ERROR. No hop 1. Not specimen B.

**E — unknown deputy**  
ERROR `unknown_deputy`. Handler 0.

**F — missing delegation context**  
ERROR `missing_delegation_context`. Handler 0.

**G — malformed delegation**  
ERROR `malformed_delegation`. Handler 0.

**H — delegation-control exception**  
ERROR `delegation_control_error`. Handler 0.

**I — valid delegation, MCP DENY**  
Teaching extra: BASELINE-shaped caller/tool that then fails scope/resource. Delegation ALLOW, hop 1 CTRL-MCP-001 DENY, handler 0.

**J — valid delegation, handler failure**  
Teaching extra: MCP ALLOW then `mcp.failed`. Not prevention.

---

## Handler proof

Runtime `ToolRegistry.invoke_counts` per tool is authoritative.

Isolate the deputy operation by **tool name** (A vs B/C already differ). Do not rely on Splunk absence as proof. Splunk missing `mcp.started` corroborates only on a complete indexed copy.

Cross-run: after ATTACK, a new defended RETEST must still see coded grants; handler 0. No global registry mutation.

---

## Check / use / TOCTOU

After ALLOW, freeze the ticket. Handler uses ticket tool/scope/resource/deputy only. If identity or operation would change after the check → ERROR, no handler.

No time-of-check/time-of-use window that re-reads HTTP body for grants.

---

## Privacy

Do not emit full prompts, customer PII, secrets, tokens, or arbitrary argument dumps. Fixture ids `lending-basics` / `cust-001` only. Preview ≤200 + `sha256:` as today.

---

## Tests (7B)

Implemented in `tests/unit/test_mcp_006_delegation.py`, `tests/security/test_mcp_delegation.py`, `tests/telemetry/test_mcp_006_events.py`, `tests/unit/test_mcp_006_evidence.py`, `tests/integration/test_mcp_006_api.py`.

| Case | Assertion |
|------|-----------|
| BASELINE | policy handler 1; tier handler 0; reason `delegation_granted` |
| ATTACK | tier handler 1; reason `vulnerable_profile_fail_open:ambient_deputy_authority`; **global** grants unchanged |
| RETEST | same request as ATTACK; DENY `delegated_authority_not_granted`; tier handler 0; no hop 1 |
| Identity spoof extra fields | HTTP reject; handler 0 |
| Client `allowed_tools` / `delegated_permissions` | extra-field reject |
| Unknown caller / deputy | ERROR; handler 0 |
| Missing / malformed context | ERROR; handler 0 |
| Control exception | ERROR; handler 0 |
| Cross-run | ATTACK overlay/ambient consult must not leak into next defended run |
| Valid delegation + MCP DENY | handler 0 |
| LLM not consulted | security tests must not call Ollama |

---

## Workshop flow (later; not 7B)

Same ten steps as other MCP labs **when** a workshop is built. Not this phase.

DETECT: DET-MCP-001 remains DENY-then-start for **CTRL-MCP-001**. Preferred ATTACK B has **no** MCP DENY. Do not create DET-MCP-006. Do not write SPL.

## Explicit non-goals (remain)

- Splunk validation / new SPL
- DET-MCP-001 edits
- DET-MCP-006
- Dashboard Studio
- Phase 7C
- Cisco products
- General IAM / OAuth token exchange / DID
- Network A2A
- Prompt-injection confused-deputy theater
- Global grant mutation
