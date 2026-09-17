# MCP-006 threat model

**Status:** Phase 7A **DESIGN**.  
**Attack id:** MCP-006 (confused deputy / delegated authority). Emitted on schema **1.4.0**.  
**Lab:** LAB-MCP-006.  
**Primary invariant:** INV-001 (delegated authorization).  
**Control:** CTRL-DELEGATION-001 (new) + CTRL-MCP-001 (reuse).  
**Evidence class:** **DOCUMENTED**.

Does not replace LAB-MCP-001–005. Supersedes the `docs/MCP_LAB_PLAN.md` MCP-006 sketch that treated payload identity spoof as the whole attack.

---

## Asset

**Delegated privileged-but-harmless operation** on the deputy path:

Compliance ambient includes `lookup_customer_tier`. Credit’s **delegated** set does not. The asset is: that ambient tool must not run **for credit** unless delegated authority says so.

## Attacker

Less-privileged **caller agent** (credit), operated by the lab red teamer via the MCP lab runner / HTTP `tool` field.

Cannot set profile, coded grants, caller/deputy ids, or `control.decision` via JSON.

## Trust boundary

`caller → deputy` at **CTRL-DELEGATION-001**, then existing `acmebank.mcp.authorize` (CTRL-MCP-001).

Splunk does not authorize. The LLM does not authorize.

## Attack

Credit asks compliance to `lookup_customer_tier` / `customer:read` / `cust-001`.

Vulnerable: deputy uses **ambient** grant → ALLOW + handler 1.  
Defended: delegated set excludes the tool → DENY `delegated_authority_not_granted` + handler 0.

Not prompt injection. Not MCP-001 “can the policy agent call this tool.” Not MCP-005 result overlay.

## Impact

Unauthorized (still harmless) customer-tier fixture lookup executed through a **legitimate** privileged deputy.

## Defense

Explicit delegated authorization + server-owned identity + unchanged downstream MCP-001–004 + MCP-005 result still data.

## Evidence

Delegation decision, authority source, caller id, deputy id, tool, execution flags, handler count.

## Invariants

| ID | How MCP-006 uses it |
|----|---------------------|
| **INV-001** | Primary. Deputy must spend **delegated** authority, not ambient. |
| **INV-004** | Privileged invoke attributed to principal + caller + deputy. |
| **INV-005** | Caller/deputy ids server-owned; content cannot overwrite them. |
| **INV-006** | Ticket binds operation; no silent tool/identity swap after ALLOW. |
| **INV-007** | Sequence reconstructible: delegation decision → MCP-001 → maybe execute. |
| **INV-008** | Missing/malformed/unknown context → ERROR or DENY, never ambient ALLOW. |
| INV-002 | Unchanged. Results still cannot grant. Not this lab’s variable. |

No new invariant.

## Abuse cases (design)

| # | Case | Expected (defended) |
|---|------|---------------------|
| 1 | Legitimate delegation (`lookup_policy`) | ALLOW, handler 1 |
| 2 | Caller asks unauthorized op (`lookup_customer_tier`) | DENY `delegated_authority_not_granted`, handler 0 |
| 3 | Caller spoofs privileged identity in JSON | Extra-field / schema ERROR; not ATTACK success |
| 4 | Caller claims fake delegated grant fields | Extra-field reject |
| 5–7 | Inject `allowed_tools` / scope / resource grant | Extra-field reject |
| 8 | Caller selects deputy id in JSON | Extra-field reject |
| 9 | Unknown caller (coded id not in catalog) | ERROR `unknown_caller`, handler 0 |
| 10 | Unknown deputy | ERROR `unknown_deputy`, handler 0 |
| 11 | Missing delegator/caller context | ERROR `missing_delegation_context`, handler 0 |
| 12 | Malformed delegation object | ERROR `malformed_delegation`, handler 0 |
| 13 | Duplicate JSON keys | Existing HTTP-boundary reject; no control.decision |
| 14 | Delegation-control exception | ERROR `delegation_control_error`, handler 0 |
| 15 | Valid delegation, then MCP-001 DENY (e.g. bad scope) | Delegation ALLOW, MCP DENY, handler 0 |
| 16 | Valid delegation + MCP ALLOW + handler failure | `mcp.failed`; not prevention |
| 17 | Repeated delegation same run | Correlation gap (`gen_ai.tool.call.id` still absent); one invoke per run in canonical specimens |
| 18 | Cross-run leakage | ATTACK then new RETEST: grants unchanged; handler 0 |

## Non-goals

Cisco products, RAG, memory, MLTK, real A2A network, DID/passport, global privilege-creep sets, prompt-string detection.
