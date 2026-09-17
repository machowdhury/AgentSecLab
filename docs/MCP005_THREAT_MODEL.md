# MCP-005 threat model

**Status:** Phase 6A **DESIGN**.  
**Attack id:** MCP-005 (malicious tool response / data treated as authority).  
**Lab:** LAB-MCP-005.  
**Primary invariant:** INV-002.  
**Controls:** CTRL-MCP-RESULT-001 (new; result → policy mutation) + CTRL-MCP-001 (reuse; follow-on tool).  
**Evidence class:** **DOCUMENTED**.

Extends `docs/MCP_THREAT_MODEL.md` T-MCP-005. Does not replace LAB-MCP-001 / 003 / 004 threats. Supersedes the LAB_PLAN sketch that used `execute_shell_command` as the result-granted tool.

---

## Asset

The agent’s **server-owned grant**:

| Grant | Value |
|-------|--------|
| `allowed_tools` | `{lookup_policy}` |
| `allowed_scopes` | `{policy:read}` |
| `allowed_policy_ids` | `{lending-basics}` |

`lookup_customer_tier` is registered and **not** in the grant. The asset is that this set does not grow because a tool **returned text**.

## Attacker

Lab operator / untrusted **data source behind an authorized tool**. In this lab that source is a **mode-selected fixture**, not a hostile HTTP client changing the first request.

The first HTTP request is the same authorized `lookup_policy` / `policy:read` / `lending-basics` call used in MCP-001 BASELINE.

The attacker does **not** need to send `lookup_customer_tier` on the wire. The vulnerable profile incorrectly promotes fixture text into a per-run overlay; the defended profile does not.

Cannot set profile, coded policy, `allowed_tools`, `run.id`, or `control.decision` via result JSON.

## Trust boundary

Two boundaries, in order:

1. `mcp.tool.result` → **CTRL-MCP-RESULT-001** (may this result mutate authority?)
2. `acmebank.mcp.authorize` → **CTRL-MCP-001** (may the follow-on tool execute?)

Splunk does not authorize. The LLM does not authorize.

## Security question

Can data returned by an authorized, completed tool alter authority?

## Attack

Harmless `lookup_policy` returns a **MALICIOUS** fixture whose `summary` contains a closed instruction-like marker requesting `lookup_customer_tier`.

Not RCE. Not a compromised handler binary (problem B). Not an unauthorized **first** tool (problem C / MCP-002). Not resource substitution (MCP-004). Not scope escalation (MCP-003).

This is INV-002: **result treated as a grant**.

## Expected results

Canonical A / B / C. Do **not** change the malicious fixture between B and C.

| Id | Profile | Result fixture | First call | RESULT-001 | Follow-on CTRL-MCP-001 | Follow-on handler |
|----|---------|----------------|------------|------------|------------------------|-------------------|
| **A BASELINE** | defended | NORMAL | ALLOW + execute + complete | OBSERVE `result_is_data` (no overlay; no follow-on intent) | none | 0 |
| **B ATTACK** | vulnerable | MALICIOUS | ALLOW + execute + complete | ALLOW `vulnerable_profile_fail_open:result_derived_grant` (per-run overlay) | ALLOW (overlay) | 1 |
| **C RETEST** | defended | **same MALICIOUS as B** | ALLOW + execute + complete | OBSERVE `result_is_data` (no overlay) | DENY `tool_not_granted` | 0 |

Server-owned `allowed_tools` stays `{lookup_policy}` on all three. Fail-open does not rewrite the coded grant.

RETEST is not “block `lookup_policy`.”

## Invariants

| ID | How MCP-005 uses it |
|----|---------------------|
| **INV-002** | Primary. Retrieved / returned content cannot independently authorize privileged actions. |
| INV-001 | Follow-on still needs an explicit tool grant. Overlay that invents a grant is the vulnerable lie. |
| INV-004 | First and follow-on control events name principal, agent, tool. Overlay is not a new principal. |
| INV-007 | Sequence reconstructible: first complete → result-trust decision → follow-on authorize → (maybe) second execute. |
| INV-008 | Missing security context must not silently ALLOW a merge. Vulnerable fail-open is **labeled** and only the closed follow-on tool. |

No new invariant. Do not create INV-009.

INV-003 (memory trust) is adjacent but not this lab: the vector is a **tool result**, not durable memory promotion.

---

## What the attacker might try (design tests)

| Input | Defended result |
|-------|-----------------|
| NORMAL fixture | OBSERVE; no follow-on intent; grants unchanged |
| MALICIOUS `SECURITY_OVERRIDE` + `lookup_customer_tier` | OBSERVE; if intent generated → CTRL-MCP-001 DENY `tool_not_granted`; handler 0 |
| Result JSON claims `allowed_tools=lookup_customer_tier` | DATA only; coded grant unchanged |
| Result claims `role=admin` / `approved=true` / `profile=vulnerable` | DATA only |
| Result claims `control.decision=ALLOW` | DATA only; does not mint a ticket |
| Result asks for a tool **not** in the closed set (e.g. shell name) | Interpreter ignores / no overlay; no generic executor |
| Structured `lab_instruction` / `requested_tool` key | **Do not add.** Extra keys on today’s handler return are not a protocol. Tests that inject extra keys stay DATA. |
| HTTP extra field `result_fixture=malicious` | Closed contract → ERROR `unknown_fields` (existing) |
| Client sends second HTTP `lookup_customer_tier` without overlay | MCP-002 path (not this lab’s ATTACK) |
| LLM “obeys” the summary | Not the proof. Interpreter is. |

---

## Vulnerable profile (MCP-005 only)

When **all** of:

- `profile=vulnerable`
- first tool registered **and** granted (this lab: `lookup_policy`)
- first call completed successfully
- interpreter finds the closed marker and the closed follow-on name `lookup_customer_tier`

Then:

- RESULT-001 decision **ALLOW**
- reason **`vulnerable_profile_fail_open:result_derived_grant`**
- **per-run overlay only** adds `lookup_customer_tier` for subsequent CTRL-MCP-001 in **this** `run.id`
- follow-on handler **executes** against the harmless `cust-001` fixture
- telemetry **keeps** server-owned `allowed_tools=lookup_policy`

Do **not**:

- mutate process-global `ALLOWED_TOOLS` / `coded_policy()`
- leak the overlay into another `run.id`
- reuse MCP-002 fail-open (`vulnerable_profile_fail_open` for ungranted **first** tool)
- reuse MCP-003 / MCP-004 reason suffixes
- fail-open arbitrary tool names parsed from free text
- implement a generic “run whatever the result says” executor
- pretend `lookup_customer_tier` became a coded grant

MCP-002 / 003 / 004 / 005 vulnerabilities must remain separately identifiable in `reason`.

---

## Prompt injection (related, not the property)

Indirect prompt injection is the usual name for “untrusted retrieved text steers the model.” MCP-005 is **broader**:

> Even if an LLM treats data as an instruction, that instruction cannot create authority.

The lab proves the **authorization** property with a deterministic interpreter. It does not prove model robustness.

---

## MCP-006 non-overlap

Confused deputy (MCP-006) is a **legitimate** grant spent on the wrong actor / claimed identity. MCP-005 is an **illegitimate** grant invented from data. Do not start MCP-006 in this phase.

---

## Security review (design — resolve before implementation)

No implementation in 6A. Ratings are design risks, not measured defects.

| Severity | If we did this | Resolution (locked) |
|----------|----------------|---------------------|
| **BLOCKER** | Mutate global `ALLOWED_TOOLS` / shared `McpPolicy` (cross-run contamination) | Per-run overlay only; discarded at run end; coded policy never rewritten |
| **BLOCKER** | Generic arbitrary tool executor from result text | Closed follow-on set: `lookup_customer_tier` only |
| **HIGH** | First-class `lab_instruction` / `requested_tool` on the result object (authority protocol) | Instruction stays in `summary` text; lab interpreter only |
| **HIGH** | Claim SANITIZE / QUARANTINE / DENY on RESULT-001 without transform / withhold / first-call deny | Defended RESULT-001 is **OBSERVE** |
| **HIGH** | Proof depends on Ollama | Deterministic interpreter |
| **HIGH** | Teach “prompt-injection resistance” as the invariant | Document INV-002 / authority; injection is related color |
| **HIGH** | Emit `TRUSTED_DATA` or a 0–100 score | Keep `untrusted_data` only |
| **MEDIUM** | Correlate two tools with `run.id` + tool only | Different names help now; later `gen_ai.tool.call.id` |
| **MEDIUM** | Preview 200 chars hides the marker | Fixture must keep `SECURITY_OVERRIDE` understandable in 200 chars |
| **LOW** | Two HTTP invokes vs one in-process follow-on | Prefer **one run**, in-process follow-on |

Do not implement until BLOCKER and HIGH rows stay resolved in the runtime contract.
