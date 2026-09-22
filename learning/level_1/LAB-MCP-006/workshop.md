# LAB-MCP-006 workshop

**Lab:** Confused Deputy / Delegated Authority  
**Saved search:** `DET-MCP-001` is packaged **disabled**. No DET-MCP-006. No notable event. Detection: **DETECTION ANALYZED — NO NEW DETECTOR**.  
**Do** open Dashboard Studio workshop `ws_lab_mcp_006` (AgentSec app). Reuse Phase 7C-validated Q-MCP searches from `../LAB-MCP-001/searches/` plus `searches/Q-MCP-DELEGATION.spl`. The dashboard binds `__RUN_ID__` as `"$token$"`.

Facts in this file come from Phase 7A–7C only. The Studio page does not create new evidence.

**Rejected SPL:** `Q-MCP-AMBIENT-USE`, `Q-MCP-DELEGATION-CHAIN`, `Q-MCP-DELEGATION-EXECUTED`, and `Q-MCP-DELEGATION-AUTHORITY` are **not published**. Do not add them to the dashboard, learner SPL, or savedsearches.

Flow:

LEARN → BASELINE → ATTACK → OBSERVE → HUNT → DETECT → DEFEND → RETEST → COMPARE → PROVE

Studio tabs use the same names. How to operate the view: `dashboard.md`.

Runtime handler count is authoritative proof of non-execution. Splunk absence of `mcp.started` is corroboration only.

LAB-MCP-001: Can this agent call this **tool**?  
LAB-MCP-003: Can this agent call the tool at this **scope**?  
LAB-MCP-004: Can this agent operate on this **resource**?  
LAB-MCP-005: Can **tool-result data** widen later authority?  
LAB-MCP-006: Can a **deputy** use authority the **caller** did not delegate?

DEPUTY AUTHORITY ≠ CALLER AUTHORITY. DEPUTY AUTHORITY ≠ DELEGATED AUTHORITY.

---

## LEARN

**What is it?** A guided lab: Credit Agent asks Compliance Agent to perform an MCP tool call. CTRL-DELEGATION-001 checks whether the **caller** actually delegated that operation. CTRL-MCP-001 then checks MCP authorization for the selected policy.

**Why it exists?** LAB-MCP-001–005 authorized the acting agent more and more contextually (tool, scope, resource, result data). INV-001 still applies when one agent acts as deputy for another: an agent cannot receive more authority than was explicitly delegated.

**How it sits in AgentSec:** After 7B runtime and 7C Splunk. Phase 7D is the Studio view `ws_lab_mcp_006`. No MCP-007.

**Core question:** The deputy may possess authority — but did the caller actually delegate that authority for this operation?

**Caller:** the entity requesting an operation (`acme-agent-credit-002`).  
**Deputy:** the agent performing work on behalf of the caller (`acme-agent-compliance-004`).  
**Delegated authority:** what the caller actually authorized the deputy to exercise (runtime: `lookup_policy`).  
**Ambient authority:** authority the deputy possesses independently (runtime: `lookup_policy`, `lookup_customer_tier`).  
**Confused deputy:** the deputy uses its own ambient authority for an operation the caller was not entitled to request.

Not every delegated-agent workflow is a confused-deputy attack. BASELINE is legitimate delegation.

**Trust boundary:**

```text
Caller
   ↓ request
Deputy
   ↓ CTRL-DELEGATION-001
MCP authorize (CTRL-MCP-001)
   ↓ only if allowed
Tool handler
```

**SERVER AUTHORITY EVIDENCE — LIMITED.** There is no indexed `allowed_tools`. Delegated tools `{lookup_policy}` and ambient tools `{lookup_policy, lookup_customer_tier}` are runtime/manifest facts. Indexed `agentsec.delegation.authority.source` is what CTRL-DELEGATION-001 consulted.

**Phase 7C LIVE ids (copy the full UUID):**

- BASELINE `1cf98c4d-1bd8-4df5-be70-b82419e2c2b2`
- ATTACK `d7524a4e-8da6-4171-8867-d2a2168128ac`
- RETEST `50f7ec04-7524-41c0-95a8-3b1ef4d91dc4`

**SPL this step:** none.

---

## BASELINE

**Action:** coded Credit → Compliance invoke for granted `lookup_policy`, scope `policy:read`, resource `lending-basics`, profile `defended`, `testbed.mode=BASELINE`.

**Expected:** CTRL-DELEGATION-001 **ALLOW** `delegation_granted`, `authority.source=delegated`. Downstream CTRL-MCP-001 **ALLOW** `tool_granted`. Handler runs. `mcp.completed`. Terminal `completed_allowed`.

This is legitimate delegation. Execution here does **not** prove authorization by itself — the control row is the authorization evidence.

**Validated reference:** `1cf98c4d-1bd8-4df5-be70-b82419e2c2b2` (local 10 = Splunk 10). Runtime policy handler **1**.

**SPL:** Q-MCP-DELEGATION (What Happened), Q-MCP-AUTHZ, Q-MCP-WHO, Q-MCP-EXECUTED.

ALLOW is not execution. The control row has `executed=false`. Runtime handler count is authoritative. Indexed `mcp.started` corroborates a begun handler on a complete copy. Do not hide extra EXECUTED rows when two control events share a tool.

---

## ATTACK

**The deputy could perform the operation, but that does not mean the caller was authorized to cause it.**

**Action:** same caller and deputy as BASELINE. Request: `lookup_customer_tier` / `customer:read` / `cust-001`. Profile **vulnerable**. `testbed.mode=ATTACK`.

```text
Credit asks Compliance for lookup_customer_tier
        ↓
CTRL-DELEGATION-001 ALLOW
reason = vulnerable_profile_fail_open:ambient_deputy_authority
authority.source = ambient_deputy
        ↓
CTRL-MCP-001 ALLOW tool_granted  (selected ambient policy)
        ↓
handler executes
```

Caller was **not** delegated this tool. Deputy **possesses** it ambiently. Vulnerable path **substitutes** ambient authority. Downstream MCP ALLOW is not caller authorization.

**INTENTIONALLY VULNERABLE LAB BEHAVIOR.**

**Validated reference:** `d7524a4e-8da6-4171-8867-d2a2168128ac` (local 10 = Splunk 10). Runtime tier handler **1**. Request hash `sha256:ea33191fceeb105e47270f6839bb98addfb7245a32534138192b23e1fab9a419`.

**SPL this step:** Q-MCP-DELEGATION, Q-MCP-AUTHZ, Q-MCP-TOOL, Q-MCP-EXECUTED on the ATTACK token.

---

## OBSERVE

Use Hunt `run.id` (defaults to BASELINE). Tables are telemetry, not a story.

Separate cards:

- **IDENTITY** — Q-MCP-WHO (caller hop 0, deputy hop 1 when hop 1 exists)
- **AUTHORITY** — Q-MCP-DELEGATION (`authority.source`, coded delegated SCOPE, requested tool)
- **CONTROL** — Q-MCP-AUTHZ (CTRL-DELEGATION-001 then CTRL-MCP-001)
- **EXECUTION** — Q-MCP-EXECUTED (`has_started`, `execution_state`)

Sequence helper shows hop 0 then hop 1. What Happened is **Q-MCP-DELEGATION**. If a field is not in that hunt, it is **not observed** here. Do not invent `allowed_tools`.

**SERVER AUTHORITY EVIDENCE — LIMITED.** Grant lists are runtime/manifest.

**SPL:** observe sequence, Q-MCP-DELEGATION, Q-MCP-WHO, Q-MCP-AUTHZ, Q-MCP-EXECUTED.

---

## HUNT

**Question:** What did CTRL-DELEGATION-001 decide, for which caller/deputy/tool, which authority source was used, and what downstream MCP / execution were indexed?

**Primary hunt:** Q-MCP-DELEGATION.

**Rejected / not published:** Q-MCP-AMBIENT-USE, Q-MCP-DELEGATION-CHAIN, Q-MCP-DELEGATION-EXECUTED, Q-MCP-DELEGATION-AUTHORITY. No hunt invents `allowed_tools`.

Q-MCP-SCOPE and Q-MCP-RESOURCE-AUTHZ are **not bound** on this dashboard. SCOPE uses equality, not subset. RESOURCE-AUTHZ on ATTACK is `other` (cust-001 vs lending-basics wire) — not the confused-deputy predicate.

Do not hunt `session.id`. Zero rows is not DENY and is not proof the handler never ran.

**SPL:** Q-MCP-DELEGATION, Q-MCP-WHO, Q-MCP-AUTHZ, Q-MCP-EXECUTED, Q-MCP-TOOL.

---

## DETECT

**DETECTION ANALYZED — NO NEW DETECTOR.** No DET-MCP-006. This dashboard does not enable DET-MCP-001.

DET-MCP-001 detects: **DENY → later execution** (same run/tool).

MCP-006 preferred ATTACK is: insufficient delegated authority → vulnerable **ALLOW → execution**.

DET-MCP-001 is expected to remain **silent**. That is not a detector failure. It is a different security invariant.

Huntable evidence is not the same as a reliable detection predicate. `authority.source=ambient_deputy` is indexed, but delegated **tool** membership is not. An enum-only notable would overclaim.

**HUNT vs DETECTION**

- **HUNT:** `Q-MCP-AFTER-DENY` on Hunt `run.id`. LIVE MCP-006 specimens: **0** rows. Zero rows means no indexed DENY-then-start was found. It is **not** "the attack did not occur."
- **DETECTION:** `DET-MCP-001` packaged **disabled**. LIVE BASELINE / ATTACK / RETEST: **0**.

**Positive control:** `DET-MCP-001-POSITIVE-CONTROL` — **SIMULATED** `| makeresults` (DENY then `mcp.started`). Expected **1** row. **NOT INDEXED.** Not a LIVE MCP-006 attack. Not OBSERVED runtime.

No DET-MCP-006 was created: there is no first-class indexed `allowed_tools`, BASELINE deputy also possesses ambient `lookup_policy` with source=`delegated`, and a reason-string detector would be a lab-label detector. Hunt is sufficient.

---

## DEFEND

**THE DEPUTY MAY BE ALLOWED TO CALL THE TOOL. THE CALLER STILL MUST BE ALLOWED TO ASK.**

CTRL-DELEGATION-001 evaluates delegated authority.  
CTRL-MCP-001 evaluates MCP authorization.  
These controls solve related but different authorization problems.

```text
Caller
  ↓
Deputy
  ↓
CTRL-DELEGATION-001
  ↓ only if ALLOW
CTRL-MCP-001
  ↓ only if ALLOW
Tool handler
```

Defended RETEST: CTRL-DELEGATION-001 **DENY** `delegated_authority_not_granted`. Downstream MCP does not begin. Splunk did **not** prevent the action. The control did.

**SERVER AUTHORITY EVIDENCE — LIMITED.** No indexed `allowed_tools`.

---

## RETEST

Same security request as ATTACK. Same caller, deputy, tool, scope, resource, arguments hash. Profile **defended**. `testbed.mode=RETEST`.

SAME REQUEST + DIFFERENT SECURITY PROFILE = DIFFERENT AUTHORIZATION OUTCOME.

- CTRL-DELEGATION-001: **DENY** `delegated_authority_not_granted`
- authority.source: `delegated` (consulted the delegated set; tool not granted)
- downstream MCP: **none** (`no_downstream_mcp_control_event`)
- runtime handler count: **0** (authoritative)
- Splunk: **no indexed MCP execution-start event observed** (corroboration only)
- deputy on hop 1: `deputy_not_on_indexed_hop1` — hop 1 never started; runtime/manifest still name `acme-agent-compliance-004`

Do not say Splunk proved the handler never ran. Do not treat an empty TOOL table as DENY by itself.

**Validated reference:** `50f7ec04-7524-41c0-95a8-3b1ef4d91dc4` (local 6 = Splunk 6). Same request hash as ATTACK.

**SPL:** Q-MCP-DELEGATION, Q-MCP-AUTHZ, Q-MCP-TOOL, Q-MCP-EXECUTED on the RETEST token.

---

## COMPARE

```text
BASELINE — delegated lookup_policy, source delegated, ALLOW, handler 1
    ↓
ATTACK — same caller/deputy, lookup_customer_tier, source ambient_deputy, fail-open ALLOW, handler 1
    ↓
RETEST — same request as ATTACK, source delegated, DENY, handler 0
```

Three aligned cards on `ws_lab_mcp_006` COMPARE. Handler counts are runtime facts. Splunk tables on BASELINE / ATTACK / RETEST corroborate the indexed copy. ATTACK MCP ALLOW is not caller grant of `lookup_customer_tier`. COMPARE uses markdown cards rather than three copies of the 18-column hunt.

---

## PROVE

Layers (do not merge):

1. Runtime — handler invocation count (authoritative for execution / non-execution)
2. Local — `events.jsonl` sequence
3. Export — `export.json` (`otlp.ok` is not Splunk success; packs keep `splunk.verified=false`)
4. Splunk indexed — complete copy vs local count
5. Search — Q-MCP-DELEGATION
6. Detection — DET-MCP-001: no indexed DENY→execution found (silent on vulnerable ALLOW; 0 hits ≠ system is secure; **NO NEW DETECTOR**)

LIVE A/B/C are OBSERVED / MEASURED. DETECT right table is **SIMULATED**.

**Correlation limitation:** no `gen_ai.tool.call.id`. This lab is one operation per run. Repeated same-tool calls would need stronger per-invocation correlation.

Knowledge check: `knowledge-check.md`.
