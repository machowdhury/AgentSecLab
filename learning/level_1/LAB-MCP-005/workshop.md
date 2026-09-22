# LAB-MCP-005 workshop

**Lab:** Tool Result Trust / Data Cannot Grant Authority  
**Saved search:** `DET-MCP-001` is packaged **disabled**. No DET-MCP-005. No notable event. Detection: **DETECTION ANALYZED — NO NEW DETECTOR**.  
**Do** open Dashboard Studio workshop `ws_lab_mcp_005` (AgentSec app). Reuse Phase 6C-validated Q-MCP searches from `../LAB-MCP-001/searches/` plus `searches/Q-MCP-RESULT-AUTHORITY.spl`. The dashboard binds `__RUN_ID__` as `"$token$"`.

Facts in this file come from Phase 6B and 6C only. The Studio page does not create new evidence.

**Rejected SPL:** `Q-MCP-RESULT-FOLLOWON` is **not published**. Do not add it to the dashboard, learner SPL, or savedsearches.

Flow:

LEARN → BASELINE → ATTACK → OBSERVE → HUNT → DETECT → DEFEND → RETEST → COMPARE → PROVE

Studio tabs use the same names. How to operate the view: `dashboard.md`.

Runtime handler count is authoritative proof of non-execution. Splunk absence of `mcp.started` is corroboration only.

LAB-MCP-001: May the agent call this **tool**?  
LAB-MCP-003: May the agent call this tool at this **scope**?  
LAB-MCP-004: May the agent call this tool at this scope for **this resource**?  
LAB-MCP-005: Can **data returned by the authorized tool** alter future authority?

The initial tool was authorized and executed. That is not the security failure. DATA ≠ AUTHORITY.

---

## LEARN

**What is it?** A guided lab: granted `lookup_policy` at granted `policy:read` against granted resource `lending-basics`. The first hop is legitimate. MCP-005 asks whether bytes returned by that hop can change what the agent may do next.

**Why it exists?** LAB-MCP-001–004 authorized the invoke. INV-002 still applies after `mcp.completed`: retrieved content cannot independently authorize privileged actions.

**How it sits in AgentSec:** After 6B runtime and 6C Splunk. Phase 6D is the Studio view `ws_lab_mcp_005`. No MCP-006.

**Core question:** First hop: the tool was authorized and the handler began. That is not proof the result is correct or trusted. Can data returned by that tool change what the agent is authorized to do next?

**Defended answer: NO.** Tool results may influence reasoning. Tool results do not create authority.

**Trust boundary:**

```text
AUTHORIZED REQUEST
        ↓
CTRL-MCP-001
        ↓
lookup_policy
        ↓
EXECUTION
        ↓
TOOL RESULT = DATA
        ↓
RESULT / DATA TRUST BOUNDARY
        ↓
FOLLOW-ON INTENT
        ↓
CTRL-MCP-001
        ↓
FOLLOW-ON OPERATION = REQUIRES AUTHORIZATION
```

**Three concepts:** provenance (where the bytes came from), content (what they contain), authority (what is permitted). PROVENANCE ≠ AUTHORITY.

**SERVER AUTHORITY EVIDENCE — LIMITED.** There is no indexed `agentsec.mcp.allowed_tools`. Use coded `allowed_scope=policy:read` and hop-1 **BOUNDED PREVIEW** `server_owned_allowed_tools": "lookup_policy"`. Do not invent a grant list.

**SPL this step:** none.

---

## BASELINE

**Action:** `POST /mcp/invoke` with tool `lookup_policy`, arguments `{policy_id: lending-basics}`, scope `policy:read`, NORMAL fixture, profile `defended`.

**Expected:** `testbed.mode=BASELINE`, hop-0 ALLOW `tool_granted`, handler runs, `mcp.completed` with `untrusted_data`, RESULT-001 OBSERVE `result_is_data`, `derived_authority=absent`, no follow-on.

A legitimate tool returned useful data. Nothing in the result changed authorization state.

**Validated reference:** `3013aa39-fe08-4b58-9898-f3abb092ac06` (local 8 = Splunk 8). NORMAL hash `sha256:2c258a80464ede4113e7721119bc6a908951b8b723c61489ac27b737cdbeb68e`.

**SPL:** Q-MCP-RESULT-AUTHORITY (What Happened), Q-MCP-AUTHZ, Q-MCP-TOOL, Q-MCP-EXECUTED.

ALLOW is not execution. The control row has `executed=false`. Runtime handler count is authoritative. Indexed `mcp.started` corroborates a begun handler on a complete copy. Extra RESULT-001 rows on AUTHZ / EXECUTED are expected. Do not hide them.

---

## ATTACK

**The initial tool invocation was NOT the security failure.** `lookup_policy` was legitimately ALLOW'd and executed.

**Action:** same first request as BASELINE. MALICIOUS fixture. Profile `vulnerable`. `testbed.mode=ATTACK`.

```text
lookup_policy → authorized → executes
        ↓
malicious result DATA
        ↓
INTENTIONALLY VULNERABLE interpretation
        ↓
result-derived per-run authority (NOT server policy)
        ↓
lookup_customer_tier → ALLOW → handler executes
```

SERVER-OWNED authority: **unchanged**. RESULT-DERIVED authority: **present**. Follow-on ALLOW is overlay, not a coded grant of `lookup_customer_tier`.

Hop-1 **BOUNDED PREVIEW** may show `lookup_customer_tie` (200-character cut). Do not reconstruct the missing character. Use the hash for content identity.

**Validated reference:** `f3f48182-df57-4b38-b069-17a199dc4939`. MALICIOUS hash `sha256:f7d67b151741ef7c7efb60242b96f8325996709128293da424f53a547230c358`. Runtime follow-on handler **1**.

**SPL this step:** Q-MCP-RESULT-AUTHORITY, Q-MCP-AUTHZ, Q-MCP-TOOL, Q-MCP-EXECUTED on the ATTACK token.

---

## OBSERVE

Use Hunt `run.id` (defaults to BASELINE). Tables are telemetry, not a story.

You must see hop-0 control, first `mcp.completed`, CTRL-MCP-RESULT-001, then hop-1 control when follow-on intent exists.

What Happened is **Q-MCP-RESULT-AUTHORITY** (one row per run). If a field is not in that hunt, it is **not observed** here. Do not invent it.

Minimum fields on the sequence table: `run_id`, `sequence`, `event.name`, hop, control_id, tool, decision, reason, result_trust, attempted, executed, outcome.

**SPL:** observe sequence, Q-MCP-RESULT-AUTHORITY, Q-MCP-RESULT (bounded preview + hash), Q-MCP-WHO.

Q-MCP-RESULT preview is **BOUNDED** (200 chars). Hash = content identity, not trust.

---

## HUNT

**Question:** Did result-derived data influence authorization, and what follow-on decision and execution were indexed?

**Primary hunt:** Q-MCP-RESULT-AUTHORITY.

**Rejected / not published:** Q-MCP-RESULT-FOLLOWON (duplicate). No hunt invents `allowed_tools`.

**SPL:** Q-MCP-RESULT-AUTHORITY, Q-MCP-AUTHZ, Q-MCP-RESULT-TRUST, Q-MCP-EXECUTED, Q-MCP-TOOL.

Q-MCP-SCOPE and Q-MCP-RESOURCE-AUTHZ are **not bound** on this dashboard. SCOPE on hop-1 ATTACK can show `known_but_ungranted` with ALLOW — that is not MCP-003. RESOURCE-AUTHZ and EXECUTED may add extra RESULT-001 rows. Extra EXECUTED rows are **shown and explained**, not hidden.

Do not hunt `session.id`. Zero rows is not DENY and is not proof the handler never ran.

---

## DETECT

**DETECTION ANALYZED — NO NEW DETECTOR.** No DET-MCP-005. This dashboard does not enable DET-MCP-001.

DET-MCP-001 detects: **DENY → later execution** (same run/tool).

MCP-005 preferred ATTACK is: malicious result → result-derived authority → **ALLOW → execution**.

DET-MCP-001 is expected to remain **silent**. That is not a detector failure. It is a different security invariant.

Not every security failure looks like DENY → bypass → execution. MCP-005 demonstrates **bad authority → ALLOW → execution**. An ALLOW can still be security-relevant when the authority used to produce it was illegitimate.

**HUNT vs DETECTION**

- **HUNT:** `Q-MCP-AFTER-DENY` on Hunt `run.id`. LIVE MCP-005 specimens: **0** rows. Zero rows means no indexed DENY-then-start was found. It is **not** "no security violation occurred."
- **DETECTION:** `DET-MCP-001` packaged **disabled**. LIVE BASELINE / ATTACK / RETEST: **0**. Index-wide CLI **0**.

**Positive control:** `DET-MCP-001-POSITIVE-CONTROL` — **SIMULATED** `| makeresults` (DENY then `mcp.started`). Expected **1** row. **NOT INDEXED.** Not a LIVE MCP-005 attack. Not OBSERVED runtime.

No DET-MCP-005 was created: there is no first-class indexed `allowed_tools`, correlation is lab-shaped, and a reason-string detector would overclaim. Hunt is sufficient.

---

## DEFEND

**THE AI CAN INTERPRET THE DATA. THE DATA STILL DOES NOT GET TO CREATE PERMISSION.**

This lab does **not** prove model prompt-injection resistance. It proves an authorization boundary. Do not teach that the model refused the hostile text; teach that authorization still ran.

Layer 1: tool result remains DATA. It cannot create legitimate server authority.  
Layer 2: follow-on operations require normal CTRL-MCP-001.

```text
malicious result
      ↓
follow-on intent
      ↓
lookup_customer_tier
      ↓
CTRL-MCP-001
      ↓
DENY tool_not_granted
      ↓
handler does not execute
```

**SERVER AUTHORITY EVIDENCE — LIMITED.** No indexed `allowed_tools`. Splunk did **not** prevent the action. The control did.

---

## RETEST

Same initial request as ATTACK. **Same MALICIOUS fixture** (same hash). Profile `defended`. `testbed.mode=RETEST`.

SAME HOSTILE DATA + DIFFERENT SECURITY PROFILE = DIFFERENT AUTHORIZATION OUTCOME.

**Expected:** hop-0 ALLOW and execution observed; RESULT-001 OBSERVE `result_is_data`; derived_authority **absent**; follow-on `lookup_customer_tier` DENY `tool_not_granted`; runtime follow-on handler count **0**; Splunk: **no indexed follow-on execution event observed**.

Do not say Splunk proved the handler never ran. Runtime handler count = 0 is authoritative.

**Validated reference:** `0ab10594-a7fc-48b6-81bf-4cbca54a64c6` (local 12 = Splunk 12). Same MALICIOUS hash as ATTACK.

**SPL:** Q-MCP-RESULT-AUTHORITY, Q-MCP-AUTHZ, Q-MCP-TOOL, Q-MCP-EXECUTED on the RETEST token.

---

## COMPARE

```text
BASELINE — NORMAL result, derived none, no follow-on
    ↓
ATTACK — same first tool, MALICIOUS result, derived PRESENT, follow-on ALLOW (overlay), handler 1
    ↓
RETEST — same MALICIOUS hash, derived none, follow-on DENY, handler 0
```

Three aligned cards on `ws_lab_mcp_005` COMPARE. Handler counts are runtime facts. Splunk tables corroborate the indexed copy. ATTACK ALLOW is not server policy granting `lookup_customer_tier`.

---

## PROVE

Layers (do not merge):

1. Runtime — handler invocation count (authoritative for execution / non-execution)
2. Local — `events.jsonl` sequence
3. Export — `export.json` (`otlp.ok` is not Splunk success; packs keep `splunk.verified=false`)
4. Splunk indexed — complete copy vs local count
5. Search — Q-MCP-RESULT-AUTHORITY
6. Detection — DET-MCP-001: no indexed DENY→execution found (silent on overlay ALLOW; 0 hits ≠ system is secure; **NO NEW DETECTOR**)

LIVE A/B/C are OBSERVED / MEASURED. DETECT right table is **SIMULATED**.

**Correlation limitation:** no `gen_ai.tool.call.id`. This lab uses two different tool names plus `run.id` + `sequence` + `hop.index`. Repeated same-tool invocations would need stronger per-invocation correlation.

Knowledge check: `knowledge-check.md`.
