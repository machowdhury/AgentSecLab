# LAB-MCP-001 workshop

**Lab:** MCP tool authorization  
**Saved search:** `DET-MCP-001` (`AgentSec - MCP Execution After Authorization Deny`) is packaged **disabled**. No notable event. No MCP-003+.  
**Do** open Dashboard Studio workshop `ws_lab_mcp_001` (AgentSec app). Reuse Phase 3C searches in `searches/`. The dashboard binds `__RUN_ID__` as `"$token$"`. You may still run the same `.spl` files in Search.

Facts in this file come from Phase 3B and 3C only. The Studio page does not create new evidence.

Flow:

LEARN → BASELINE → ATTACK → OBSERVE → HUNT → DETECT → DEFEND → RETEST → COMPARE → PROVE

Studio tabs use the same names. How to operate the view: `dashboard.md`.

Runtime handler count is authoritative proof of non-execution. Splunk absence of `mcp.started` is corroboration only.

---

## LEARN

**What is it?** A guided lab: one granted `lookup_policy` call, one known-ungranted `lookup_customer_tier` call in `vulnerable`, the same unauthorized call in `defended`, and Q-MCP investigation questions in Splunk.

**Why it exists?** You already saw untrusted text stopped before the LLM. Tools are a different dangerous operation: running a named handler. If the control runs after the handler, DENY is a lie.

**How it sits in AgentSec:** After runtime (3B) and validated Splunk hunts (3C). Phase 3D is the one Studio view `ws_lab_mcp_001`. Still no detections. No MCP-003+.

**Trust path:** User → MCP Policy Agent `acme-agent-mcp-001` → MCP Client → CTRL-MCP-001 → MCP Server → Tool Handler → Result (`untrusted_data`) → OTel → Splunk.

Transport is **in-process JSON-RPC `tools/call`**. Real authorize-then-execute. Not a full remote MCP product.

**Authorization vs execution:** `agentsec.control.decision` is the decision. `mcp.started` is when the handler began. ALLOW is not execution.

**Registry vs grant:** registered + granted → ALLOW. registered + not granted → DENY. not registered → ERROR.

**What the attacker controls:** `tool`, `arguments`, `requested_scope`, `user_id`. Not profile, allow-list, `run.id`, or the decision.

**SPL this step:** none.

---

## BASELINE

**Action:** `POST /mcp/invoke` with tool `lookup_policy`, arguments `{policy_id: lending-basics}`, scope `policy:read`, profile `defended`.

**Expected:** `testbed.mode=BASELINE`, ALLOW `tool_granted`, `mcp.started`, `mcp.completed`, runtime handler count **1**.

**Validated reference:** `163d11e2-e751-4282-9406-19b490542ed4` (local 7 = Splunk 7).

**SPL:** Q-MCP-AUTHZ, Q-MCP-TOOL, Q-MCP-EXECUTED (and the What Happened summary of those indexed fields).

ALLOW is not execution. The control row has `executed=false`. Runtime handler count is authoritative. Indexed `mcp.started` corroborates a begun handler on a complete copy.

**Why it was allowed:** the tool is registered and granted.

---

## ATTACK

**Action:** Open Attack Service Tool Authorization, predict, then Launch ATTACK (LIVE). Same agent requests `lookup_customer_tier` with scope `customer:read`. Profile is server-owned `vulnerable` ExperimentContext. The browser does not send tool, scope, grants, or profile.

The tool is **registered** and **not granted**. This is unauthorized invocation, not a claim that the tool is malware. Controlled lab authorization failure; not a production exploit.

**Expected:** labeled ALLOW `vulnerable_profile_fail_open:CTRL-MCP-001…`, handler begins, `mcp.completed`, handler count **1**. Fresh `run.id`.

**Validated REPLAY reference:** `5e8f55f3-eb46-47ee-b979-b72d9c9b1f49`. Fresh LIVE ids are not this UUID.

**SPL this step:** Path A in Search with the fresh run.id, or Q-MCP-AUTHZ / Q-MCP-EXECUTED on the ATTACK token. Predict before you launch.

---

## OBSERVE

Use Hunt `run.id` (defaults to BASELINE). Do not hide ordering.

You must see `agentsec.control.decision` **before** `agentsec.mcp.started` when execution occurred.

Minimum fields: `run.id`, `sequence`, `event.name`, tool, decision, reason, attempted, executed, outcome.

**SPL:** observe sequence table (same event.name filter as Q-MCP-EXECUTED, rows not collapsed), Q-MCP-AUTHZ, Q-MCP-TOOL.

Zero Q-MCP-TOOL rows does not automatically mean DENY.

---

## HUNT

**Question:** which principal/agent requested which tool, what was decided, what scope was requested vs granted, did execution begin, what result metadata exists?

**SPL:** Q-MCP-WHO, Q-MCP-SCOPE, Q-MCP-PARAMS, Q-MCP-EXECUTED, Q-MCP-RESULT, Q-MCP-RESULT-TRUST.

Do not hunt `session.id`. Preview+hash only for parameters. Results are `untrusted_data` when completed.

If Splunk is empty, check `artifacts/<run-id>/export.json`. Do not conclude DENY.

---

## DETECT

**HUNT** asks whether the violation occurred in this copy.

**SPL:** `Q-MCP-AFTER-DENY` on Hunt `run.id`. Validated LIVE specimens: **0** rows. Zero rows means no indexed violation was found. It does not independently prove the handler never executed.

**DETECTION** continuously checks the same invariant.

**Saved search:** `AgentSec - MCP Execution After Authorization Deny` (`DET-MCP-001`). Severity **HIGH**. Packaged **disabled**. This workshop dashboard does not enable it. It did **not** fire on the validated LIVE runs.

Invariant: DENY, then later `mcp.started`, same run/tool, start sequence > DENY sequence.

DENY alone is not an alert. ALLOW (including labeled fail-open) is not this detection. `mcp.failed` after ALLOW is not DENY-then-start. ERROR is not DENY. Splunk detects a copy of a violation; it does not enforce authorization.

**Positive control:** `DET-MCP-001-POSITIVE-CONTROL` — **SIMULATED** `| makeresults` (DENY seq 3, `mcp.started` seq 4). Not indexed. Not an AcmeBank run. Not OBSERVED runtime evidence. Hunt fixture `Q-MCP-AFTER-DENY-POSITIVE-CONTROL` remains SIMULATED in `searches/`.

---

## DEFEND

CTRL-MCP-001 is a **lab allow-list**, not production IAM.

Server-owned policy. Tool registry. Grant check. Scope comparison. Control **before** handler. Fail closed for unknown tools and control-evaluation failures.

`defended` → DENY on known-ungranted. `vulnerable` → labeled fail-open ALLOW for that known-ungranted tool only. Unknown stays ERROR.

Splunk searches do not move the control.

**SPL this step:** none.

---

## RETEST

Same unauthorized request as ATTACK. Launch RETEST (LIVE) on Attack Service. Profile is server-owned `defended`. `testbed.mode=RETEST`. The request bytes do not change.

**Expected:** DENY `tool_not_granted`, `attempted=false`, `executed=false`, `outcome=prevented`, runtime handler count **0**, no `mcp.started`. Fresh `run.id` different from ATTACK.

**Validated REPLAY reference:** `7a1d37b5-d589-4dfd-8322-25ebd0152dbc` (local 6 = Splunk 6).

Runtime handler count is authoritative proof of non-execution.

Splunk absence of `mcp.started` is corroboration only.

**SPL:** Path A on the fresh RETEST run.id, or Q-MCP-AUTHZ, Q-MCP-TOOL, Q-MCP-EXECUTED on the RETEST token.

---

## COMPARE

```text
BASELINE — granted lookup_policy, ALLOW, handler 1, mcp.completed
    ↓
ATTACK — known-ungranted lookup_customer_tier, vulnerable fail-open ALLOW, handler 1
    ↓
RETEST — same ungranted tool, defended DENY, handler 0, no mcp.started
```

Same known-ungranted request: vulnerable → labeled fail-open ALLOW → executes. Defended → DENY → does not execute.

Handler counts are runtime facts. Splunk tables corroborate the indexed copy.

---

## PROVE

Layers (do not merge):

1. Runtime — handler invocation count
2. Local — `events.jsonl` sequence
3. OTLP export — `export.json` (`splunk.verified=false` until searched)
4. Splunk indexed — complete copy vs local count
5. SPL query result — analytical interpretation

Knowledge check: `knowledge-check.md`.
