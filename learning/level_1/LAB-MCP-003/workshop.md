# LAB-MCP-003 workshop

**Lab:** Scope escalation in MCP tool authorization  
**Saved search:** `DET-MCP-001` is packaged **disabled**. No DET-MCP-003. No notable event.  
**Do** open Dashboard Studio workshop `ws_lab_mcp_003` (AgentSec app). Reuse Phase 4C-validated Q-MCP searches from `../LAB-MCP-001/searches/`. The dashboard binds `__RUN_ID__` as `"$token$"`.

Facts in this file come from Phase 4B and 4C only. The Studio page does not create new evidence.

Flow:

LEARN → BASELINE → ATTACK → OBSERVE → HUNT → DETECT → DEFEND → RETEST → COMPARE → PROVE

Studio tabs use the same names. How to operate the view: `dashboard.md`.

Runtime handler count is authoritative proof of non-execution. Splunk absence of `mcp.started` is corroboration only.

LAB-MCP-001: May this agent call this **tool**?  
LAB-MCP-003: May this agent call this tool **at this requested scope**?

The tool is authorized. The excessive scope is not.

---

## LEARN

**What is it?** A guided lab: granted `lookup_policy` at `policy:read`, the same tool at catalog-valid ungranted `policy:restricted:read` in `vulnerable` then `defended`, plus unknown `policy:write` as ERROR.

**Why it exists?** LAB-MCP-001 taught registered ≠ granted for **tool names**. This lab is the next sentence: granted tool ≠ granted at every **scope** the tool can name.

**How it sits in AgentSec:** After 4B runtime and 4C Splunk. Phase 4D is the Studio view `ws_lab_mcp_003`. No MCP-004.

**Catalog vs grant:**

| Token | Catalog | Agent grant | State |
|-------|---------|-------------|-------|
| `policy:read` | yes | yes | granted |
| `policy:restricted:read` | yes | no | known but ungranted |
| `policy:write` | no | n/a | unknown |

Colons are opaque labels. No hierarchy, wildcard, or prefix matching.

**Path:** request → tool exists? → tool granted? → requested scope valid? → requested scope granted? → args valid? → ALLOW → handler.

Scope authorization happens **before** handler execution.

**SPL this step:** none.

---

## BASELINE

**Action:** `POST /mcp/invoke` with tool `lookup_policy`, arguments `{policy_id: lending-basics}`, scope `policy:read`, profile `defended`.

**Expected:** `testbed.mode=BASELINE`, ALLOW `tool_granted`, requested=allowed=`policy:read`, then separately `mcp.started` / `mcp.completed`, runtime handler count **1**.

**Validated reference:** `5b089682-1d5a-49a7-ac43-967265fd6bc6` (local 7 = Splunk 7).

**SPL:** Q-MCP-AUTHZ, Q-MCP-SCOPE, Q-MCP-TOOL, Q-MCP-EXECUTED.

ALLOW is not execution. The control row has `executed=false`. Runtime handler count is authoritative. Indexed `mcp.started` corroborates a begun handler on a complete copy.

---

## ATTACK

**Action:** same granted tool, same arguments, requested_scope `policy:restricted:read`. Profile `vulnerable`.

The tool is granted. The scope is known to the catalog and **not granted** to the agent. Vulnerable profile intentionally fails open.

**Expected:** ALLOW `vulnerable_profile_fail_open:scope_not_granted`. `allowed_scope` remains `policy:read`. Handler begins. `mcp.completed`. Handler count **1**.

The grant did **not** change.

**Validated reference:** `b466ad12-72ec-44b7-be28-aacfaf2c25b1`.

**SPL this step:** Q-MCP-AUTHZ, Q-MCP-SCOPE, Q-MCP-TOOL, Q-MCP-EXECUTED on the ATTACK token.

---

## OBSERVE

Use Hunt `run.id` (defaults to BASELINE). Do not hide ordering.

You must see `agentsec.control.decision` **before** `agentsec.mcp.started` when execution occurred.

Minimum fields: `run.id`, `sequence`, `event.name`, tool, requested_scope, allowed_scope, decision, reason, attempted, executed, outcome.

**SPL:** observe sequence table, Q-MCP-AUTHZ, Q-MCP-SCOPE.

Zero Q-MCP-TOOL rows does not automatically mean DENY.

---

## HUNT

**Question:** what was decided, what scope was requested vs coded, did execution begin?

**SPL:** Q-MCP-AUTHZ, Q-MCP-SCOPE, Q-MCP-TOOL, Q-MCP-EXECUTED.

Do not create duplicate scope searches. Do not hunt `session.id`.

If Splunk is empty, check `artifacts/<run-id>/export.json`. Do not conclude DENY.

---

## DETECT

**HUNT** asks whether the violation occurred in this copy.

**SPL:** `Q-MCP-AFTER-DENY` on Hunt `run.id`. LIVE MCP-003 specimens: **0** rows. Zero rows means no indexed violation was found. It does not independently prove the handler never executed.

**DETECTION** continuously checks the same invariant.

**Saved search:** `DET-MCP-001`. It does not care whether DENY was `tool_not_granted` or `scope_not_granted`. Packaged **disabled**. This workshop dashboard does not enable it. It did **not** fire on the validated LIVE MCP-003 runs. Do not create DET-MCP-003.

Invariant: DENY, then later `mcp.started`, same run/tool, start sequence > DENY sequence.

**Positive control:** `DET-MCP-001-SCOPE-POSITIVE-CONTROL` — **SIMULATED** `| makeresults` (DENY `scope_not_granted`, requested `policy:restricted:read`, allowed `policy:read`, then `mcp.started`). Not indexed. Not an AcmeBank run. Not OBSERVED runtime evidence.

---

## DEFEND

CTRL-MCP-001 is a **lab allow-list**, not production IAM.

Tool granted. Requested scope known. Requested scope not granted → **DENY** `scope_not_granted` → handler does not begin. `allowed_scope` remains `policy:read`. The control does not rewrite the grant.

Unknown catalog tokens are **ERROR** `unknown_scope`, not DENY, and not RETEST.

Splunk searches do not move the control.

**SPL this step:** Q-MCP-AUTHZ / Q-MCP-SCOPE on the UNKNOWN token for the teaching panel.

---

## RETEST

Same unauthorized **scope** as ATTACK. Profile `defended`. `testbed.mode=RETEST`.

**Expected:** DENY `scope_not_granted`, `attempted=false`, `executed=false`, `outcome=prevented`, runtime handler count **0**, no `mcp.started`.

**Validated reference:** `f638fd4f-1c4f-4ab6-8d42-4d03a4f3afd5` (local 6 = Splunk 6).

Runtime handler count is authoritative proof of non-execution.

Splunk absence of `mcp.started` is corroboration only.

**SPL:** Q-MCP-AUTHZ, Q-MCP-SCOPE, Q-MCP-TOOL, Q-MCP-EXECUTED on the RETEST token.

---

## COMPARE

```text
BASELINE — granted scope policy:read, ALLOW, handler 1, mcp.completed
    ↓
ATTACK — known-but-ungranted policy:restricted:read, vulnerable fail-open ALLOW, handler 1
    ↓
RETEST — same excessive scope, defended DENY, handler 0, no mcp.started
```

Same tool. Same arguments. Different requested authority.

Handler counts are runtime facts. Splunk tables corroborate the indexed copy.

---

## PROVE

Layers (do not merge):

1. Runtime — handler invocation count
2. Local — `events.jsonl` sequence
3. Export — `export.json` (`splunk.verified=false` until searched)
4. Splunk indexed — complete copy vs local count
5. Search — Q-MCP analytical interpretation
6. Detection — DET-MCP-001: no indexed DENY→execution violation found (not non-execution proof)

Knowledge check: `knowledge-check.md`.
