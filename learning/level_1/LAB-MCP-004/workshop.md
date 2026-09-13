# LAB-MCP-004 workshop

**Lab:** Parameter and Resource Authorization  
**Saved search:** `DET-MCP-001` is packaged **disabled**. No DET-MCP-004. No notable event.  
**Do** open Dashboard Studio workshop `ws_lab_mcp_004` (AgentSec app). Reuse Phase 5C-validated Q-MCP searches from `../LAB-MCP-001/searches/` plus `searches/Q-MCP-RESOURCE-AUTHZ.spl`. The dashboard binds `__RUN_ID__` as `"$token$"`.

Facts in this file come from Phase 5B and 5C only. The Studio page does not create new evidence.

Flow:

LEARN → BASELINE → ATTACK → OBSERVE → HUNT → DETECT → DEFEND → RETEST → COMPARE → PROVE

Studio tabs use the same names. How to operate the view: `dashboard.md`.

Runtime handler count is authoritative proof of non-execution. Splunk absence of `mcp.started` is corroboration only.

LAB-MCP-001: May the agent call this **tool**?  
LAB-MCP-003: May the agent call this tool at this **scope**?  
LAB-MCP-004: May the agent call this tool at this scope for **this resource**?

The tool is authorized. The scope is authorized. The excessive resource is not.

---

## LEARN

**What is it?** A guided lab: granted `lookup_policy` at granted `policy:read` against granted resource `lending-basics`, the same tool and scope against catalog-valid ungranted `executive-restricted` in `vulnerable` then `defended`, plus unknown `does-not-exist` as ERROR.

**Why it exists?** LAB-MCP-001 taught registered ≠ granted for **tool names**. LAB-MCP-003 taught granted tool ≠ granted at every **scope**. This lab is the next sentence: granted tool + granted scope ≠ granted against every **resource** that tool can name.

**How it sits in AgentSec:** After 5B runtime and 5C Splunk. Phase 5D is the Studio view `ws_lab_mcp_004`. No MCP-005.

**Catalog vs grant:**

| Resource | Catalog | Agent grant | State |
|----------|---------|-------------|-------|
| `lending-basics` | yes | yes | granted |
| `executive-restricted` | yes | no | known but ungranted |
| `does-not-exist` | no | n/a | unknown |

Do not determine known-vs-unknown from grant-set membership alone. Use the control reason.

**Path:** request → tool exists? → tool granted? → scope valid? → scope granted? → arguments structurally valid? → resource exists? → resource granted? → ALLOW ticket → handler.

Arguments identify the requested resource. Arguments do not grant authority.

**AllowTicket:** validated resource → `ticket.resource_id` → handler uses the exact authorized resource. The request must not be changeable after authorization so a different resource is executed.

**Duplicate JSON keys:** rejected at the HTTP boundary. Phase 5C `ffafb62e-a6c6-42c0-837d-094cbfb3f795` is `run.failed` `duplicate_json_keys` with **no** CTRL-MCP-001 event. Do not invent control telemetry for that copy.

**SPL this step:** none.

---

## BASELINE

**Action:** `POST /mcp/invoke` with tool `lookup_policy`, arguments `{policy_id: lending-basics}`, scope `policy:read`, profile `defended`.

**Expected:** `testbed.mode=BASELINE`, ALLOW `tool_granted`, `resource.id=lending-basics`, `allowed_resource.ids=lending-basics`, resource relation **granted**, then separately `mcp.started` / `mcp.completed`, runtime handler count **1**.

**Validated reference:** `fb50dcaf-8e84-4a3f-a55b-997c72edbd04` (local 7 = Splunk 7).

**SPL:** Q-MCP-AUTHZ, Q-MCP-RESOURCE-AUTHZ, Q-MCP-TOOL, Q-MCP-EXECUTED.

ALLOW is not execution. The control row has `executed=false`. Execution is `mcp.started`.

---

## ATTACK

**Action:** same granted tool, same granted scope, arguments `{policy_id: executive-restricted}`. Profile `vulnerable`.

The tool is granted. The scope is granted. The resource is known to the catalog and **not granted** to the agent. Vulnerable profile intentionally fails open.

**Expected:** ALLOW `vulnerable_profile_fail_open:resource_not_granted`. `allowed_resource.ids` remains `lending-basics`. Resource relation **known_but_ungranted**. Handler begins. `mcp.completed`. Handler count **1**.

The resource was **not** granted. The grant did **not** change. Do not label this resource authorized, resource granted, or grant widened.

**Validated reference:** `5ab59fc7-303e-4eea-84e7-ae0b2f405146`.

**SPL this step:** Q-MCP-AUTHZ, Q-MCP-RESOURCE-AUTHZ, Q-MCP-TOOL, Q-MCP-EXECUTED on the ATTACK token.

Q-MCP-SCOPE on this run is still `granted` because requested_scope remains `policy:read`. That is why the resource hunt exists.

---

## OBSERVE

Use Hunt `run.id` (defaults to BASELINE). Do not hide ordering.

You must see `agentsec.control.decision` **before** `agentsec.mcp.started` when execution occurred.

Minimum fields: `run.id`, `sequence`, `event.name`, tool, requested_scope, allowed_scope, resource.id, allowed_resource.ids, decision, reason, attempted, executed, outcome.

**SPL:** observe sequence table, Q-MCP-AUTHZ, Q-MCP-RESOURCE-AUTHZ.

Zero Q-MCP-TOOL rows does not automatically mean DENY.

---

## HUNT

**Question:** what was decided, what resource was requested vs coded, did execution begin?

**Primary hunt:** Q-MCP-RESOURCE-AUTHZ.

**SPL:** Q-MCP-AUTHZ, Q-MCP-SCOPE, Q-MCP-RESOURCE-AUTHZ, Q-MCP-TOOL, Q-MCP-EXECUTED.

Do not create duplicate resource searches. Do not hunt `session.id`.

If Splunk is empty, check `artifacts/<run-id>/export.json`. Do not conclude DENY.

---

## DETECT

**HUNT** asks whether the violation occurred in this copy.

**SPL:** `Q-MCP-AFTER-DENY` on Hunt `run.id`. LIVE MCP-004 specimens: **0** rows. Zero rows means no indexed violation was found. It does not independently prove the handler never executed.

**DETECTION** continuously checks the same invariant.

**Saved search:** `DET-MCP-001`. It does not care whether DENY was `tool_not_granted`, `scope_not_granted`, or `resource_not_granted`. Packaged **disabled**. This workshop dashboard does not enable it. It did **not** fire on the validated LIVE MCP-004 runs. Do not create DET-MCP-004.

Invariant: DENY, then later `mcp.started`, same run/tool, start sequence > DENY sequence.

**Positive control:** `DET-MCP-001-RESOURCE-POSITIVE-CONTROL` — **SIMULATED** `| makeresults` (DENY `resource_not_granted`, resource.id `executive-restricted`, allowed_resource.ids `lending-basics`, then `mcp.started`). Not indexed. Not an AcmeBank run. Not OBSERVED runtime evidence.

DET-MCP-001 currently correlates `run_id` + tool. Valid for one invocation per run. Not sufficient later for multiple same-tool calls against different resources. This workshop does not add per-invocation identity.

---

## DEFEND

CTRL-MCP-001 is a **lab allow-list**, not production IAM.

Tool granted. Scope granted. Arguments valid. Resource known. Resource not granted → **DENY** `resource_not_granted` → handler does not begin. Handler count 0 at runtime. No indexed `mcp.started` on a complete copy. `allowed_resource.ids` remains `lending-basics`. The control does not rewrite the grant.

Splunk did not prevent the action.

Unknown catalog tokens are **ERROR** `unknown_resource`, not DENY, and not RETEST.

Malformed arguments are **ERROR** `malformed_arguments`, not a resource-grant question.

Duplicate JSON keys are rejected at the HTTP boundary with **no** control.decision event.

Splunk searches do not move the control.

**SPL this step:** Q-MCP-AUTHZ / Q-MCP-RESOURCE-AUTHZ on the UNKNOWN token for the teaching panel.

---

## RETEST

Same unauthorized **resource** as ATTACK. Profile `defended`. `testbed.mode=RETEST`.

**Expected:** DENY `resource_not_granted`, `attempted=false`, `executed=false`, `outcome=prevented`, runtime handler count **0**, no `mcp.started`.

**Validated reference:** `0726a0ff-a551-41a8-bfbb-ab2ceca4c0dd` (local 6 = Splunk 6).

Runtime handler count is authoritative proof of non-execution.

Splunk absence of `mcp.started` is corroboration only.

**SPL:** Q-MCP-AUTHZ, Q-MCP-RESOURCE-AUTHZ, Q-MCP-TOOL, Q-MCP-EXECUTED on the RETEST token.

---

## COMPARE

```text
BASELINE — granted resource lending-basics, ALLOW, handler 1, mcp.completed
    ↓
ATTACK — known-but-ungranted executive-restricted, vulnerable fail-open ALLOW, handler 1
    ↓
RETEST — same ungranted resource, defended DENY, handler 0, no mcp.started
```

Same tool. Same scope. ATTACK and RETEST use the same resource. Different profile changes whether the vulnerable fail-open is permitted.

Handler counts are runtime facts. Splunk tables corroborate the indexed copy.

---

## PROVE

Layers (do not merge):

1. Runtime — handler invocation count
2. Local — `events.jsonl` sequence
3. Export — `export.json` (`splunk.verified=false` until searched)
4. Splunk indexed — complete copy vs local count
5. Search — Q-MCP analytical interpretation (Q-MCP-RESOURCE-AUTHZ is the MCP-004 hunt)
6. Detection — DET-MCP-001: no indexed DENY→execution violation found (not non-execution proof; not “system is secure”)

Knowledge check: `knowledge-check.md`.
