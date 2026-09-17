# MCP-005 runtime contract (LAB-MCP-005)

**Status:** Phase 6B **IMPLEMENTED + LOCALLY VALIDATED**. Not Splunk-validated. Not a workshop. Not a new detection.  
**Schema:** `agentsec.security_event` **1.3.0** (additive over 1.2.0).  
**Controls:** CTRL-MCP-RESULT-001 (new) + CTRL-MCP-001 (reuse; follow-on).  
**Evidence class:** pytest and local bundles are **MEASURED** / **OBSERVED**. Splunk: **NOT ATTEMPTED**.

Parents: `docs/MCP005_LAB_SPECIFICATION.md`, `docs/MCP005_RESULT_TRUST_MODEL.md`, `docs/SCHEMA_1_3_0.md`.

---

## WHAT IS IT?

An authorized `lookup_policy` call completes. The **bytes it returns** must not become authority. LAB-MCP-005 makes that INV-002 property fail-open (vulnerable, per-run overlay) and fail-closed (defended, OBSERVE).

## WHY DOES IT EXIST?

Tool / scope / resource grants answering “may this call happen?” are not the same question as “may the **result** widen what happens next?”

## HOW DOES IT WORK?

```text
POST /mcp/invoke  {tool=lookup_policy, arguments.policy_id=lending-basics, requested_scope=policy:read}
        │  extra JSON (including result_fixture) → ERROR unknown_fields
        ▼
1.  CTRL-MCP-001 first call (unchanged order)     ALLOW tool_granted
2.  lookup_policy handler executes once
3.  Mode-owned fixture replaces the returned JSON shape’s summary
        BASELINE → NORMAL
        ATTACK / RETEST → MALICIOUS (identical text)
4.  mcp.completed  (untrusted_data, mcp.tool.handler, preview≤200 + sha256)
5.  CTRL-MCP-RESULT-001  BEFORE overlay is consulted
        defended → OBSERVE result_is_data  (no overlay)
        vulnerable + closed fixture → ALLOW vulnerable_profile_fail_open:result_derived_grant
        exception → ERROR; no overlay; no follow-on execute
6.  Lab interpreter may extract a closed follow-on INTENT
        marker SECURITY_OVERRIDE: + invoke lookup_customer_tier only
7.  If intent exists and RESULT-001 was not ERROR:
        follow-on tools/call enters CTRL-MCP-001  (never interpreter → handler())
        overlay present → ALLOW result_derived_grant
        overlay absent  → DENY tool_not_granted  (defended)
8.  Follow-on handler only after that ALLOW
```

Fixture selection is **mode-owned**. There is no HTTP `result_fixture` field.

## WHERE DOES IT SIT?

Same `POST /mcp/invoke`, same agent `acme-agent-mcp-001`. MCP-005 begins **after** the first authorized tool completes. MCP-001 / 003 / 004 authorization order is unchanged.

MCP-005 is selected when `attack_id=MCP-005` (lab runner) or when HTTP testbed mode is ATTACK/RETEST on the granted `lookup_policy` + `policy:read` + `lending-basics` combo. HTTP BASELINE of that combo remains MCP-001 (no RESULT-001), so existing MCP-001 event counts stay intact.

## TRUST BOUNDARY

1. `mcp.tool.result` → CTRL-MCP-RESULT-001 (may these bytes mutate authority?)
2. `acmebank.mcp.authorize` → CTRL-MCP-001 (may the follow-on tool execute?)

Splunk does not authorize. The LLM does not authorize. Provenance `mcp.tool.handler` is not a grant.

## RESULT INTERPRETER

**INTENTIONALLY VULNERABLE LAB MACHINERY.** Not a general prompt parser, command parser, tool dispatcher, or LLM oracle.

| Rule | Value |
|------|--------|
| Marker | Exact `SECURITY_OVERRIDE:` (no case fold, no Unicode lookalike) |
| Tool | Closed set `{lookup_customer_tier}` via `invoke <name>` |
| Args | `{customer_id: cust-001}` only |
| Unknown tool after marker | No intent, no overlay, no execute |
| Authority-claim JSON (`role=admin`, `allowed_tools=…`) | DATA only |

## SERVER-OWNED vs RESULT-DERIVED AUTHORITY

`coded_policy()` / `ALLOWED_TOOLS` stay `{lookup_policy}`. The vulnerable overlay:

- exists only inside the current `McpServer` / run
- is labeled `result-derived`
- allows only `lookup_customer_tier` + `customer:read`
- is discarded when the run ends
- is not extensible (`ResultDerivedOverlay.__post_init__` rejects other tools)

Follow-on CTRL-MCP-001 still emits **coded** `allowed_scope=policy:read`. Overlay ALLOW does not rewrite that field.

## CONTROL SEMANTICS

| Profile | RESULT-001 | Follow-on CTRL-MCP-001 |
|---------|------------|------------------------|
| defended + NORMAL | OBSERVE `result_is_data`; no intent | none |
| vulnerable + MALICIOUS | ALLOW `vulnerable_profile_fail_open:result_derived_grant` | ALLOW same reason (overlay) |
| defended + MALICIOUS | OBSERVE `result_is_data` | DENY `tool_not_granted`; attempted=false; executed=false; outcome=prevented; **no** `mcp.started` |

Never emit `ALLOW result_is_data`. Never claim SANITIZE (content unchanged). Never claim QUARANTINE (HTTP still returns the fixture). Never DENY the already-completed first `lookup_policy`.

## FAIL-SAFE

| Failure | Result |
|---------|--------|
| RESULT-001 / interpreter exception | ERROR; overlay not applied; follow-on handler 0 |
| Follow-on authorize exception | ERROR; follow-on handler 0; no mcp.started |
| First handler exception | no RESULT-001; no overlay; follow-on handler 0 |

No fail-open on missing overlay. Vulnerable MCP-002 fail-open is **not** used for the MCP-005 follow-on when overlay is present (distinct reason). Follow-on is not submitted with `profile=vulnerable` and overlay=None.

## SCHEMA DEVIATION FROM 6A

6A left 1.2.0 unchanged. 6B **bumped to 1.3.0** because runtime evidence would otherwise be dishonest. See `docs/SCHEMA_1_3_0.md`. `gen_ai.tool.call.id` was **not** added.

## NON-GOALS (still)

No Splunk validation, no new/changed SPL, no DET-MCP-001 edit, no DET-MCP-005, no Dashboard Studio, no MCP-006.
