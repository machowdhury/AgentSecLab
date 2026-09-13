# Phase 5B MCP-004 runtime validation

**Phase:** 5B LAB-MCP-004 runtime  
**Schema:** `agentsec.security_event` **1.2.0** (additive over 1.1.0)  
**Date:** 2026-09-12  
**Pytest:** **220 passed**, 2 deselected (`live_ollama`, `live_splunk`) — this session, `.venv/bin/python -m pytest tests -m "not live_ollama and not live_splunk"`  
**Evidence class:** MEASURED (pytest) + OBSERVED (local `artifacts/<run-id>/`). Splunk: **NOT ATTEMPTED**.

Do not treat this file as Splunk, Dashboard Studio, or detection proof.

---

## Resource catalog and grant (MEASURED)

`lookup_policy` catalog = `{lending-basics, executive-restricted}` (`POLICY_FIXTURES` keys).  
Agent `acme-agent-mcp-001` coded grant `allowed_policy_ids = {lending-basics}`. HTTP cannot set this set.

`lookup_customer_tier` has no `resource_key`; resource steps are skipped (MCP-002 preserved).

Matching: exact `in` membership. No strip, lowercase, Unicode normalize, prefix, regex, wildcard, or substring.

## Authorization order (MEASURED)

1. tool exists  
2. tool granted  
3. requested_scope present and syntactically acceptable  
4. requested_scope known to tool  
5. requested_scope granted to agent  
6. arguments structurally valid  
7. resource identifier extracted  
8. resource exists in server-owned catalog  
9. resource granted to agent  
10. ALLOW ticket (`resource_id` bound)  
11. handler begins  

Duplicate JSON keys fail at the HTTP parse **before** step 1. Handler spy increments only in `ToolRegistry.call_handler`.

MCP-003 fail-open ALLOW (scope) still proceeds to args + resource. If the resource is granted, the **MCP-003 reason is preserved** (not overwritten with `tool_granted`). MCP-004 fail-open is applied only when tool+scope already ALLOW'd with `tool_granted` and the resource is known+ungranted under `vulnerable`.

## Duplicate-key policy (MEASURED)

`src/agentsec/json_strict.py` `object_pairs_hook` rejects duplicate keys at any nesting. `POST /mcp/invoke` uses this decoder on the raw body.

`{"policy_id":"lending-basics","policy_id":"executive-restricted"}` → HTTP 400, `block_reason=duplicate_json_keys`, handler 0, no `control.decision`, no `mcp.started`. Not last-value-wins.

## AllowTicket binding (MEASURED)

`AllowTicket.resource_id` is set at authorize time. `execute()` passes `{policy_id: ticket.resource_id}` to the handler. Mutating the original request dict **and** `ticket.arguments["policy_id"]` after ALLOW still executes `lending-basics`. Handler `POLICY_FIXTURES[policy_id]` is a fixture lookup after catalog+grant, not the ACL.

---

## Primary specimens (local artifacts)

Generator: `scripts/run_lab_mcp_004_runtime.py`. Same tool `lookup_policy`, same scope `policy:read`. Only `policy_id` and profile/mode change.

| Spec | run.id | Profile | mode | policy_id | allowed_resource.ids | Decision | Handler |
|------|--------|---------|------|-----------|----------------------|----------|---------|
| **A BASELINE** | `0dec6e56-2dc9-44fa-8d53-485345b9ad94` | defended | BASELINE | `lending-basics` | `lending-basics` | ALLOW `tool_granted` | **1** |
| **B ATTACK** | `195d6fc5-cb08-4ce7-833b-01942f7664df` | vulnerable | ATTACK | `executive-restricted` | `lending-basics` | ALLOW `vulnerable_profile_fail_open:resource_not_granted` | **1** |
| **C RETEST** | `32480a0c-6a26-419a-8a1a-ff8cb5ed0fa6` | defended | RETEST | `executive-restricted` | `lending-basics` | DENY `resource_not_granted` | **0** |

Sequences (OBSERVED in `events.jsonl`):

- A/B: `control.decision` before `mcp.started` then `mcp.completed`
- C: `control.decision` DENY → `pipeline.stopped` → **no** `mcp.started`

Control ALLOW events: `operation.attempted=false`, `executed=false`.  
C DENY: `attempted=false`, `executed=false`, `outcome=prevented`.  
`export.json` `splunk.verified=false`. `manifest.json` `schema.version=1.2.0`, `splunk.validated=false`. Resource identity and coded grant present on manifest/result.

---

## Edge cases (pytest MEASURED)

| Id | Input | Result | Handler |
|----|--------|--------|---------|
| D | `does-not-exist` | ERROR `unknown_resource` | 0 |
| E | missing `policy_id` | ERROR `malformed_arguments` | 0 |
| F | `policy_id` integer | ERROR `malformed_arguments` | 0 |
| G | unexpected argument key | ERROR `malformed_arguments` | 0 |
| H | `LENDING-BASICS` | ERROR `unknown_resource` | 0 |
| I | `"lending-basics "` | ERROR `unknown_resource` | 0 |
| J | `" lending-basics"` | ERROR `unknown_resource` | 0 |
| K | `"lending-basics%00"` | ERROR `unknown_resource` | 0 |
| L | array `policy_id` | ERROR `malformed_arguments` | 0 |
| M | nested object `policy_id` | ERROR `malformed_arguments` | 0 |
| N | HTTP `allowed_policy_ids` | ERROR `unknown_fields` | 0 |
| O | argument grant keys | ERROR `malformed_arguments` | 0 |
| P | duplicate JSON key | ERROR `duplicate_json_keys` | 0 |
| Q | exploding `authorize_fn` | ERROR `control_evaluation_failure:…` | 0 |
| R | handler raise after ALLOW `lending-basics` | `mcp.started` + `mcp.failed`; `executed=true`; `outcome=error` | 1 |

Also MEASURED: `lending*`, `lending`, `*` → ERROR `unknown_resource`, handler 0.

LAB-MCP-001 / LAB-MCP-003 regression: existing tests still pass (`lookup_policy`+`policy:read` ALLOW; `lookup_customer_tier` defended DENY `tool_not_granted`; vulnerable MCP-002 labeled fail-open; MCP-003 scope DENY / fail-open). Q-MCP SPL files and DET-MCP-001 **not modified**. Studio XML **not modified**.

## Fail-open separation (MEASURED)

| Lab | Vulnerable reason |
|-----|-------------------|
| MCP-002 | existing exact string beginning `vulnerable_profile_fail_open:CTRL-MCP-001 known tool ` (includes `allowed_tools`) |
| MCP-003 | `vulnerable_profile_fail_open:scope_not_granted` |
| MCP-004 | `vulnerable_profile_fail_open:resource_not_granted` |

Three distinct strings. Unknown resource does not fail-open. Fail-open does not rewrite `allowed_resource.ids`.

## Non-execution proof

`ToolRegistry.invoke_counts["lookup_policy"]` / `invoke_total`. C, D–Q leave count at 0. Missing `mcp.started` is corroboration only.

## Check/use proof

`tests/security/test_mcp_resource_authorization.py::test_ticket_resource_equals_handler_resource`: after ALLOW, mutating request + ticket.arguments still yields handler `policy_id=lending-basics`.

## DET-MCP-001 compatibility

DET-MCP-001 files **unchanged**. RETEST C is DENY + no later `mcp.started` for the same run/tool (local invariant test). ATTACK B is ALLOW, so that detector would not fire (by design).

**Correlation limitation:** the detector groups by `run_id` + tool. Canonical MCP-004 runs issue **one** `lookup_policy` invocation. Future multiple same-tool invocations in one run would need stronger correlation (likely invocation identity). Not a correctness bug in the current canonical model.

## Schema

Version string is **1.2.0**. Additive properties `agentsec.mcp.resource.id` and `agentsec.mcp.allowed_resource.ids`. Additive enum `MCP-004`. No `effective_resource`. Preview/hash unchanged. Loan events emit 1.2.0 with unchanged field meanings.

## Limitations

- In-process JSON-RPC, not remote MCP transport.
- Splunk indexing / Q-MCP-* on these run IDs: **not this phase**.
- Workshop / Studio: **not this phase**.
- No DET-MCP-004. DET-MCP-001 unmodified.
- HTTP `lookup_policy`+`policy:read`+`lending-basics` still classified MCP-001 (LAB-MCP-001 preserved). Canonical A/B/C packs set `attack.id=MCP-004` explicitly.
- Authority-bearing resource ids are **not** stripped. Whitespace-only `policy_id` remains `malformed_arguments`.
- Lab HTTP hop fields still expose `control.reason` (teaching surface). No catalog enumeration API.
- Duplicate-key rejection is on `/mcp/invoke` only (the MCP authorization boundary).
- Agent-only grant (no principal ACL). `lookup_customer_tier` has no resource ACL.
