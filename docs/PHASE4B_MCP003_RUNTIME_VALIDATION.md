# Phase 4B MCP-003 runtime validation

**Phase:** 4B LAB-MCP-003 runtime  
**Schema:** `agentsec.security_event` **1.1.0** (not bumped)  
**Date:** 2026-09-12  
**Pytest:** **169 passed**, 2 deselected (`live_ollama`, `live_splunk`) — this session, `.venv/bin/python -m pytest tests -m "not live_ollama and not live_splunk"`  
**Evidence class:** MEASURED (pytest) + OBSERVED (local `artifacts/<run-id>/`). Splunk: **NOT ATTEMPTED**.

Do not treat this file as Splunk, Dashboard Studio, or detection proof.

---

## ToolSpec refactor

`ToolSpec` now has `valid_scopes: frozenset[str]` **and** `required_scope` (must be a catalog member).

`lookup_policy.valid_scopes = {policy:read, policy:restricted:read}`.  
Matching: `requested_scope in valid_scopes` then `requested_scope in policy.allowed_scopes`. Exact membership only.

## Authorization order (MEASURED)

tool exists → tool granted → requested_scope present/non-blank → catalog membership → agent grant → argument schema → ALLOW ticket → handler.

Handler spy increments only in `ToolRegistry.call_handler`, after the ticket.

## Unknown_scope result

ERROR `unknown_scope` on CTRL-MCP-001. Not DENY. Handler 0. No `mcp.started`.

Comma-delimited `policy:read,policy:restricted:read` → **ERROR `unknown_scope`** (one opaque string; v1 has no multi-scope).

---

## Primary specimens (local artifacts)

Generator: `scripts/run_lab_mcp_003_runtime.py`. Same tool `lookup_policy`, same arguments `policy_id=lending-basics`.

| Spec | run.id | Profile | mode | requested | allowed | Decision | Handler |
|------|--------|---------|------|-----------|---------|----------|---------|
| **A BASELINE** | `c02825ed-96bd-4c0d-8fdc-a4e8f5051feb` | defended | BASELINE | `policy:read` | `policy:read` | ALLOW `tool_granted` | **1** |
| **B ATTACK** | `affa8d57-03dc-4a5a-8e16-6db9f6cfaa0a` | vulnerable | ATTACK | `policy:restricted:read` | `policy:read` | ALLOW `vulnerable_profile_fail_open:scope_not_granted` | **1** |
| **C RETEST** | `a7778a8a-ebe1-4803-a44e-f34ec79baafa` | defended | RETEST | `policy:restricted:read` | `policy:read` | DENY `scope_not_granted` | **0** |

Sequences (OBSERVED in `events.jsonl`):

- A/B: `control.decision` before `mcp.started` then `mcp.completed`
- C: `control.decision` DENY → `pipeline.stopped` → **no** `mcp.started`

Control ALLOW events: `operation.attempted=false`, `executed=false`.  
C DENY: `attempted=false`, `executed=false`, `outcome=prevented`.  
`export.json` `splunk.verified=false`. `manifest.json` `splunk.validated=false`.

---

## Edge cases (pytest MEASURED)

| Id | Input | Result | Handler |
|----|--------|--------|---------|
| D | `policy:write` | ERROR `unknown_scope` | 0 |
| E | `Policy:read` | ERROR `unknown_scope` | 0 |
| F | `"policy:read "` | ERROR `unknown_scope` | 0 |
| G | `policy:*` | ERROR `unknown_scope` | 0 |
| H | `policy:read,policy:restricted:read` | ERROR `unknown_scope` | 0 |
| I | missing / `"   "` | ERROR `missing_requested_scope` | 0 |
| J | scope keys only in arguments | ERROR `malformed_arguments` or HTTP `missing_requested_scope` | 0 |
| K | client `allowed_scope` | HTTP ERROR `unknown_fields` | 0 |
| L | `security.profile` spoof | HTTP ERROR `unknown_fields`; profile stays defended | 0 |
| M | exploding `authorize_fn` | ERROR `control_evaluation_failure:…` | 0 |
| N | handler raise after ALLOW `policy:read` | `mcp.started` + `mcp.failed`; `executed=true`; `outcome=error` | 1 |

LAB-MCP-001 regression (MEASURED, existing tests still pass): `lookup_policy`+`policy:read` ALLOW; `lookup_customer_tier` defended DENY `tool_not_granted`; vulnerable MCP-002 labeled fail-open; unknown tool ERROR.

## Fail-open separation (MEASURED)

MCP-002 reason contains `allowed_tools` / ungranted tool name.  
MCP-003 reason is exactly `vulnerable_profile_fail_open:scope_not_granted`.  
They are not equal. Unknown scope does not fail-open.

## Non-execution proof

`ToolRegistry.invoke_total` / `invoke_counts["lookup_policy"]`. C, D–M leave count at 0. Missing `mcp.started` is corroboration only.

## DET-MCP-001 compatibility

DET-MCP-001 files **unchanged**. RETEST C is DENY + no later `mcp.started` for the same run/tool (local invariant test). ATTACK B is ALLOW, so that detector would not fire (by design).

## Schema

Version string remains **1.1.0**. Additive enum value `MCP-003` on `agentsec.attack.id`. No `effective_scope`. Fail-open telemetry keeps requested vs allowed mismatch.

## Limitations

- In-process JSON-RPC, not remote MCP transport.
- Splunk indexing / Q-MCP-* on these run IDs: **not this phase**.
- Workshop / Studio: **not this phase**.
- No new detection.
- HTTP `lookup_policy`+`policy:read` still classified MCP-001 (LAB-MCP-001 preserved). Canonical A/B/C packs set `attack.id=MCP-003` explicitly.
- Authority-bearing scope strings are **not** stripped (Phase 4B lock). Whitespace-only remains `missing_requested_scope`.
