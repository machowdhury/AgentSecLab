# Phase 7B — MCP-006 local runtime validation

**Status:** **PASS** — IMPLEMENTED + LOCALLY VALIDATED.  
**Date:** 2026-09-14  
**Schema:** 1.4.0  
**Splunk:** `splunk.verified=false`. **NOT STARTED.** No SPL. No detector. No Studio.

**Pytest:** `.venv/bin/python -m pytest tests -q --tb=line -m "not live_ollama and not live_splunk"` → **344 passed, 2 deselected** (MEASURED).

## Canonical local runs (OBSERVED)

Generated with `scripts/run_lab_mcp_006_local_specimens.py` (OTEL off). Bundles under `artifacts/<run-id>/` (gitignored).

### A — BASELINE

| Field | Value |
|-------|--------|
| run.id | `0eb3207d-5de5-4c05-96c9-641ec15e1d82` |
| profile / mode | defended / BASELINE |
| caller / deputy | credit-002 / compliance-004 |
| operation | `lookup_policy` / `policy:read` / `lending-basics` |
| delegated / ambient | `{lookup_policy}` / `{lookup_policy, lookup_customer_tier}` |
| CTRL-DELEGATION-001 | ALLOW `delegation_granted` source=`delegated` |
| CTRL-MCP-001 | ALLOW `tool_granted` |
| attempted / executed / outcome | true / true / success |
| handler | policy **1**, tier **0** |
| event count | 10 |
| schema | 1.4.0 |

### B — ATTACK

| Field | Value |
|-------|--------|
| run.id | `d991e30f-5393-4059-8a7a-9a7742226701` |
| profile / mode | vulnerable / ATTACK |
| operation | `lookup_customer_tier` / `customer:read` / `cust-001` |
| CTRL-DELEGATION-001 | ALLOW `vulnerable_profile_fail_open:ambient_deputy_authority` source=`ambient_deputy` |
| CTRL-MCP-001 | ALLOW `tool_granted` (per-request ambient policy, **defended** membership) |
| attempted / executed / outcome | true / true / success |
| handler | tier **1** |
| event count | 10 |

### C — RETEST

| Field | Value |
|-------|--------|
| run.id | `874b2e37-fff1-43d4-940a-c2feef28fcab` |
| profile / mode | defended / RETEST |
| operation | **same as B** |
| CTRL-DELEGATION-001 | DENY `delegated_authority_not_granted` source=`delegated` |
| downstream MCP | none |
| attempted / executed / outcome | false / false / prevented |
| handler | **0** |
| event count | 6 (no `mcp.started`) |

## Other local packs

| Id | run.id | Result |
|----|--------|--------|
| D unknown caller | `b04b4689-b9d9-4533-99a4-1f5b86bcca17` | ERROR `unknown_caller`; handler 0 |
| E unknown deputy | `5180ee1c-0702-47c7-af62-9128737b0efc` | ERROR `unknown_deputy`; handler 0 |
| K valid delegation + MCP DENY | `274fb5e8-060b-450c-83fe-eb43f0615753` | Delegation ALLOW; MCP DENY `scope_not_granted`; handler 0 |
| L handler failure | `47c7f915-19ca-46fb-880d-e5dd7238967f` | Delegation+MCP ALLOW; `outcome=error`; handler 1; not prevented |

F/G/H/I/J/M/N covered by pytest (missing, malformed, HTTP spoof/injection, duplicate keys, control exception, cross-run, check/use).

## Logic proof (MEASURED)

| Question | Answer |
|----------|--------|
| Dangerous op before validation? | No. RETEST has 0 `mcp.started`. |
| Missing context → ALLOW? | No. ERROR `missing_delegation_context`. |
| Inherit ambient on defended? | No. DENY `delegated_authority_not_granted`. |
| DENY after execute? | No. Control flags `executed=false` on DENY. |
| Global mutation? | Snapshot equality after ATTACK; `coded_policy()` unchanged. |
| LLM authorize? | No `agentsec.llm.*` on MCP-006 runs. |

## Schema honesty

1.4.0 required. 1.3.0 could not emit CTRL-DELEGATION-001 / MCP-006 / authority.source.

## Non-goals remaining

Phase 7C Splunk, SPL, DET-MCP-006, Dashboard Studio. Do not start automatically.
