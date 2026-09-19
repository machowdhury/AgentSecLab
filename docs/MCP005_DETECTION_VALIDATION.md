# MCP-005 detection validation

**Date:** 2026-09-13  
**Lab:** LAB-MCP-005 live A/B/C (schema 1.3.0)  
**DET-MCP-001:** **unchanged**  
**New detector:** **NO NEW DETECTOR**  
**Hunt:** `Q-MCP-RESULT-AUTHORITY` (investigation only)

Evidence class: DET-MCP-001 live A/B/C = **MEASURED** (0 rows). SIMULATED positive control = **SIMULATED** (1 row, not indexed). Detector decision = **DOCUMENTED** from indexed field inventory.

Companion: `docs/MCP005_SPLUNK_VALIDATION.md`.

---

## DET-MCP-001 — revalidation (do not modify)

Question: after CTRL-MCP-001 **DENY**, did `mcp.started` occur for the same `run.id` + tool?

| Specimen | Indexed story | DET-MCP-001 rows |
|----------|---------------|-----------------:|
| A BASELINE | no DENY | **0** |
| B ATTACK | RESULT-001 ALLOW overlay; follow-on ALLOW then `mcp.started` | **0** |
| C RETEST | follow-on DENY `tool_not_granted`; **no** hop-1 `mcp.started` | **0** |
| F handler fail | ALLOW then `mcp.failed`; no DENY | **0** |
| Index-wide CLI | same search as packaged SPL | **0** |

Preferred ATTACK B has **no DENY**. DET-MCP-001 is correctly silent. That is INV-001 behavior, not INV-002 coverage.

C has a DENY for `lookup_customer_tier` and no later `mcp.started` for that tool. Zero rows is **not** proof the handler never ran. Runtime `lookup_customer_tier` handler count is **0**. Splunk shows `no_indexed_followon_execution_event`.

---

## DET-MCP-001 SIMULATED positive control

File: `learning/level_1/LAB-MCP-001/searches/DET-MCP-001-POSITIVE-CONTROL.spl`

| Check | Result |
|-------|--------|
| Generator | `makeresults` |
| `evidence_class` | `SIMULATED` |
| Rows | **1** |
| `run_id` | `simulated-det-mcp-001-0001` |
| Indexed `dc(_raw)` for that run id | **0** |

The detector core still matches DENY then later `mcp.started`. The fixture was **not** written to `index=agentsec_telemetry`.

---

## Candidate invariant (evaluated, not packaged)

> Result-derived authority must not cause a follow-on operation to be authorized when server-owned authority does not grant that operation.

Potential deterministic condition:

- RESULT-001 reason contains `result_derived_grant`
- hop-1 CTRL-MCP-001 decision = ALLOW
- hop-1 `mcp.started` present
- server-owned grant excludes `lookup_customer_tier`

---

## Detection quality questions

| Question | Answer from indexed evidence |
|----------|------------------------------|
| Distinguish lab vulnerability from legitimate later delegation? | **No.** Overlay ALLOW uses a lab fail-open **reason string**. There is no first-class `allowed_tools` field to prove the server grant still excludes the follow-on tool. |
| Deterministic fields only? | Partial. Reason `result_derived_grant` is deterministic **lab labeling**, not a grant snapshot. |
| Avoid parsing result text? | A detector on `SECURITY_OVERRIDE` would fail this. RESULT-001 reason does not require result-text regex. |
| Avoid LLM classification? | Yes if restricted to control fields. |
| Know server-owned grant state? | **Not as a structured field.** Only hop-1 preview `server_owned_allowed_tools` (truncated at 200 chars on ATTACK) and coded `allowed_scope=policy:read` (scope, not tools). |
| Correlate the correct follow-on? | Yes in **this** lab via `hop.index=1` + `lookup_customer_tier`. No `gen_ai.tool.call.id`. |
| Avoid FPs from multiple legitimate calls / other labs / approval flows? | **Not yet.** Hunt against indexed MCP-004 A returned 0 rows (no RESULT-001). A reason-string detector would still be coupled to this lab's fail-open vocabulary and would misfire if a future legitimate grant used the same reason or if RESULT-001 were reused loosely. |

---

## Decision

**NO NEW DETECTOR.**

Acceptable Phase 6C outcome. Hunt `Q-MCP-RESULT-AUTHORITY` answers the INV-002 reconstruction question. DET-MCP-001 remains the DENY-then-start detector.

Do not create:

- `DET-MCP-005`
- `AgentSec - MCP Result-Derived Authority Used for Follow-On Execution`
- ES notable / adaptive response
- result-text regex detection
- LLM classification detection

If a later phase emits a first-class server-owned tool grant field **and** a non-lab-specific overlay marker, re-open this gate. Do not treat this document as a promise to add a detector.

---

## Live negatives (hunt / detection)

| Population | Q-MCP-RESULT-AUTHORITY | DET-MCP-001 |
|------------|------------------------|-------------|
| MCP-005 A | 1 row, `derived_authority=absent`, `no_followon` | 0 |
| MCP-005 B | 1 row, `derived_authority=present`, follow-on ALLOW + execution observed | 0 |
| MCP-005 C | 1 row, `derived_authority=absent`, DENY, no hop-1 execution event | 0 |
| MCP-005 F | 0 rows (no RESULT-001) | 0 |
| MCP-004 A still in index | **0 rows** | 0 (index-wide) |
| `CTRL-MCP-RESULT-001` by `attack.id` | only `MCP-005` (3 runs: A/B/C) | n/a |

The hunt does not classify old MCP labs as result-derived authority failures.

---

## What was not created

No savedsearch stanza. No schedule. No notable. No Dashboard Studio. No MCP-006.
