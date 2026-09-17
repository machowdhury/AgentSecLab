# MCP-006 detection validation

**Date:** 2026-09-14  
**Lab:** LAB-MCP-006 live A/B/C (schema 1.4.0)  
**DET-MCP-001:** **unchanged**  
**New detector:** **NO NEW DETECTOR**  
**Hunt:** `Q-MCP-DELEGATION` (investigation only)

Evidence class: DET-MCP-001 live A/B/C = **MEASURED** (0 rows). SIMULATED positive control = **SIMULATED** (1 row, not indexed). Detector decision = **DOCUMENTED** from indexed field inventory.

Companion: `docs/MCP006_SPLUNK_VALIDATION.md`.

---

## DET-MCP-001 — revalidation (do not modify)

Question: after an authorization **DENY**, did `mcp.started` occur for the same `run.id` + tool?

| Specimen | Indexed story | DET-MCP-001 rows |
|----------|---------------|-----------------:|
| A BASELINE | no DENY; delegation ALLOW then MCP ALLOW then start | **0** |
| B ATTACK | incorrect delegation ALLOW → MCP ALLOW → `mcp.started` | **0** |
| C RETEST | CTRL-DELEGATION-001 DENY; **no** `mcp.started` | **0** |

Preferred ATTACK B has **no DENY**. DET-MCP-001 is correctly silent. Zero does **not** mean the confused-deputy attack did not occur.

C has a delegation DENY and no later `mcp.started`. Zero rows is **not** proof the handler never ran. Runtime `lookup_customer_tier` handler count is **0**. Splunk shows `no_indexed_mcp_execution_event` on a complete copy.

Do not widen DET-MCP-001 to “any DENY.” Widening would still be 0 rows on C (no start) and would confuse MCP-002 teaching.

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

> A deputy must not execute a privileged tool because ambient deputy authority was substituted when the caller’s delegated grant excluded that tool.

Potential deterministic condition:

- CTRL-DELEGATION-001 `authority.source=ambient_deputy`
- CTRL-DELEGATION-001 decision = ALLOW
- hop-1 `mcp.started` present
- requested tool **not** in the delegated grant

---

## Detection quality questions

| Question | Answer from indexed evidence |
|----------|------------------------------|
| Is `authority.source` indexed? | **Yes.** Structured `delegated` / `ambient_deputy` on hop-0 control. |
| Is it stable / server-derived? | **Yes.** Coded control; HTTP cannot set it. |
| Can duplicate extraction distort it? | Copies are identical (`mvcount=2`). Collapse before compare. |
| Is delegated grant membership indexed? | **No.** No `allowed_tools`. Preview `delegated_tools` is bounded and not first-class. |
| Is ambient grant membership indexed? | **No.** Hop-1 ATTACK `allowed_scope=customer:read,policy:read` is the selected MCP policy wire, not an independent ambient inventory. |
| Can the client spoof these control fields? | Not via MCP-006 HTTP identity/grant keys (rejected as unknown / malformed). |
| Correlate the correct execution? | Yes in **this** lab via `run.id` + hop 1 + tool. No `gen_ai.tool.call.id`. |
| Can benign activity satisfy ambient_deputy + ALLOW + start? | In this lab `ambient_deputy` is **only** emitted on the vulnerable fail-open path. A notable on that enum is a **lab-label detector**. Legitimate BASELINE has deputy ambient **possession** but source=`delegated` — possession alone must not alert. |
| Distinguish lab vulnerability from a future legitimate ambient use? | **Not as a general detector.** The enum is this lab’s fail-open vocabulary. |

---

## False positive analysis

Legitimate BASELINE: caller has valid delegation, deputy also possesses ambient `lookup_policy`, delegation ALLOW, MCP ALLOW, handler executes, `authority.source=delegated`. A detector that keyed on “deputy has ambient” would false-positive. Indexed telemetry does **not** list ambient possession as a field; it lists **source consulted**.

A detector on `authority.source=ambient_deputy` would not fire on BASELINE (**MEASURED** via hunt). It would fire on ATTACK because the runtime **labeled** the substitution. That is tautological with the lab fail-open path, not independent grant-membership proof.

---

## False negative analysis

Ingest loss of hop-0 control, missing `authority.source`, truncated fields, duplicate extraction mishandled as conflicting values, multiple operations per run, same tool twice, out-of-order ingestion, partial traces — any of these can hide the reconstruction. Without `gen_ai.tool.call.id`, a future multi-call run cannot bind the ambient ALLOW to the correct start.

---

## Decision

**DETECTION ANALYZED — NO NEW DETECTOR.**

Acceptable Phase 7C outcome **B**. Hunt `Q-MCP-DELEGATION` answers the reconstruction question using indexed `authority.source`. Item 3 of the 7A predicate (tool not in delegated grant as an indexed set) remains a **telemetry gap**. A reason-string or enum-only notable would be the class Phase 6C rejected.

DET-MCP-001 remains the DENY-then-start detector. Do not create `DET-MCP-006`. Do not schedule a notable.

Control vs detection vs hunt:

- CTRL-DELEGATION-001: runtime enforcement
- Q-MCP-DELEGATION: investigation
- DET-MCP-001: analytical identification of a different invariant

Splunk does not authorize the operation. Dashboard Studio was not built in this phase.
