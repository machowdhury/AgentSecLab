# Phase 3E — MCP authorization invariant detection

**Date:** 2026-09-12  
**Status:** **VALIDATED** for one disabled saved search (`DET-MCP-001`). Not MCP-003+. Not remediation. Not ES notable.  
**Schema:** `agentsec.security_event` **1.1.0** — unchanged  
**Hunt query:** `Q-MCP-AFTER-DENY` — unchanged  
**Detection:** `DET-MCP-001` / saved search `AgentSec - MCP Execution After Authorization Deny`

Evidence class: SPL packaging is **DOCUMENTED**. Pytest contracts are **MEASURED**. Live Splunk CLI on Phase 3C specimens is **MEASURED**. Positive control is **SIMULATED**. Runtime handler counts remain Phase 3B/3C facts.

Do not tag COMPLETE automatically. Splunk still does not enforce authorization.

---

## Detection objective

Did an MCP tool execution begin after CTRL-MCP-001 denied the same run/tool?

## Invariant

If CTRL-MCP-001 returns DENY for a `run.id` + tool, no later `event.name=agentsec.mcp.started` may occur for that same pair with `agentsec.sequence` greater than the DENY sequence.

This is a **HIGH-CONFIDENCE** invariant violation: authorization already denied, and the handler nevertheless began.

## SPL

Canonical: `learning/level_1/LAB-MCP-001/searches/DET-MCP-001.spl`.

Operationalization of `Q-MCP-AFTER-DENY` (minimal, documented):

| Hunt (`Q-MCP-AFTER-DENY`) | Detection (`DET-MCP-001`) |
|---------------------------|---------------------------|
| `__RUN_ID__` token | no run token |
| `mcp.started` / `completed` / `failed` | `mcp.started` only |
| columns: run, tool, deny_seq, sequence, event_name | identity, scopes, `trace_id`, `deny_sequence`, `mcp_start_sequence` |
| `earliest=0` in file | no `earliest=` in file; saved search `-24h` to `now` |

Same index, sourcetype, `mvindex(mvdedup(...),0)` collapse, `eventstats` by `run_id, tool`, `sequence>deny_sequence`. No `join` / `transaction` / `map`.

Scopes and `control.id` are copied from the DENY event (they are not on `mcp.started`). That derivation is deterministic and matches the Phase 3C field contract.

## Severity

**HIGH.**

Rationale: the control already returned DENY; a later `mcp.started` for the same run/tool means the authorization boundary was crossed. Not HIGH because “MCP is dangerous.” Not CRITICAL: this is a lab invariant detector, not proof of a production breach, and Splunk is a copy.

Vanilla Splunk: severity is in the saved-search description. No ES `action.notable`. No risk score.

## Packaging

`splunk_app/agentsec/default/savedsearches.conf`

| Item | Value |
|------|--------|
| Stanza | `AgentSec - MCP Execution After Authorization Deny` |
| `disabled` | `1` |
| `enableSched` | `0` |
| `cron_schedule` | `0 * * * *` (documented only; not enabled) |
| `dispatch.earliest_time` | `-24h` |
| `dispatch.latest_time` | `now` |
| Throttle | none |
| Security domain (docs) | `agentsec.mcp.authorization` |
| ES notable | not used |

Lab convention: detections stay disabled until an operator enables them.

## Expected negatives (LIVE)

| Specimen | `run.id` | Why DET-MCP-001 must not fire |
|----------|----------|-------------------------------|
| BASELINE | `163d11e2-e751-4282-9406-19b490542ed4` | ALLOW `tool_granted` then `mcp.started`. No DENY. |
| ATTACK | `5e8f55f3-eb46-47ee-b979-b72d9c9b1f49` | Labeled fail-open **ALLOW**, then start. Not DENY-then-start. |
| RETEST | `7a1d37b5-d589-4dfd-8322-25ebd0152dbc` | DENY `tool_not_granted`, handler 0, no `mcp.started`. DENY alone is not an alert. |
| UNKNOWN TOOL | `2e804c0d-eb86-405a-ab8d-360616df0ef9` | ERROR `unknown_tool`. ERROR is not DENY. |
| MALFORMED ARG | `f2ef017e-d66c-4712-bacd-07138a30d2e6` | ERROR `malformed_arguments`. ERROR is not DENY. |
| HANDLER FAILURE | `5b83b6e4-f8c4-4989-8ef5-b76614b49ca5` | ALLOW then `mcp.failed`. Execution then error, not prevention and not DENY-then-start. |

## Live negative validation (MEASURED)

Splunk CLI `-output csv`, `earliest=0`, 2026-09-12 this session. Index still held RETEST `dc(_raw)=6` and a DENY decision (sanity).

| Search | Rows |
|--------|------|
| DET-MCP-001 all MCP control+start events | **0** (empty CSV) |
| DET-MCP-001 scoped to each specimen above | **0** each |
| Index leak `simulated-det-mcp-001-0001` | **count=0** |

Empty CSV means zero result rows, not a CLI failure (same convention as Phase 3C).

## SIMULATED positive control (SIMULATED)

`DET-MCP-001-POSITIVE-CONTROL.spl`: `makeresults` DENY sequence 3, `mcp.started` sequence 4, same synthetic run/tool.

**Actual CLI result (1 row):**

`run_id=simulated-det-mcp-001-0001`, tool `lookup_customer_tier`, agent `acme-agent-mcp-001`, principal `applicant-web`, control_id `CTRL-MCP-001`, decision DENY, deny_sequence 3, mcp_start_sequence 4, profile defended, mode RETEST, requested_scope `customer:read`, allowed_scope `policy:read`, trace_id `simulated-trace-det-mcp-001`, evidence_class **SIMULATED**.

Hunt fixture `Q-MCP-AFTER-DENY-POSITIVE-CONTROL` still returns 1 SIMULATED row (unchanged).

Not indexed. Not OBSERVED runtime.

## False-positive analysis

Likely **false negatives** (lossy ingest hiding `mcp.started` after DENY) more than false positives.

FP considerations: sequence corruption; grouping the wrong tool with a DENY (mitigated by `by run_id, tool`); treating ERROR as DENY (the SPL requires `decision="DENY"`). Vulnerable fail-open is ALLOW and will not fire. `mcp.failed` after ALLOW will not fire.

## Performance notes

Index + sourcetype + two `event.name` values. `eventstats` by `run_id, tool` over `-24h` lab volume. No `join` / `transaction` / `map` / subsearch. Cheap in this lab. `earliest=0` is validation-only, not the packaged schedule.

## Workshop update

DETECT tab now teaches hunt vs detection. Left table remains indexed `Q-MCP-AFTER-DENY`. Right table is **SIMULATED** `DET-MCP-001-POSITIVE-CONTROL`. Copy states DET-MCP-001 is disabled and did **not** fire on validated LIVE runs.

DETECT-only UI review: `docs/reviews/ui-review-ws-lab-mcp-001-detect-2026-09-11.md`. Screenshot: `docs/screenshots/lab-mcp-001/detect_3e_detect.png`. No BLOCKER/HIGH. Residual MEDIUM: Studio orange empty chrome; SIMULATED column clip.

## Limitations

- Zero detections ≠ handler never ran.
- Packaged window `-24h` may miss older lab specimens; validation used `earliest=0`.
- Disabled by default; enabling is an operator choice.
- Not a general MCP bypass detector.
- Not SOAR, not remediation, not Cisco, not MLTK.

## Phase 3E verdict

**VALIDATED** for one HIGH, disabled invariant detection. Stop. Do not start MCP-003. Do not add remediation.
