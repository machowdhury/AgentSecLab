# Logic proof — Goal / Instruction Integrity workbench

**Date:** 2026-09-24
**Scope:** UX and investigation presentation for `LAB-AGENT-GOAL-INTEGRITY-001`; runtime behavior unchanged.

## Security property

INV-002 and INV-006: untrusted instruction bytes cannot redefine the server-owned task contract or authorize an out-of-task objective.

`AUTHORIZED TOOL != AUTHORIZED GOAL` and `AUTHORIZED SUB-ACTION != AUTHORIZED OVERALL GOAL`.

## Actual evidence chain

```text
server-owned TaskContract
→ closed untrusted instruction fixture
→ frozen ProposedTaskChange
→ CTRL-GOAL-INTEGRITY-001
→ effective action
→ lookup_policy / policy:read request
→ CTRL-MCP-001
→ lookup_policy handler
→ operation-specific counts / runtime events / Splunk copy
```

## Model answers

1. **Attacker influence:** the closed malicious instruction bytes selected through `GOAL-001`. The browser cannot submit the instruction, task, profile, grants, decisions, or run ID.
2. **Server-owned facts:** `TaskContract`, task ID and fingerprint, permitted action `summarize_lending_policy`, permitted tool `lookup_policy`, policy scope/resource, ExperimentContext, coded policy, controls, and correlation IDs.
3. **Property under test:** a granted tool must not imply permission to use it for `extract_full_policy`.
4. **Participating controls:** `CTRL-GOAL-INTEGRITY-001` protects task/goal integrity; `CTRL-MCP-001` separately authorizes the tool request.
5. **Authoritative decisions:** Goal control selects whether the proposed expansion becomes the effective action. MCP control decides whether `lookup_policy` may execute. Neither decision substitutes for the other.
6. **OBSERVE semantics:** vulnerable ATTACK records labeled fail-open OBSERVE and mints a closed per-run goal overlay. This is not an MCP ALLOW. Defended RETEST records Goal DENY.
7. **Attempted operation:** both modes request the granted `lookup_policy` tool. The purpose differs: ATTACK uses it for `extract_full_policy`; RETEST uses it for `summarize_lending_policy`.
8. **Authorized operation:** CTRL-MCP-001 ALLOWs `lookup_policy / policy:read / lending-basics` in both modes.
9. **Actual execution:** ATTACK executes one wrong-goal lookup and no in-task lookup. RETEST executes one in-task lookup and no wrong-goal lookup.
10. **Execution proof:** `wrong_goal_lookup_policy_count` and `in_task_lookup_policy_count` are authoritative for purpose-specific execution. `lookup_policy_handler_count=1` alone is insufficient. MCP lifecycle events corroborate that a handler ran.
11. **ATTACK vs RETEST change:** server-owned profile, Goal decision/reason, effective action, overlay presence, wrong-goal count, and in-task count.
12. **Intentionally identical:** task contract/fingerprint, malicious instruction bytes/hash, proposed task change/fingerprint, proposed `extract_full_policy`, resulting tool, requested scope/resource, coded grants, and MCP ALLOW `tool_granted`.
13. **Fingerprints:** `input_fingerprint` and `instruction_hash` cover the malicious instruction bytes; `task_fingerprint` covers the server-owned task contract; `proposed_fingerprint` covers the canonical proposed task change. Equality of one does not prove whole-experiment identity.
14. **Splunk role:** reconstruct task, instruction trust, proposed goal, Goal decision, MCP decision, and indexed execution lifecycle. Splunk does not decide either control result.
15. **Falsification:** different ATTACK/RETEST instruction, task, or proposed fingerprints; RETEST effective action `extract_full_policy`; RETEST wrong-goal count 1; RETEST MCP DENY; or ATTACK wrong-goal count 0 would falsify expected semantics.

## Trust boundaries and decision points

- Browser → Attack Service: closed four-field launch contract.
- Instruction fixture → TaskContract: `CTRL-GOAL-INTEGRITY-001`, before the effective action is selected.
- Effective action → tool handler: `CTRL-MCP-001`, before handler invocation.
- Runtime → Splunk: evidence transport, not enforcement.

The dangerous objective cannot happen before Goal evaluation. Missing Goal context becomes ERROR, not ALLOW. The vulnerable overlay is closed to one action and one run and does not mutate policy or the task contract.

## Failure paths

- Unknown/authority-like fields: ERROR before follow-on; handler 0.
- Goal parse/control failure: ERROR, not DENY.
- MCP control exception: ERROR; no handler.
- Handler exception after ALLOW: execution occurred and is reported as MCP failure, not prevention.

## Tests before UX implementation

MEASURED: the combined Goal/Identity model gate passed **81 tests in 1.02s**, including authority-field rejection, check/use freezing, control ordering, operation-specific counts, telemetry, launch contracts, concurrency, and failure paths.

## Remaining proof obligations

- Fresh LIVE ATTACK/RETEST operation-specific runtime evidence.
- Local event count versus Splunk `dc(_raw)`.
- Browser comparison and controlled error-state validation.
- MCP/RAG/Memory regression after the shared CSS rename.
