# Logic proof — MCP reference workbench

**Date:** 2026-09-22
**Scope:** presentation changes only; CTRL-MCP-001 and runtime behavior unchanged.

## Security property

INV-001: an agent cannot receive more authority than explicitly delegated. The browser cannot widen server-owned MCP grants.

## Assumptions

- Attack Service remains localhost educational infrastructure.
- `coded_policy()` is server-owned.
- The MCP ToolRegistry counter is authoritative for handler invocation in this lab.
- Splunk is a transported copy, not the enforcement point.

## Attacker-controlled input

An allowlisted closed specimen containing tool, requested scope, and arguments. Browser JSON is restricted to `lab_id`, `specimen_id`, `mode`, and `execution`.

## Trust boundary and code path

```text
browser closed launch
→ parse_launch_json
→ LaunchService allowlist / ExperimentContext
→ AcmeBank /mcp/invoke
→ CTRL-MCP-001
→ ToolRegistry handler (only after ALLOW)
→ telemetry / evidence
→ Splunk
```

## Decision points

- Unknown/extra browser fields: ERROR before runtime call.
- Unknown experiment/specimen: ERROR.
- Known-ungranted tool in vulnerable ATTACK: labeled fail-open ALLOW.
- Same request in defended RETEST: DENY `tool_not_granted`.

## Dangerous operation

`lookup_customer_tier` handler invocation.

## Where validation occurs

CTRL-MCP-001 evaluates before ToolRegistry invocation. The UI reads the returned control hop and runtime handler count; it does not compute authorization.

## Failure path and fail-open possibility

Unknown fields and malformed requests fail as ERROR. Missing security context does not become ALLOW. The only fail-open is the predefined, labeled ATTACK ExperimentContext.

## Telemetry

Control decision/reason precedes MCP start when execution occurs. ATTACK handler count 1; RETEST handler count 0. `mcp.started` absence in Splunk is corroborative only after event-copy completeness.

## Questions

- Could the dangerous operation happen before validation? **No in the inspected code path and tests.**
- Could missing context become ALLOW? **No; malformed/unknown context is ERROR.**
- Could one agent silently inherit another agent's authority? **Not in LAB-MCP-001; coded policy remains bound to `acme-agent-mcp-001`.**
- Could telemetry report DENY after the operation already happened? **The tested pipeline orders control before handler. DET-MCP-001 exists to hunt DENY-then-start; it remains disabled.**
- Which assertion lacks a test? **Formal screen-reader output is not automatically tested; semantic labels and keyboard/focus behavior are checked, but assistive-technology interpretation remains PARTIAL.**

## Evidence

- MEASURED: targeted automated suite, 55 passed.
- MEASURED: established offline suite, 943 passed and 2 deselected.
- OBSERVED: checkpoint ATTACK `2b8949c2-1e11-4c91-a578-d73fa7e7d323`, ALLOW, handler 1.
- OBSERVED: checkpoint RETEST `1b297f0b-d473-4125-bb56-773fe8479898`, DENY, handler 0.
- MEASURED: local events 7/6 equal Splunk `dc(_raw)` 7/6.
- OBSERVED: Q-MCP-WHO, Q-MCP-AUTHZ, and Q-MCP-EXECUTED returned the expected fresh rows.
- MEASURED: all checkpoint authority-field attempts (`profile`, `grants`, `allowed_tools`, `allowed_scope`, `roles`, `permissions`, `python`, `spl`, `environment`, `payload`, `policy`, `run.id`, `security.profile`, `control.decision`, `operation.executed`) returned HTTP 400 `unknown_fields`, produced no run.id, and did not call the runtime.
