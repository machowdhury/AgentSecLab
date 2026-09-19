# Q-MCP-RESOURCE-AUTHZ

| Item | Value |
|------|--------|
| Query ID | `Q-MCP-RESOURCE-AUTHZ` |
| Security question | What resource was requested, what resource set was granted, and what authorization decision was made? |
| Validation status | **VALIDATED** (live Splunk CLI, 2026-09-12, schema 1.2.0 MCP-004 specimens) |
| Validation date | 2026-09-12 |
| SPL file | `Q-MCP-RESOURCE-AUTHZ.spl` |
| Lab | LAB-MCP-004 |

Existing Q-MCP-SCOPE cannot answer this. On MCP-004 ATTACK, requested_scope still equals allowed_scope, so SCOPE shows `granted` while the **resource** is ungranted. Q-MCP-PARAMS preview/hash remains provenance, not this hunt.

## Required fields (indexed names)

`event.name`, `agentsec.run.id`, `gen_ai.agent.id`, `agentsec.principal.id`, `gen_ai.tool.name`, `agentsec.mcp.resource.id`, `agentsec.mcp.allowed_resource.ids`, `agentsec.control.decision`, `agentsec.control.reason`, `agentsec.security.profile`, `agentsec.testbed.mode`, `agentsec.operation.attempted`, `agentsec.operation.executed`, `agentsec.operation.outcome`, `trace_id`

## SPL

See `Q-MCP-RESOURCE-AUTHZ.spl`. Bind `__RUN_ID__`.

## Line-by-line explanation

1. Scope `index=agentsec_telemetry sourcetype=otel:agentic:json` and one `agentsec.run.id`. Restrict to `event.name=agentsec.control.decision` (resource fields are emitted there).
2. Collapse INDEXED_EXTRACTIONS+KV_MODE duplicate copies with `mvindex(mvdedup(…),0)`.
3. `resource_in_grant` is exact equality of the **collapsed strings**. Indexed `allowed_resource.ids` is a comma-sorted scalar (`lending-basics`), duplicated (`mvcount=2`, `mvdedup=1`), not a JSON array of grants. Do not treat `mvcount=2` as two grants.
4. `resource_relation` uses **control reason**, not catalog inference from id vs grant:
   - `decision=ERROR` → `not_a_grant` (unknown_resource **and** malformed_arguments)
   - reason contains `resource_not_granted` → `known_but_ungranted` (defended DENY **and** vulnerable fail-open ALLOW)
   - `ALLOW` and string membership → `granted`
5. Table identity, resource pair, decision/reason, relation, profile/mode, operation flags, `trace_id`.

Do **not** infer catalog membership solely by `resource.id` vs `allowed_resource.ids`. `executive-restricted` and `does-not-exist` are both absent from the grant; only the reason distinguishes them.

## Expected result

| Specimen | resource_id | allowed_resource.ids | decision / reason | relation |
|----------|-------------|----------------------|-------------------|----------|
| A BASELINE | `lending-basics` | `lending-basics` | ALLOW `tool_granted` | `granted` |
| B ATTACK | `executive-restricted` | `lending-basics` | ALLOW `vulnerable_profile_fail_open:resource_not_granted` | `known_but_ungranted` |
| C RETEST | `executive-restricted` | `lending-basics` | DENY `resource_not_granted` | `known_but_ungranted` |
| D unknown | `does-not-exist` | `lending-basics` | ERROR `unknown_resource` | `not_a_grant` |
| E malformed | *(empty — not extracted)* | `lending-basics` | ERROR `malformed_arguments` | `not_a_grant` |
| F handler fail | `lending-basics` | `lending-basics` | ALLOW `tool_granted` | `granted` (execution is a different question) |
| G duplicate JSON keys | no control row | — | — | 0 rows |

Vulnerable ALLOW must **not** display as resource granted. The grant remains `lending-basics`.

## Actual result

**VALIDATED** (Splunk CLI CSV). See `docs/PHASE5C_MCP004_SPLUNK_VALIDATION.md`.

| Spec | relation | Notes |
|------|----------|--------|
| A | `granted` | Control `executed=false`; use Q-MCP-EXECUTED for `mcp.completed` |
| B | `known_but_ungranted` | ALLOW fail-open; allowed ids unchanged |
| C | `known_but_ungranted` | DENY; no `mcp.started` on complete copy |
| D | `not_a_grant` | Not DENY, not `known_but_ungranted` |
| E | `not_a_grant` | `resource_id` empty; not fabricated |
| F | `granted` | Later `mcp.failed` is execution, not prevention |
| G | 0 rows | HTTP/schema boundary; no CTRL-MCP-001 event |

## Validated run.id / test data

`fb50dcaf-8e84-4a3f-a55b-997c72edbd04`, `5ab59fc7-303e-4eea-84e7-ae0b2f405146`, `0726a0ff-a551-41a8-bfbb-ab2ceca4c0dd`, `0e4e0051-528d-4bf3-8773-d1fb55a5864f`, `9ea63448-bf6a-4619-b313-b152f4d94bb6`, `ccd13a5f-0c4f-4447-84da-e0bbb1184585`, `ffafb62e-a6c6-42c0-837d-094cbfb3f795`.

## Performance notes

Index + sourcetype + run.id + one event name + eval + table. No `join`, `transaction`, `map`, `append`, or subsearch. `earliest=0` is lab-only.

## Known limitations

- One coded grant in this lab (`lending-basics`). Membership is collapsed-string equality, matching the indexed shape.
- `resource_relation` is a **display helper**, not a detector.
- Duplicate-key rejection never emits this control row.
- Does not prove the handler ran (control ALLOW `executed=false`).

## No-data semantics

Zero rows means this Splunk copy has no `agentsec.control.decision` for that `run.id` (schema-boundary failure, export loss, or wrong id). That is **not** DENY, **not** unknown_resource, and **not** proof the handler never ran.
