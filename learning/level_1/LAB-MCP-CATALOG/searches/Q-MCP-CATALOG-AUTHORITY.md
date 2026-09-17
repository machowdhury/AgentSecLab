# Q-MCP-CATALOG-AUTHORITY

| Item | Value |
|------|--------|
| Query ID | `Q-MCP-CATALOG-AUTHORITY` |
| Security question | What catalog metadata did this run observe, how was it classified, and did a follow-on tool request after that observation get authorized? |
| Validation status | **VALIDATED** (live Splunk CLI, 2026-09-16, schema 1.5.0 LAB-MCP-CATALOG specimens) |
| Validation date | 2026-09-16 |
| SPL file | `Q-MCP-CATALOG-AUTHORITY.spl` |
| Lab | LAB-MCP-CATALOG |

Existing Q-MCP-AUTHZ shows METADATA-001 as an extra `control.decision` row (OBSERVE `metadata_is_data`) plus hop-0 / hop-1 CTRL-MCP-001, but it does not table metadata trust, provenance, or the description **hash**. Q-MCP-PARAMS labels the same hash as `arguments_hash`, which is the wrong security question. Q-MCP-RESULT-AUTHORITY looks for CTRL-MCP-RESULT-001 and returns **zero rows** on these specimens.

This hunt is the LAB-MCP-CATALOG INV-002 reconstruction. It is **not** a detector. OBSERVE is not ALLOW. The description is not authorized. Splunk does not grant tools.

Do **not** dump `_raw` or the full tool description. The fingerprint is `metadata_hash`. `metadata_preview` is the bounded METADATA-001 preview (≤200 characters).

## Required fields (indexed names)

`event.name`, `agentsec.run.id`, `gen_ai.tool.name`, `agentsec.control.id`, `agentsec.control.decision`, `agentsec.control.reason`, `agentsec.mcp.metadata.trust`, `agentsec.mcp.metadata.provenance`, `agentsec.content.hash`, `agentsec.content.preview`, `agentsec.mcp.requested_scope`, `agentsec.mcp.allowed_scope`, `agentsec.hop.index`, `agentsec.security.profile`, `agentsec.testbed.mode`

There is **no** indexed `agentsec.mcp.allowed_tools`, `agentsec.mcp.catalog.fixture`, `gen_ai.tool.call.id`, or `agentsec.event.name`. METADATA-001 does not emit `mcp.method.name`.

## SPL

See `Q-MCP-CATALOG-AUTHORITY.spl`. Bind `__RUN_ID__`.

## Line-by-line explanation

1. Scope `index=agentsec_telemetry sourcetype=otel:agentic:json` and one `agentsec.run.id`. Include control, `mcp.started`, `mcp.completed`, and `mcp.failed`.
2. Collapse INDEXED_EXTRACTIONS+KV_MODE duplicate copies with `mvindex(mvdedup(…),0)`.
3. Identify `CTRL-MCP-METADATA-001` for classification (`untrusted_data` / `mcp.catalog.snapshot`), description hash, bounded preview, and OBSERVE `metadata_is_data`.
4. Identify hop `0` CTRL-MCP-001 as the first `lookup_policy` grant check. That ALLOW is **not** authorization of the description.
5. Identify hop `1` CTRL-MCP-001 as the follow-on request: tool, requested vs coded allowed **scope**, decision, reason.
6. Observe hop `1` `mcp.started` / `mcp.completed` without claiming the handler never ran.
7. `derived_authority=present` only when the follow-on reason contains `metadata_derived_authority`. METADATA-001 OBSERVE is **not** derived authority. Do not infer presence from follow-on ALLOW alone.
8. Keep one row per `run.id`. Runs without METADATA-001 (for example MCP-005) return **zero rows**.

## Expected result

| Specimen | metadata | derived_authority | first tool | follow-on | execution observation |
|----------|----------|-------------------|------------|-----------|------------------------|
| A BASELINE | OBSERVE `metadata_is_data`; NORMAL hash | absent | `lookup_policy` ALLOW `tool_granted` | none | `no_followon` |
| B ATTACK | OBSERVE `metadata_is_data`; MALICIOUS hash | present | `lookup_policy` ALLOW `tool_granted` | `lookup_customer_tier` ALLOW `vulnerable_profile_fail_open:metadata_derived_authority` | `mcp.completed_observed` |
| C RETEST | OBSERVE; **same hash as B** | absent | `lookup_policy` ALLOW `tool_granted` | `lookup_customer_tier` DENY `tool_not_granted` | `no_indexed_followon_execution_event` |

ATTACK must **not** look like the description received authorization. METADATA-001 stays OBSERVE on A/B/C. Coded hop-1 `allowed_scope` stays `policy:read`.

## Actual result

**VALIDATED** (Splunk CLI CSV). See `docs/PHASE8D_MCP_CATALOG_SPLUNK_VALIDATION.md`.

| Spec | derived_authority | Notes |
|------|-------------------|-------|
| A | `absent` | `no_followon`; OBSERVE is not DENY and not ALLOW |
| B | `present` | follow-on ALLOW + `mcp.completed_observed`; coded allowed_scope still `policy:read` |
| C | `absent` | follow-on DENY `tool_not_granted`; `no_indexed_followon_execution_event`; hash equals B |
| MCP-005 ATTACK (still indexed) | *(no row)* | no METADATA-001; hunt does not classify result-trust labs as catalog poisoning |

## Validated run.id / test data

A `d95717ed-ffd2-46c0-a130-9a5d7d539a5d`, B `a0937bff-31a5-453a-99bf-47d7b5148ce4`, C `23c222ea-6a87-40b7-a3e9-f12a5b572fa1`.

ATTACK/RETEST description hash (indexed METADATA-001): `sha256:9d0745320ca79852f2fbd7145bf074fcd353e290c18ba16fd02d801f9f3375b1`.

BASELINE hash (different): `sha256:8a76d34c6c21fda0dc930fa2f64fe87c3216f23cbc73ca357c47b0927850d9c3`.

## Performance notes

Search scope: one index, one sourcetype, one `run.id`, four event names. Correlation: `eventstats` by `run_id` then `dedup run_id`. No `join`, `transaction`, `map`, `append`, or subsearch. `earliest=0` is lab-only.

Expected lab cost: one run is 8–13 events. Production scaling was **not measured**. Cheap on lab data is not production validation.

## Known limitations

- No first-class `allowed_tools` field. Coded `server_owned_allowed_scope` is **scope** (`policy:read`), not the tool allow-list.
- `derived_authority` is a **display helper** from the follow-on reason string, not a detector and not a general poisoning signature.
- Zero rows means this copy has no METADATA-001 for that `run.id`. That is not “safe,” not DENY, and not proof a description was trusted.
- `followon_execution_observation=no_indexed_followon_execution_event` is Splunk corroboration. Authoritative non-execution remains the runtime handler count.
- ATTACK/RETEST same-hash proof compares two bound searches (or two CLI hashes). This hunt does not `join` two `run.id` values.
- `metadata_preview` may contain synthetic lab instruction text. Do not treat it as `_raw` and do not publish unbounded descriptions.
- Do not write “handler definitely never ran” from Splunk alone.

## No-data semantics

Zero rows: no indexed `CTRL-MCP-METADATA-001` for this `run.id` (wrong id, export loss, or a lab that never emitted catalog metadata). That is **not** blocked, **not** “no attack,” and **not** proof metadata-derived authority was refused.
