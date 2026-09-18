# Q-MEMORY-CONTEXT-AUTHORITY

| Item | Value |
|------|--------|
| Query ID | `Q-MEMORY-CONTEXT-AUTHORITY` |
| Security question | Which write run persisted this memory, which later recall run loaded it, how was it classified, and did a follow-on tool request after that observation get authorized? |
| Validation status | **VALIDATED** (live Splunk CLI, 2026-09-17, schema 1.7.0 LAB-MEMORY-001 specimens) |
| Validation date | 2026-09-17 |
| SPL file | `Q-MEMORY-CONTEXT-AUTHORITY.spl` |
| Lab | LAB-MEMORY-001 |

Existing Q-MCP-AUTHZ shows MEMORY-CONTEXT-001 as an extra `control.decision` row (OBSERVE `memory_context_is_data`) plus hop-1 CTRL-MCP-001 on the **recall** run, but it does not table write-run identity, `source_run_id`, or the **memory** hash. Q-MCP on **write** runs returns **zero rows** (no `control.decision`). Q-MCP-PARAMS would mislabel hop-1 request hashes as `arguments_hash`. Q-RAG-CONTEXT-AUTHORITY is a one-`run.id` retrieved-context hunt and does not reconstruct write → recall.

This hunt is the LAB-MEMORY-001 INV-003 reconstruction. It is **not** a detector. OBSERVE is not ALLOW. Recalled memory is not authorized. Splunk does not grant tools.

Do **not** dump `_raw` or the full memory body. The fingerprint is SHA-256 on `agentsec.memory.written` / `agentsec.memory.recalled` / CTRL-MEMORY-CONTEXT-001. `write_preview` / `recall_preview` are bounded (≤200 characters).

Bind **two** tokens. `memory.id` is a fixture identity shared by ATTACK and RETEST, so it cannot uniquely key a specimen.

## Required fields (indexed names)

`event.name`, `agentsec.run.id`, `gen_ai.agent.id`, `gen_ai.tool.name`, `agentsec.control.id`, `agentsec.control.decision`, `agentsec.control.reason`, `agentsec.memory.id`, `agentsec.memory.trust`, `agentsec.memory.provenance`, `agentsec.memory.source_run_id`, `agentsec.content.hash`, `agentsec.content.preview`, `agentsec.mcp.requested_scope`, `agentsec.mcp.allowed_scope`, `agentsec.hop.index`, `agentsec.security.profile`, `agentsec.testbed.mode`

There is **no** indexed `trusted_memory`, `memory_authorized`, `session.id`, `invocation.id`, `agentsec.mcp.allowed_tools`, `gen_ai.tool.call.id`, or `agentsec.event.name`. MEMORY-CONTEXT-001 does not emit `mcp.method.name`. Write events do **not** carry `agentsec.memory.trust` (trust is classified at recall).

## SPL

See `Q-MEMORY-CONTEXT-AUTHORITY.spl`. Bind `__WRITE_RUN_ID__` and `__RECALL_RUN_ID__`.

## Line-by-line explanation

1. Scope `index=agentsec_telemetry sourcetype=otel:agentic:json` and the two bound `agentsec.run.id` values (OR). Include write, recall, control, `mcp.started`, `mcp.completed`, and `mcp.failed`.
2. Collapse INDEXED_EXTRACTIONS+KV_MODE duplicate copies with `mvindex(mvdedup(…),0)`.
3. Identify `agentsec.memory.written` as the writer: write `run.id`, memory id, SHA-256, provenance, preview. Writer `source_run_id` equals the write `run.id`.
4. Identify `agentsec.memory.recalled` as the destination run: recall `run.id`, same memory id, SHA-256, `source_run_id` pointing at the writer.
5. Identify `CTRL-MEMORY-CONTEXT-001` for classification (`untrusted_data` / `agentsec.memory.fixture`) and OBSERVE `memory_context_is_data`.
6. Identify hop `1` CTRL-MCP-001 as the follow-on request: tool, requested vs coded allowed **scope**, decision, reason.
7. Observe hop `1` `mcp.started` / `mcp.completed` / `mcp.failed` without claiming the handler definitely never ran.
8. `stats` (not `join` / `transaction` / `map`) collapses one specimen into one row. `write_recall_linked=linked` only when recall `source_run_id` equals write `run.id` **and** SHA-256 and memory id match.
9. `derived_authority=present` only when the follow-on reason contains `memory_derived_authority`. MEMORY-CONTEXT-001 OBSERVE is **not** derived authority. Do not infer presence from follow-on ALLOW alone.
10. Zero rows means this copy has no indexed write **and** recall pair for those two `run.id` values. That is not “safe.”

## Expected result

| Specimen | write → recall | memory | derived_authority | follow-on | execution observation |
|----------|----------------|--------|-------------------|-----------|------------------------|
| A BASELINE | `linked`; NORMAL hash | OBSERVE `memory_context_is_data` | absent | none | `no_followon` |
| B ATTACK | `linked`; MALICIOUS hash | OBSERVE | present | `lookup_customer_tier` ALLOW `vulnerable_profile_fail_open:memory_derived_authority` | `mcp.completed_observed` |
| C RETEST | `linked`; **same SHA-256 as B** | OBSERVE | absent | `lookup_customer_tier` DENY `tool_not_granted` | `no_indexed_followon_execution_event` |

ATTACK must **not** look like memory received authorization. MEMORY-CONTEXT-001 stays OBSERVE on A/B/C. Coded hop-1 `allowed_scope` stays `policy:read`. ATTACK write profile stays `defended`; overlay is recall-only.

## Actual result

**VALIDATED** (Splunk CLI CSV). See `docs/PHASE11C_MEMORY_SPLUNK_VALIDATION.md`.

| Spec | write_recall_linked | derived_authority | Notes |
|------|---------------------|-------------------|-------|
| A | `linked` | `absent` | `no_followon`; OBSERVE is not DENY and not ALLOW; NORMAL is not SAFE |
| B | `linked` | `present` | follow-on ALLOW + `mcp.completed_observed`; coded allowed_scope still `policy:read`; INTENTIONALLY VULNERABLE LAB PROFILE; write_profile `defended`, recall_profile `vulnerable` |
| C | `linked` | `absent` | follow-on DENY `tool_not_granted`; `no_indexed_followon_execution_event`; SHA-256 equals B |
| A write + B recall (mismatch) | `not_linked` | n/a | different hashes; `source_run_id` does not equal the bound write `run.id` |
| Unknown UUIDs | *(no row)* | | zero rows ≠ SAFE |

## Validated run.id / test data

| Spec | Write `run.id` (writer) | Recall `run.id` (destination) |
|------|-------------------------|-------------------------------|
| A | `a8407246-7992-4ad8-bd02-cb701e150f30` | `914c41ce-5123-49eb-892c-c948295dbc46` |
| B | `05f1d8d0-28b7-40ac-bbb9-1dc64b4ba464` | `b8737cd9-9b6b-48f2-acfa-178ae1446ddc` |
| C | `060a0a72-ceb5-4b99-8330-98de81d8ae5e` | `5d5b9d1b-092d-4ddb-8422-4092d289cd49` |

ATTACK/RETEST memory hash (indexed write, recall, and CONTEXT-001): `sha256:1dc7335c3fd8c54326e36194d783536d944c6d527660eb1bda4a36a9cb5ed1b9`.

BASELINE hash (different): `sha256:ee41410ab03d53a4f979cb3196619abb2aceedc69b41106ddd3a4e15599b340b`.

Do **not** reuse Phase 11B local-only IDs.

## Performance notes

Search scope: one index, one sourcetype, two `run.id` values, six event names. Correlation: `stats` then scalar collapse. No `join`, `transaction`, `map`, `append`, or subsearch. `earliest=0` is lab-only.

Expected lab cost: one specimen is 11–16 events (write 5 + recall 6/11/10). Production scaling was **not measured**. Cheap on lab data is not production validation.

## Known limitations

- No first-class `allowed_tools` field. Coded `followon_coded_allowed_scope` is **scope** (`policy:read`), not the tool allow-list.
- `derived_authority` is a **display helper** from the follow-on reason string, not a detector and not a general injection signature.
- Zero rows means this copy has no indexed write+recall pair for those tokens. That is not “safe,” not DENY, and not proof memory was trusted.
- `followon_execution_observation=no_indexed_followon_execution_event` is Splunk corroboration. Authoritative non-execution remains the runtime handler count. Missing `mcp.started` does not independently prove the handler definitely never ran.
- ATTACK/RETEST same-hash proof compares two bound searches (or two CLI hashes). This hunt does not `join` ATTACK to RETEST.
- Locked MALICIOUS preview is shorter than 200 characters, so the preview contains the synthetic marker. The fingerprint remains the hash. Do not correlate by preview.
- Hop-1 `agentsec.content.hash` is the **tool-request** fingerprint, not the memory fingerprint. This hunt does not table it as `write_hash` / `recall_hash`.
- `memory_id` coalesce prefers the write-side id. A mismatched token pair can show the write fixture id even when `write_recall_linked=not_linked`.
- Write-run `agentsec.memory.trust` is **empty** (NOT APPLICABLE at persist). Classification is at recall.
- Q-MCP remains the generic authorization/execution surface on the **recall** run.

## No-data semantics

Zero rows = no indexed `agentsec.memory.written` **and** `agentsec.memory.recalled` pair for the bound tokens. Not DENY. Not SAFE. Not prevention.

## False positives / false negatives

This is a reconstruction hunt, not a detector. A row with `derived_authority=present` is a labeled lab overlay, not a production notable. A BASELINE row is untrusted data, not an all-clear. Missing follow-on execution events are not independent non-execution proof. `not_linked` is a token-binding error signal, not an incident.
