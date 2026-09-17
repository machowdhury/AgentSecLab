# Phase 8D — LAB-MCP-CATALOG live Splunk validation

**Date:** 2026-09-16  
**Schema:** `agentsec.security_event` **1.5.0**  
**Lab:** LAB-MCP-CATALOG specimens; reuse LAB-MCP-001 Q-MCP / DET-MCP-001; one new hunt `Q-MCP-CATALOG-AUTHORITY`  
**Scope:** Fresh LIVE OTLP → collector → HEC → Splunk; field discovery; existing Q-MCP revalidation; catalog-authority hunt; DET-MCP-001 compatibility. **No** Dashboard Studio. **No** DET-MCP-CATALOG. **No** scanner wire-up. **No** rug-pull / `tools/list_changed`. **No** A2A. Runtime and schema **unchanged** in this phase.

Evidence class: **OBSERVED** (runtime + Splunk CLI). Completeness vs local `events.jsonl`: **MEASURED**. DET-MCP-001 / hunt positive-control check: **SIMULATED** (`makeresults`). Phase 8C local-only run IDs are **not** Splunk proof.

Runtime remains authoritative for handler invocation. Splunk is corroboration.

Companion: `docs/MCP_CATALOG_SPLUNK_FIELD_CONTRACT.md`, `docs/MCP_CATALOG_SEARCH_CONTRACT.md`, `docs/reviews/splunk-ko-review-lab-mcp-catalog-2026-09-16.md`.

---

## Schema 1.5.0 SPL compatibility

Inspected all `learning/level_1/LAB-MCP-001/searches/Q-MCP-*.spl` and `DET-MCP-001.spl`.

**None** hardcode `schema.version`. Searches filter `index`, `sourcetype`, `agentsec.run.id`, and `event.name`. Indexed events on these specimens are **1.5.0**. Existing Q-MCP files were **not rewritten**.

---

## Splunk environment

| Item | Value |
|------|--------|
| Index | `agentsec_telemetry` |
| Sourcetype | `otel:agentic:json` |
| Source | `agentsec-otel-collector` |
| Splunk | container `agentsec_splunk` |
| Execution | `splunk search` CLI as user `splunk`, `-output csv` |
| Auth | password stays inside the container (`admin:${SPLUNK_PASSWORD}`). Not passed on the host argv. |
| Lab | `./scripts/lab-up.sh --build` READY; AcmeBank image rebuilt with 8C / 1.5.0 runtime |

Specimens ran in-container Python with OTEL on (`scripts/run_lab_mcp_catalog_live_specimens.py` copied to `/tmp`; image does not copy `scripts/`). Profile switched in-process (`AGENTSEC_SECURITY_PROFILE`) so the HTTP container stayed defended. `export.json` has `otlp.ok=true` and `splunk.verified=false` (honest). Splunk proof is this document’s independent CLI. Do **not** rewrite `splunk.verified` because CLI succeeded.

Official Splunk Agent Skills consulted (read-only, after `.cursor/rules/33-splunk-agent-skills.mdc` and `.cursor/skills/splunk-ko-review/SKILL.md`): Splunk Search, Search Performance Optimizer (notes only; no rewrite), Field Extraction and CIM Mapping, Knowledge Object Governance. `/spl-validate` headings are in the hunt `.md`. AgentSec evidence semantics remain authoritative.

---

## Fresh run IDs

Do not reuse Phase 8C local-only IDs (`e7e35b7c-…`, `414bb714-…`, `39958d1b-…`).

| Spec | Profile | Mode | Fixture | Runtime (authoritative) | Policy / tier handlers | `run.id` |
|------|---------|------|---------|-------------------------|------------------------:|----------|
| **A BASELINE** | defended | BASELINE | NORMAL | METADATA-001 OBSERVE `metadata_is_data`; first `lookup_policy` ALLOW `tool_granted` + execute; no follow-on | **1 / 0** | `d95717ed-ffd2-46c0-a130-9a5d7d539a5d` |
| **B ATTACK** | vulnerable | ATTACK | MALICIOUS | METADATA-001 still OBSERVE; first `lookup_policy` ALLOW + execute; follow-on `lookup_customer_tier` ALLOW `vulnerable_profile_fail_open:metadata_derived_authority`; follow-on handler **1** | **1 / 1** | `a0937bff-31a5-453a-99bf-47d7b5148ce4` |
| **C RETEST** | defended | RETEST | **same MALICIOUS as B** | METADATA-001 OBSERVE; first `lookup_policy` ALLOW + execute; follow-on DENY `tool_not_granted`; follow-on handler **0** | **1 / 0** | `23c222ea-6a87-40b7-a3e9-f12a5b572fa1` |

Initial tool: `lookup_policy` / `policy:read` / `lending-basics`. Follow-on: `lookup_customer_tier` / `customer:read`. Method: `tools/call` on MCP allowlist + execution events (absent on METADATA-001). `agentsec.attack.id=MCP-CATALOG-001`. Schema **1.5.0**. Coded server-owned tools remain `{lookup_policy}`. Trace ids: A `00eaf61d027c31ade288c9bb3c5af3c2`; B `a5bf0ad5763add3da5aaa992c4d0cc81`; C `814133d2028e2545ca3abb9d2f7a4a7a`.

Do **not** summarize A as “safe.” OBSERVE is classification, not a grant.

---

## Transport completeness

| Layer | Status | Class |
|-------|--------|--------|
| Runtime in-container invoke | Decisions and handler counts as table above | OBSERVED in specimen JSON / `manifest.json` |
| Local `events.jsonl` | 8 / 13 / 12 | MEASURED |
| OTLP SDK | `otlp.ok=true` all three packs | OBSERVED in `export.json` |
| HEC → index | `lab-ready.sh` READY; HEC health HTTP 200 | OBSERVED |
| Splunk `dc(_raw)` | equals local unique event count for every run.id | MEASURED |

| Spec | Local | Splunk `dc(_raw)` | Difference | Terminal | Class |
|------|------:|------------------:|-----------:|----------|--------|
| A | 8 | 8 | **0** | `completed_allowed` | **COMPLETE** |
| B | 13 | 13 | **0** | `completed_allowed` | **COMPLETE** |
| C | 12 | 12 | **0** | `completed_denied` | **COMPLETE** |

`stats count` is **not** used for completeness (Phase 2C.1 multivalue duplication). Missing hop-1 `mcp.started` on C is **not** inferred solely from Splunk; local `lookup_customer_tier` handler count is **0**.

---

## Duplicate extraction finding

Phase 2C.1 / 3C / 4C / 5C / 6C / 7C multivalue duplication is **OBSERVED** again. Classification: **B** (one event, repeated identical copies) from **C** (INDEXED_EXTRACTIONS=json + KV_MODE=json, plus OTLP log attributes on some keys). **A** (physical duplicate events) ruled out: `dc(_raw)` equals local count.

On BASELINE A, every event had `mvcount('agentsec.run.id')=3`, `mvcount('event.name')=3`, `mvcount('service.name')=3`, `mvcount('trace_id')=3`. METADATA-001: `mvcount('agentsec.control.decision')=3`, `mvcount('agentsec.mcp.metadata.trust')=2`, `mvcount('agentsec.content.hash')=2`.

Normalize with `mvindex(mvdedup('field'),0)`. **Do not change `props.conf`.**

---

## Field discovery (actual indexed names)

Verified on live A/B/C. Conceptual names that exist **do** appear as expected. See `docs/MCP_CATALOG_SPLUNK_FIELD_CONTRACT.md`.

| Conceptual | Indexed name | Status |
|------------|--------------|--------|
| run identity | `agentsec.run.id` | OBSERVED |
| sequence | `agentsec.sequence` | OBSERVED |
| event name | `event.name` | OBSERVED (not `agentsec.event.name`) |
| service | `service.name` | OBSERVED `acmebank` |
| agent identity | `gen_ai.agent.id` | OBSERVED `acme-agent-mcp-001` |
| tool | `gen_ai.tool.name` | OBSERVED |
| MCP method | `mcp.method.name` | OBSERVED `tools/call` on allowlist + mcp.*; **absent** on METADATA-001 |
| operation | `gen_ai.operation.name` | OBSERVED `execute_tool` on mcp.* |
| profile / mode | `agentsec.security.profile` / `agentsec.testbed.mode` | OBSERVED |
| control id / type / decision / reason | `agentsec.control.*` | OBSERVED including `CTRL-MCP-METADATA-001` / `mcp_metadata_trust` / OBSERVE |
| attempted / executed / outcome | `agentsec.operation.*` | OBSERVED; booleans are Splunk strings `"true"`/`"false"` |
| metadata trust / provenance | `agentsec.mcp.metadata.trust` / `agentsec.mcp.metadata.provenance` | OBSERVED `untrusted_data` / `mcp.catalog.snapshot` on METADATA-001 only |
| content hash / preview | `agentsec.content.hash` / `agentsec.content.preview` | OBSERVED; METADATA-001 hash is the description fingerprint |
| requested / allowed scope | `agentsec.mcp.requested_scope` / `agentsec.mcp.allowed_scope` | OBSERVED on CTRL-MCP-001; **empty** on METADATA-001 |
| resource identity | `agentsec.mcp.resource.id` | OBSERVED on hop-0 CTRL-MCP-001 |
| schema version | `agentsec.schema.version` | OBSERVED **1.5.0** |

**NOT INDEXED / NOT EXTRACTED:** `agentsec.event.name`, `gen_ai.tool.call.id`, `agentsec.mcp.allowed_tools`, `agentsec.mcp.catalog.fixture`, `session.id`, `mcp.session.id`.

No eval alias was invented for missing fields.

---

## BASELINE Splunk result (A)

COMPLETE copy. Sequence 3: METADATA-001 OBSERVE `metadata_is_data`, trust `untrusted_data`, provenance `mcp.catalog.snapshot`, NORMAL hash `sha256:8a76d34c6c21fda0dc930fa2f64fe87c3216f23cbc73ca357c47b0927850d9c3`. Sequence 4: CTRL-MCP-001 ALLOW `tool_granted` for `lookup_policy`. Sequences 5–6: `mcp.started` then `mcp.completed` for `lookup_policy` only. No hop-1 control. No follow-on request.

This is **not** “safe.” Metadata is classified as data. The first tool was legitimately granted.

---

## ATTACK Splunk result (B)

COMPLETE copy. METADATA-001 still OBSERVE `metadata_is_data` (not ALLOW). Description hash `sha256:9d0745320ca79852f2fbd7145bf074fcd353e290c18ba16fd02d801f9f3375b1`. First `lookup_policy` ALLOW `tool_granted` + `mcp.started`/`completed`. Hop-1 CTRL-MCP-001 ALLOW `vulnerable_profile_fail_open:metadata_derived_authority` for `lookup_customer_tier` (`requested_scope=customer:read`, coded `allowed_scope` still `policy:read`). Hop-1 `mcp.started` seq 10 then `mcp.completed` seq 11.

The description itself did **not** receive authorization. Overlay is on CTRL-MCP-001.

---

## RETEST Splunk result (C)

COMPLETE copy. Same MALICIOUS hash as B. METADATA-001 OBSERVE. First `lookup_policy` ALLOW + execute. Hop-1 CTRL-MCP-001 DENY `tool_not_granted`. Indexed hop-1 event is `agentsec.pipeline.stopped` (seq 10). **No** hop-1 `mcp.started` on this COMPLETE copy.

Runtime `lookup_customer_tier` handler count **0** is authoritative non-execution proof. Splunk `followon_execution_observation=no_indexed_followon_execution_event` is corroboration.

---

## ATTACK/RETEST fingerprint proof

**OBSERVED** from indexed METADATA-001 `agentsec.content.hash` (collapsed):

| Spec | Hash |
|------|------|
| A | `sha256:8a76d34c6c21fda0dc930fa2f64fe87c3216f23cbc73ca357c47b0927850d9c3` |
| B | `sha256:9d0745320ca79852f2fbd7145bf074fcd353e290c18ba16fd02d801f9f3375b1` |
| C | `sha256:9d0745320ca79852f2fbd7145bf074fcd353e290c18ba16fd02d801f9f3375b1` |

B == C. Same metadata, different authorization behavior. Not inferred from documentation alone. Proof does **not** use description preview equality.

---

## Existing Q-MCP reuse

| Query | A | B | C | Notes |
|-------|--:|--:|--:|-------|
| Q-MCP-WHO | 2 | 3 | 3 | Extra METADATA-001 row: same tool `lookup_policy`, **empty** `method` (field not on that event) |
| Q-MCP-AUTHZ | 2 | 3 | 3 | Extra METADATA-001 OBSERVE row; hop-1 B ALLOW / C DENY |
| Q-MCP-TOOL | 1 | 2 | 1 | C has only `lookup_policy` start — correct |
| Q-MCP-EXECUTED | 2 | 3 | 3 | Extra METADATA OBSERVE row for `lookup_policy` inherits `mcp.completed` because `eventstats` is `by run_id, tool`. **Do not** read that as metadata authorizing execution. C follow-on: `no_mcp_execution_event` |
| Q-MCP-AFTER-DENY | 0 | 0 | 0 | C DENY then no later mcp.* for that tool |
| Q-MCP-RESULT-TRUST | 1 | 2 | 1 | Result channel only. Do not confuse with metadata trust |
| Q-MCP-PARAMS | 2 | 3 | 3 | Extra row is the description hash **mislabeled** `arguments_hash`. Do not treat as tool arguments |
| Q-MCP-RESULT-AUTHORITY | 0 | 0 | 0 | Looks for RESULT-001; correctly empty |

Existing files were **not modified**. Extra metadata rows are documented, not “fixed” by rewriting Q-MCP.

---

## New catalog hunt decisions

| Candidate | Classification | Action |
|-----------|----------------|--------|
| Q-MCP-CATALOG-METADATA | **SUPPORTED** (fields indexed) / **REDUNDANT** as a second file | Columns on `Q-MCP-CATALOG-AUTHORITY` |
| Q-MCP-CATALOG-TRUST | **SUPPORTED** / **REDUNDANT** as a second file | Same hunt |
| Q-MCP-CATALOG-FINGERPRINT | **SUPPORTED** (hash indexed) / **REDUNDANT** as a join hunt | Two-run CLI compare of `metadata_hash` |
| Q-MCP-CATALOG-FOLLOWON | **SUPPORTED BY EXISTING Q-MCP** | Q-MCP-AUTHZ + Q-MCP-TOOL + hunt followon_* |
| Q-MCP-CATALOG-AUTHZ | **SUPPORTED BY EXISTING Q-MCP** | Q-MCP-AUTHZ hop-1 |
| Q-CATALOG-WHAT-WAS-ADVERTISED | **BLOCKED BY TELEMETRY** | Full catalog list not indexed |
| Q-CATALOG-SCANNER-FINDINGS | **BLOCKED BY TELEMETRY** | Scanners not ingested |

**Created:** `Q-MCP-CATALOG-AUTHORITY` only. Distinct INV-002 reconstruction; required fields OBSERVED live; existing Q-MCP cannot collapse trust+hash+follow-on cleanly; useful to a SOC/learner. Not a detector.

---

## DET-MCP-001 result

File **unchanged**. Scoped CLI on fresh A/B/C: **0 / 0 / 0** rows.

| Spec | Why 0 |
|------|--------|
| A | no DENY |
| B | vulnerability produced ALLOW; execution-after-DENY invariant does not apply |
| C | DENY occurred but no later `mcp.started` |

This is a **detection gap** for catalog poisoning, not a detector failure.

---

## Detection gap analysis

Indexed evidence **does** exist for a lab-shaped predicate: METADATA-001 `untrusted_data` + hop-1 CTRL-MCP-001 ALLOW + reason `vulnerable_profile_fail_open:metadata_derived_authority` + hop-1 `mcp.started`.

That reason is **intentionally lab-generated**. It is a good positive-control teaching signal and a **poor** general production detector for tool-description poisoning (would miss any overlay that does not emit that string; would false-positive if another lab reused the vocabulary).

**DETECTION CANDIDATE JUSTIFIED FOR LATER DESIGN** (lab teaching detector only). General tool-description-poisoning detection remains a gap. **DET-MCP-CATALOG was not implemented.**

---

## Positive control result

No synthetic events were indexed.

| Check | Result |
|-------|--------|
| Generator | `makeresults` |
| `evidence_class` | `SIMULATED` |
| Synthetic `run.id` | `catalog-8d-sim-00000000-0000-0000-0000-000000000001` |
| Indexed `dc(_raw)` for that id | **0** |

Not OBSERVED. Not LIVE. Existing DET-MCP-001 `makeresults` fixture remains the execution-after-DENY teaching control.

---

## Splunk knowledge-object review

Written: `docs/reviews/splunk-ko-review-lab-mcp-catalog-2026-09-16.md`.

Implemented: one hunt file + catalog.json. Not implemented (recommendations only): Dashboard Studio bind, savedsearch packaging, rewriting Q-MCP-EXECUTED for extra METADATA rows, CIM mapping of `agentsec.mcp.metadata.*`.

---

## Performance notes

For `Q-MCP-CATALOG-AUTHORITY`: index + sourcetype + `run.id` + four event names; `eventstats` by `run_id`; no expensive commands listed in the search-quality ban list. Lab copy is 8–13 events. **Performance was not measured** beyond successful CLI elapsed time on this lab. Cheap on lab data is not production validation. `earliest=0` is lab-only.

---

## Limitations

- `export.json` `splunk.verified` stays false.
- No `gen_ai.tool.call.id`; this lab is one catalog snapshot plus at most one follow-on per run.
- Full advertised tool list is not indexed.
- Scanners are not a Splunk sourcetype.
- Q-MCP-EXECUTED extra OBSERVE row can look like metadata “executed.”
- Preview is bounded; hash is the fingerprint.
- Splunk is investigation, not authorization.

---

## Phase 8D verdict

**PASS.** LAB-MCP-CATALOG: **IMPLEMENTED + LOCALLY VALIDATED + SPLUNK VALIDATED**. Detection: **DETECTION ANALYZED — DETECTION CANDIDATE JUSTIFIED FOR LATER DESIGN**. Workshop: **NOT COMPLETE**. Scanner integration: **NOT STARTED**.

STOP. Phase 8E not started.
