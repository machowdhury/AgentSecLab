# PHASE 9C — scanner evidence Splunk validation

**Date:** 2026-09-16  
**Verdict:** **PASS — SCANNER EVIDENCE SPLUNK VALIDATED**  
**Evidence class:** OBSERVED_SCANNER (9B packs) ingested LIVE; runtime correlation MEASURED against existing 8D OBSERVED_RUNTIME specimens.  
**Boundary:** SCANNER FINDING != AUTHORIZATION DECISION (scanner finding is not an authorization decision).  
**Schema:** `agentsec.security_event` remains **1.5.0**. Scanner events are **not** that schema.

Do not treat this file as Phase 9D, a detector, or a Dashboard Studio workshop.

Canonical IDs (unabbreviated):

- NORMAL scan `b3061c4e-7a81-445c-8fd8-3108dd14c419` description `sha256:8a76d34c6c21fda0dc930fa2f64fe87c3216f23cbc73ca357c47b0927850d9c3` file `sha256:d706a2f8f8476ed0a972d2b7f371a42450addbfbafa2448488d8223e370bac60`
- MALICIOUS scan `7ae3ea64-4e7a-40fe-943f-3e582bce5ee8` description `sha256:9d0745320ca79852f2fbd7145bf074fcd353e290c18ba16fd02d801f9f3375b1` file `sha256:5e0bf29c6546a9a3d791918b59f7f6a99ac09dd9462f3295be8cbacc64c84cb7`
- BASELINE `d95717ed-ffd2-46c0-a130-9a5d7d539a5d` · ATTACK `a0937bff-31a5-453a-99bf-47d7b5148ce4` · RETEST `23c222ea-6a87-40b7-a3e9-f12a5b572fa1`

---

## Event model (decided before SPL)

Smallest useful model:

1. **Scan summary** (`event.name=agentsec.scanner.scan`) — always one per scan, including `scan.finding_count=0`.
2. **Finding** (`event.name=agentsec.scanner.finding`) — one per normalized finding.

One sourcetype: `agentsec:scanner:finding` (9A candidate, accepted). Same index `agentsec_telemetry`. Transport: HEC per-event sourcetype override. Not OTLP. Not `otel:agentic:json`.

---

## Ingestion architecture

Phase 9B JSON packs → `agentsec.scanners.hec_events` (normalized HEC envelopes) → HTTP HEC `http://127.0.0.1:8088/services/collector/event` → index `agentsec_telemetry` / sourcetype `agentsec:scanner:finding`.

`props.conf` stanza: `INDEXED_EXTRACTIONS=json`, `KV_MODE=none`.

Raw scanner stdout stays in `docs/phase9b-evidence/*/raw/` and is linked by `provenance.raw_output_sha256`.

After Splunk restart, HEC SSL had come back on (HTTPS health 200, HTTP reset). Existing `splunk_hec_init` restored in-mesh HTTP. That is lab HEC bootstrap, not a runtime authorization change.

---

## Sourcetype result

**Accepted:** `agentsec:scanner:finding`

Live `sourcetype` cardinality on these events: 1. Scan_ids are **not** present on `otel:agentic:json` (`dc(_raw)=0`).

Macro `agentsec_index` remains `sourcetype=otel:agentic:json` and was **not** widened.

---

## Live scanner evidence

Canonical 9B packs only:

| Fixture | scan_id | Local events | HEC HTTP | Splunk `dc(_raw)` | Transport |
|---------|---------|--------------|----------|-------------------|-----------|
| NORMAL | `b3061c4e-7a81-445c-8fd8-3108dd14c419` | 1 scan | 200 | 1 | **COMPLETE** |
| MALICIOUS | `7ae3ea64-4e7a-40fe-943f-3e582bce5ee8` | 1 scan + 1 finding | 200, 200 | 2 | **COMPLETE** |

Total local 3, submitted 3, Splunk `dc(_raw)=3` and `count=3`. Incomplete leftover 9B directories without manifests were **not** ingested.

---

## Transport completeness

| Specimen | Local normalized | Submitted | `dc(_raw)` | Status |
|----------|------------------|-----------|------------|--------|
| NORMAL | 1 | 1 | 1 | COMPLETE |
| MALICIOUS | 2 | 2 | 2 | COMPLETE |

Do not use `stats count` alone: here `count` happened to equal `dc(_raw)`. Completeness claim uses `dc(_raw)`.

---

## Field discovery / multivalue

See `docs/SCANNER_SPLUNK_FIELD_CONTRACT.md`. MEASURED `mvcount=1` on identity fields. No runtime-class-B duplication on this sourcetype.

`finding.native_confidence`: NOT INDEXED / ABSENT FROM SOURCE. Not invented.

Native severity `HIGH` preserved. No AgentSec severity alias.

---

## NORMAL scan Splunk result

Scan ran. Fixture NORMAL. File `sha256:d706a2f8…`. Description `sha256:8a76d34c…`. finding_count **0**. `finding_state=scan_executed_zero_findings`. Classification omitted (null in pack). Scanner 4.8.4 static YARA, no LLM, target not executed.

## MALICIOUS scan Splunk result

Scan ran. Fixture MALICIOUS. File `sha256:5e0bf29c…`. Description `sha256:9d074532…`. finding_count **1**. Classification `DETECTED_BY_SCANNER`. Finding: native rule/category/title `PROMPT INJECTION`, native severity `HIGH`, tool `lookup_policy`, analyzer `yara_analyzer`.

---

## Artifact identity / hash semantics

Description hashes match 8D `agentsec.content.hash` for BASELINE vs ATTACK/RETEST.

File hashes do **not** match those content hashes. Correlation token = file hash → **0 rows**.

---

## Zero-finding semantics

| State | How Splunk shows it |
|-------|---------------------|
| Scanner executed + zero findings | `Q-SCANNER-FINDINGS` one row, `scan_executed_zero_findings` |
| Scanner evidence missing | 0 rows for that `scan_id` (MEASURED unknown UUID) |
| Finding present | `finding_present` plus scan summary `scan_executed_with_findings` |
| Scanner error | Would require `scan.parse_error` on a scan event (not in these packs) |

Not collapsed to PASS/FAIL.

---

## Runtime correlation / ATTACK vs RETEST

`Q-SCANNER-RUNTIME-CORRELATION` on MALICIOUS description hash: scanner + ATTACK run `a0937bff-…` + RETEST run `23c222ea-…`. METADATA-001 OBSERVE / `metadata_is_data` / `untrusted_data` on both.

Reused LIVE (unchanged SPL):

| Mode | Follow-on CTRL-MCP-001 | Execution observation |
|------|------------------------|------------------------|
| ATTACK vulnerable | ALLOW `vulnerable_profile_fail_open:metadata_derived_authority` | `mcp.completed_observed` |
| RETEST defended | DENY `tool_not_granted` | `no_indexed_followon_execution_event` |

Same description hash. Scanner HIGH describes the artifact. Runtime describes what happened. **Scanner evidence did not authorize either run.**

NORMAL description hash correlates to BASELINE `d95717ed-…` only.

---

## Splunk questions and searches

Published: `Q-SCANNER-WHO`, `Q-SCANNER-ARTIFACT`, `Q-SCANNER-FINDINGS`, `Q-SCANNER-RUNTIME-CORRELATION`.

Reused: `Q-MCP-WHO` (available), `Q-MCP-AUTHZ`, `Q-MCP-EXECUTED`, `Q-MCP-CATALOG-AUTHORITY`.

Rejected: `Q-SCANNER-PASS-FAIL`, `DET-SCANNER-*`, `DET-MCP-CATALOG`, file-hash correlation hunt, rewriting Q-MCP-AUTHZ / Q-MCP-CATALOG-AUTHORITY.

Every published search was executed LIVE. Details: `docs/SCANNER_SEARCH_CONTRACT.md` and adjacent `.md` files (`/spl-validate` headings).

---

## CIM review

**NOT APPLICABLE.** Consulted Field Extraction and CIM Mapping skill via `.cursor/skills/splunk-ko-review/reference.md`. Do not map YARA prompt-injection native findings to Malware/IDS.

---

## Splunk knowledge-object review

`docs/reviews/splunk-ko-review-scanner-evidence-2026-09-16.md`

Objects reviewed: sourcetype/props, four hunts, reuse of Q-MCP, DET-MCP-001 unchanged, no Studio, no saved-search detector, no lookup, no data model, `agentsec_index` unchanged.

---

## Performance notes

Lab CLI on 3 scanner events plus existing catalog runs. `earliest=0` lab-only. No join/transaction/map/append. **NOT MEASURED** as production scale.

---

## Security semantics review

- CTRL-MCP-001 unchanged.
- CTRL-MCP-METADATA-001 unchanged.
- AllowTicket / `coded_policy()` not imported by HEC adapter.
- DET-MCP-001 unchanged (no `scanner` in file).
- SCANNER FINDING ≠ AUTHORIZATION DECISION.
- Scanner PASS (zero findings) ≠ trusted.
- Scanner FAIL (HIGH) ≠ DENY.
- Scanner silence (0 search rows) ≠ safe.
- Scanner finding ≠ execution.
- Splunk ≠ authorization.

---

## Test results

Offline pytest MEASURED after this phase (see `docs/IMPLEMENTATION_STATUS.md` last pytest line). Offline tests do not substitute for the LIVE CLI results above.

---

## Limitations

- Tiny lab volume.
- One scanner (Cisco mcp-scanner 4.8.4 static YARA).
- HEC SSL can re-enable across Splunk restart; lab HTTP restore is operational, not a security control.
- `values()` order is not ATTACK-before-RETEST.
- `finding.summary` is indexed but not a required hunt column.
- Incomplete leftover pack directories under `docs/phase9b-evidence/` were ignored.

---

## Stop

Phase 9D not started. No detector. No Studio. No Snyk Agent Scan. No rug-pull. No A2A.
