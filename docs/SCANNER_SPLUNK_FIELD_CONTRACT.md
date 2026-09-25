# Scanner Splunk field contract

**Status:** Phase 9C **VALIDATED** against live Splunk (2026-09-16).  
**Sourcetype:** `agentsec:scanner:finding`  
**Index:** `agentsec_telemetry`  
**Schema:** independent of `agentsec.security_event` **1.5.0**. Scanner fields are **not** on `otel:agentic:json`.

Discovery method: Splunk `fieldsummary` plus `mvcount` / `dc(_raw)` on the ingested Phase 9B packs. Do not invent aliases to match this table.

---

## Event model (locked before SPL)

| event.name | When | Count on 9C specimens |
|------------|------|------------------------|
| `agentsec.scanner.scan` | Always, one per scan | 2 (NORMAL + MALICIOUS) |
| `agentsec.scanner.finding` | One per normalized finding | 1 (MALICIOUS only) |

Zero findings ≠ no scan. The NORMAL specimen is a scan event with `scan.finding_count=0` and **no** finding event.

---

## Hash semantics

| Field | Bytes hashed | 9C NORMAL | 9C MALICIOUS |
|-------|--------------|-----------|--------------|
| `artifact.sha256` | entire exported `tools.json` | `sha256:d706a2f8…bac60` | `sha256:5e0bf29c…84cb7` |
| `artifact.description_sha256` | `lookup_policy` description UTF-8 only | `sha256:8a76d34c…0d9c3` | `sha256:9d074532…375b1` |

`artifact.description_sha256` is the honest join key to runtime `agentsec.content.hash`.

`artifact.sha256` is **not** equal to `agentsec.content.hash`. Using the MALICIOUS file hash as `Q-SCANNER-RUNTIME-CORRELATION`'s token returned **0 rows** (MEASURED).

---

## Indexed field discovery

| Expected (9B pack) | Indexed name | Cardinality (3 events) | Multivalue | Missing behavior |
|--------------------|--------------|------------------------|------------|------------------|
| scan_id | `scan_id` | 2 | mvcount=1 | — |
| evidence_class | `evidence_class` | 1 (`OBSERVED_SCANNER`) | 1 | — |
| scanner.name | `scanner.name` | 1 | 1 | — |
| scanner.version | `scanner.version` | 1 (`4.8.4`) | 1 | — |
| scanner.repository | `scanner.repository` | 1 | 1 | — |
| scanner.commit | `scanner.commit` | 1 | 1 | — |
| scanner.wheel_sha256 | `scanner.wheel_sha256` | 1 | 1 | — |
| artifact.type | `artifact.type` | 1 | 1 | — |
| artifact.sha256 | `artifact.sha256` | 2 | 1 | — |
| artifact.bytes | `artifact.bytes` | 2 (numeric) | 1 | — |
| artifact.fixture | `artifact.fixture` | 2 | 1 | — |
| artifact.description_sha256 | `artifact.description_sha256` | 2 | 1 | — |
| artifact.tool_count | `artifact.tool_count` | 1 (`2`) | 1 | — |
| execution.static_scan | `execution.static_scan` | 1 (`true` string) | 1 | — |
| execution.target_executed | `execution.target_executed` | 1 (`false`) | 1 | — |
| execution.network_required | `execution.network_required` | 1 (`false`) | 1 | — |
| execution.llm_used | `execution.llm_used` | 1 (`false`) | 1 | — |
| execution.exit_code | `execution.exit_code` | 1 (`0`) | 1 | Present on scan events only (count=2) |
| execution.timed_out | `execution.timed_out` | 1 (`false`) | 1 | Present on scan events only |
| provenance.raw_output_sha256 | `provenance.raw_output_sha256` | 2 | 1 | — |
| provenance.adapter_version | `provenance.adapter_version` | 1 (`9b.1`) | 1 | — |
| scan.finding_count | `scan.finding_count` | 2 (`0` and `1`) | 1 | Present on scan events only |
| scan.classification | `scan.classification` | 1 (`DETECTED_BY_SCANNER`) | 1 | **ABSENT** on NORMAL (null omitted) |
| finding.native_rule_id | `finding.native_rule_id` | 1 | 1 | Finding events only |
| finding.native_category | `finding.native_category` | 1 | 1 | Finding events only |
| finding.native_severity | `finding.native_severity` | 1 (`HIGH`) | 1 | Finding events only; **not remapped** |
| finding.native_confidence | — | — | — | **NOT INDEXED / ABSENT FROM SOURCE** |
| finding.title | `finding.title` | 1 | 1 | Finding events only |
| finding.summary | `finding.summary` | 1 (bounded native) | 1 | Finding events only; not a required hunt column |
| finding.tool_name | `finding.tool_name` | 1 | 1 | Finding events only |
| finding.analyzer | `finding.analyzer` | 1 | 1 | Finding events only |
| event.name | `event.name` | 2 | 1 | — |
| timestamp | `timestamp` | 2 | 1 | Pack `created_at` |

Default Splunk fields also present: `host=agentsec-scanner`, `source=agentsec-scanner-hec`, `sourcetype=agentsec:scanner:finding`, `index=agentsec_telemetry`.

## P0 additive nested fields (unit-tested)

HEC now also emits `external.*` and `correlation.*` (contract 1.0.0). These were **not** part of the 2026-09-16 live `fieldsummary`. Do not treat them as MEASURED in Splunk until re-ingest.

| Nested field | Meaning |
|--------------|---------|
| `external.evidence_class` | Contract class (`finding` for Cisco P0) |
| `external.producer_class` | Honesty label (`OBSERVED_SCANNER`) |
| `external.provider` / `tool` / `tool_version` | Provenance |
| `external.raw_evidence_sha256` | Hash of `raw/scanner-output.json` |
| `correlation.method` | `hash_join` |
| `correlation.key` | `description_sha256/content.hash` |
| `correlation.value` | same as `artifact.description_sha256` |

Top-level `evidence_class` remains `OBSERVED_SCANNER` so Q-SCANNER-WHO stays compatible.

## Not indexed (by design)

artifact.path, execution.argv, execution.binary, raw stdout/stderr, full tool descriptions, `agentsec.run.id`, `agentsec.schema.version`, `agentsec.control.decision`.

Live `dc(agentsec.schema.version)=0` on this sourcetype. Live `dc(_raw)=0` for these scan_ids on `otel:agentic:json`.

---

## Multivalue / duplication

Runtime `otel:agentic:json` historically showed INDEXED_EXTRACTIONS + KV_MODE duplication (`mvcount=3`).

Scanner props: `INDEXED_EXTRACTIONS=json` and `KV_MODE=none`.

MEASURED on these 3 events: `mvcount(scanner.name)=1`, `mvcount(scan_id)=1`, `mvcount(event.name)=1`, `mvcount(artifact.description_sha256)=1`, `mvcount(finding.native_severity)=1` on the finding event.

`dc(_raw)=3` and `count=3`. No extra physical copies.

Hunts still use `mvindex(mvdedup(…),0)` as defense in depth.

---

## Booleans

Indexed as JSON strings `true` / `false`, not `1` / `0`. Compare accordingly.

---

## CIM

**NOT APPLICABLE.** YARA `PROMPT INJECTION` / native `HIGH` is not an honest CIM Malware, IDS, or Authentication mapping. Do not force it.

---

## Privacy

Indexed: hashes, native rule identifiers, bounded finding summary (`Detected 1 threat: prompt injection`).

Not indexed: full catalog descriptions, raw scanner JSON (including formatter `server_url` noise), argv paths, secrets.
