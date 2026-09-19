# Q-SCANNER-WHO

| Item | Value |
|------|--------|
| Query ID | `Q-SCANNER-WHO` |
| Security question | Which scanner ran this scan? |
| Validation status | **VALIDATED** |
| Validation date | 2026-09-16 |
| SPL file | `Q-SCANNER-WHO.spl` |
| Bind token | `__SCAN_ID__` |

## Required fields (indexed names)

`event.name`, `scan_id`, `evidence_class`, `scanner.name`, `scanner.version`, `scanner.repository`, `scanner.commit`, `scanner.wheel_sha256`, `provenance.adapter_version`, `execution.static_scan`, `execution.target_executed`, `execution.network_required`, `execution.llm_used`

## SPL

See `Q-SCANNER-WHO.spl`. Filter `"event.name"=agentsec.scanner.scan` so a zero-finding scan still returns a row.

## Line-by-line explanation

1. Scope `index=agentsec_telemetry sourcetype=agentsec:scanner:finding` and one `scan_id`. `earliest=0` is lab-only.
2. Restrict to the scan-summary event. Findings are a different question (`Q-SCANNER-FINDINGS`).
3. Collapse scalar copies with `mvindex(mvdedup(…),0)` even though live `mvcount` was 1.
4. Table scanner identity and execution flags. Booleans are indexed strings `true`/`false`.

## Expected result

One row per scan that was ingested. Scanner name/version/commit from the Phase 9B pack. `static_scan=true`, `target_executed=false`, `llm_used=false`.

## Actual result

**VALIDATED** (Splunk CLI CSV, 2026-09-16).

| scan_id | scanner_name | version | static_scan | llm_used |
|---------|--------------|---------|-------------|----------|
| `b3061c4e-…c419` NORMAL | `cisco-ai-mcp-scanner` | 4.8.4 | true | false |
| `7ae3ea64-…5ee8` MALICIOUS | `cisco-ai-mcp-scanner` | 4.8.4 | true | false |

Unknown `scan_id`: **0 rows**.

## Validated run.id / test data

Phase 9B packs `docs/phase9b-evidence/normal-b3061c4e-7a81-445c-8fd8-3108dd14c419` and `malicious-7ae3ea64-4e7a-40fe-943f-3e582bce5ee8`. This search does not use `agentsec.run.id`.

## Performance notes

Index + sourcetype + scan_id + one event name. Lab-cheap. `earliest=0` is lab-only.

## Known limitations

Does not prove the scanner process is still running. Does not authorize. Wheel SHA-256 is the pin hash, not a finding.

## No-data semantics

Zero rows means this Splunk copy has no scan-summary event for that `scan_id`. That is **not** zero findings and **not** a clean artifact.
