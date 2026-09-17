# Q-SCANNER-RUNTIME-CORRELATION

| Item | Value |
|------|--------|
| Query ID | `Q-SCANNER-RUNTIME-CORRELATION` |
| Security question | Which runtime catalog observations correspond to the scanned artifact by description hash? |
| Validation status | **VALIDATED** |
| Validation date | 2026-09-16 |
| SPL file | `Q-SCANNER-RUNTIME-CORRELATION.spl` |
| Bind token | `__DESCRIPTION_SHA256__` |

## Required fields (indexed names)

Scanner: `artifact.description_sha256`, `event.name`, `scan_id`, `artifact.fixture`, `scan.finding_count`, `scan.classification`.

Runtime: `agentsec.content.hash`, `event.name`, `agentsec.run.id`, `agentsec.control.id`, `agentsec.control.decision`, `agentsec.control.reason`, `agentsec.mcp.metadata.trust`, `agentsec.testbed.mode`, `agentsec.security.profile`.

## SPL

See `Q-SCANNER-RUNTIME-CORRELATION.spl`. OR of two sourcetypes + `stats` by unified hash. No `join`, `transaction`, `map`, or `append`.

## Line-by-line explanation

1. Scope `index=agentsec_telemetry` and **either** a scanner scan-summary with matching `artifact.description_sha256` **or** a METADATA-001 control event with matching `agentsec.content.hash`.
2. Unify the hash into `corr`. Do not use `artifact.sha256` here.
3. Label `evidence_kind` scanner vs runtime.
4. `stats values(...)` by `corr` so missing sides stay visible as empty `values()`.

## Expected result

NORMAL description hash: scanner scan `b3061c4e-…` fixture NORMAL finding_count 0 **and** BASELINE run `d95717ed-…` METADATA-001 OBSERVE.

MALICIOUS description hash: scanner scan `7ae3ea64-…` DETECTED_BY_SCANNER finding_count 1 **and** ATTACK `a0937bff-…` plus RETEST `23c222ea-…` METADATA-001 OBSERVE on both.

`tools.json` SHA-256 used as this token: **0 rows** (wrong hash semantics).

## Actual result

**VALIDATED** (Splunk CLI CSV, 2026-09-16).

NORMAL hash: evidence_kinds `runtime scanner`; run_id BASELINE; metadata_decision OBSERVE; finding_count 0.

MALICIOUS hash: evidence_kinds `runtime scanner`; run_ids ATTACK and RETEST; modes `ATTACK RETEST`; profiles `defended vulnerable`; scanner_classification `DETECTED_BY_SCANNER`; metadata_decision OBSERVE on both. Follow-on ALLOW vs DENY is **not** this search — reuse `Q-MCP-CATALOG-AUTHORITY` / `Q-MCP-AUTHZ`.

File-hash token `sha256:5e0bf29c…`: **0 rows**.

## Validated run.id / test data

8D runs BASELINE / ATTACK / RETEST. Phase 9B scans NORMAL / MALICIOUS. Hash equality is description UTF-8 bytes, not whole-file bytes.

## Performance notes

Index + two sourcetype predicates + exact hash. Tiny lab volume. `earliest=0` is lab-only. Not a production join pattern claim.

## Known limitations

Does not answer ATTACK vs RETEST authorization. Does not treat scanner HIGH as DENY. `values()` order is Splunk's, not time order. METADATA-001 is OBSERVE on both profiles.

## No-data semantics

Zero rows means no indexed scanner scan **and** no indexed METADATA-001 with that description hash. That is not "the artifact is clean." Scanner-only or runtime-only would still produce a row with one `evidence_kind`.
