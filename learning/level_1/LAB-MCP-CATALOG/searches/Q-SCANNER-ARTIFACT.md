# Q-SCANNER-ARTIFACT

| Item | Value |
|------|--------|
| Query ID | `Q-SCANNER-ARTIFACT` |
| Security question | What artifact did the scanner scan, and how is that artifact identified? |
| Validation status | **VALIDATED** |
| Validation date | 2026-09-16 |
| SPL file | `Q-SCANNER-ARTIFACT.spl` |
| Bind token | `__SCAN_ID__` |

## Required fields (indexed names)

`event.name`, `scan_id`, `artifact.type`, `artifact.sha256`, `artifact.description_sha256`, `artifact.bytes`, `artifact.fixture`, `artifact.tool_count`, `scan.finding_count`, `provenance.raw_output_sha256`

## SPL

See `Q-SCANNER-ARTIFACT.spl`.

## Line-by-line explanation

1. Scope scanner sourcetype and one `scan_id`.
2. Use the scan-summary event so zero-finding scans still show artifact identity.
3. Table both hashes. `artifact.sha256` is the `tools.json` file. `description_sha256` is lookup_policy description UTF-8 bytes.
4. `raw_output_sha256` links to the evidence-bundle raw file; raw stdout is not indexed.

## Expected result

NORMAL: file hash `sha256:d706a2f8…`, description hash `sha256:8a76d34c…` (8D BASELINE), 826 bytes, finding_count 0.

MALICIOUS: file hash `sha256:5e0bf29c…`, description hash `sha256:9d074532…` (8D ATTACK/RETEST), 963 bytes, finding_count 1.

The two hashes on each row must differ.

## Actual result

**VALIDATED** (Splunk CLI CSV, 2026-09-16). Expected hashes and byte counts matched the Phase 9B manifests.

## Validated run.id / test data

Same Phase 9B packs as `Q-SCANNER-WHO`. Runtime correlation uses `description_sha256`, not `artifact.sha256`.

## Performance notes

Index + sourcetype + scan_id. Lab-cheap. `earliest=0` is lab-only.

## Known limitations

Does not prove runtime used the file. File hash is not `agentsec.content.hash`.

## No-data semantics

Zero rows means no indexed scan summary for that `scan_id`. It does not mean the artifact is safe.
