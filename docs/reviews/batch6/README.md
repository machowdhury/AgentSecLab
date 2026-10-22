# Batch 6 review pack

| File | Contents |
|---|---|
| `CONTROL_MATRIX_30.md` | The 30 original concepts in their six categories, each classified from source and tests (4 VERIFIED LIVE, 18 PARTIAL, 1 REPLAY, 2 CONTENT-ONLY, 5 MISSING) |
| `VERIFIER_SECURITY.md` | Bridge v2: host-only signing, read-only receipts, lifecycle fixes, residual risks, migration notes |
| `COLD_START_PREFLIGHT.md` | Written isolation proof, written before the cold start |
| `COLD_START_RESULTS.md` | What the disposable copy showed, cleanup and before/after comparison |
| `pilot/` | Five-person pilot package. **NOT CONDUCTED** |
| `cold_start/` | Browser journey screenshots and run JSON from the disposable copy |

Corrections to Batch 5: its C5/C6 notes said the branch might lack the HTTPS-HEC work. The branch does contain it
(`scripts/hec-certs.sh`, `d2da328`); the develop tree's separate uncommitted edits are what a merge would have to reconcile.
Its B5-V1 to V4 and T1 to T3 findings are fixed in Batch 6 (see `VERIFIER_SECURITY.md`); the xfail probes were replaced by passing tests.
