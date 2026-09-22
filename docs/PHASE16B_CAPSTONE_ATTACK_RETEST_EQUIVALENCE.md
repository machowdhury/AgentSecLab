# Phase 16B — ATTACK / RETEST fingerprint proof

Measured SHA-256 of the frozen RAG-001 malicious document (also the capstone memory fixture body).

| Mode | content.hash | Result |
|------|--------------|--------|
| ATTACK retrieve / write / recall | `sha256:c565f364c7c5fba3cf25d235bb8e2bee7d9433daa9f07d5e097ab6d2a82a97ef` | MEASURED |
| RETEST retrieve / write / recall | `sha256:c565f364c7c5fba3cf25d235bb8e2bee7d9433daa9f07d5e097ab6d2a82a97ef` | MEASURED |
| Comparison | identical | **MATCH** |

Launch ERROR `check_use_mismatch` if retrieve hash ≠ write hash ≠ experiment fingerprint.

Do not infer equivalence from fixture names.

SAME ADVERSARIAL INFLUENCE. DIFFERENT AUTHORIZATION. DIFFERENT EXECUTION.
