# Evaluation and risk

## EVAL Center (`/learn/evals`)
Experiments are recorded, simulated or documented. Each states its source, hash and limitations. Comparisons show differences between recorded runs; they are not statistical results, scores or rates. No run has an independent verifier receipt, so all are `NOT_VERIFIED`.

## Risk Center (`/learn/risk`)
Every field shows its origin: SOURCE (from committed evidence), DERIVED (computed from source), ANALYST (you wrote it), or MISSING. Likelihood and impact levels come only from analyst entries; the 3×3 matrix is qualitative. Drafts stay in the browser with a checksum for integrity; the checksum is not a signature or an approval. Import and export use a strict schema.

Export checks: `PYTHONPATH=src python scripts/export_evals.py --check`, `... scripts/export_risk.py --check`.
