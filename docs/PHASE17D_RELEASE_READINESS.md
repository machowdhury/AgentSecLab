# Phase 17D — Release readiness

**Date:** 2026-09-21 (session continued 2026-09-22 UTC)  
**Predecessor:** Phase 17C PASS (technical correctness). Schema **1.9.0**. Product **1.0.0-rc1**.  
**Verdict:** PASS — **READY FOR v1.0.0-rc1**  
**Not claimed:** production product, GitHub Release, git tag `v1.0.0`, Phase 18.

## Predecessor verification (inspected)

Implementation status documented 16D/17A/17B/17C. Curriculum LIVE/REPLAY matches published nav. Attack Service was rebuilt from repository (`./scripts/lab-up.sh --build`). HTTP 200 on :5001 includes ATLAS **REQUIRES REVALIDATION** / `AML.T0054`.

## Architecture freeze

`coded_policy()`, CTRL-* ownership, ExperimentContext, launch contract, DET-MCP-001-only detector packaging, schema 1.9.0: **unchanged**. Pytest 940 passed / 2 deselected.

## Reproducibility

**PARTIALLY REPRODUCED / CURRENT-ENVIRONMENT VALIDATED.** Images for AcmeBank and Attack Service rebuilt from git. Splunk volume and indexed history were reused. **NOT FULLY CLEAN-ROOM VALIDATED.**

## Release-candidate recommendation

READY FOR v1.0.0-rc1. Do not tag `v1.0.0`. Do not declare production readiness.

Companion reports in this directory: `PHASE17D_*.md`, `docs/reviews/ui-review-agentsec-release-17d-2026-09-21.md`.
