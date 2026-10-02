# AgentSec v1.1.0 — validation

This file records the v1.1.0 qualification. The first confirmation series failed and blocked the tag. The attribution fix was then measured. The failed series is kept below. It is not a pass.

## Candidate

| Check | Result |
|-------|--------|
| Reviewed candidate | `9aaab66ce9d7f72c00439de9af94487389f4e0ac` |
| `develop` at qualification start | that commit |
| `main` at qualification start | `15f379e37773f250f70bc43270e64325590525e4` |
| `v1.0.0^{}` | `537be71a13a5776c42a59ee9a25e2d4051d34ad0` |
| `v1.0.0-rc1^{}` | `e6115b6d1c03a1672b4364e84748c7840671fbfc` |
| `v1.0.0-rc2^{}` | `1be214b92f840f843aaf27fb2b9536f764dd7126` |
| `v1.0.0-rc3^{}` | `6c7af8e87f96cda4ee929664fbb17ec763dd135c` |
| Schema / ExternalEvidence | `1.9.0` / `1.0.0` |
| DET-MCP-001 | `disabled = 1`, `enableSched = 0` |
| Untracked and not released | `docs/plans/`, `docs/reviews/AGENTSEC_REMOTE_DEPLOYMENT_VALIDATION.md` |

## Offline suite

Command: `uv run --extra test python -m pytest tests -q --tb=line -m "not live_ollama and not live_splunk"`

One run before the reliability loop: `1085 passed, 3 deselected` in 8.67s.

First ten consecutive runs on the version-aligned tree, 2026-10-02, were clean. A confirmation series on the same tree was not. Reliability is not a pass.

| Run | Result | Time |
|-----|--------|------|
| 1 | 1085 passed, 3 deselected, 0 failed | 8.03s |
| 2 | 1085 passed, 3 deselected, 0 failed | 9.30s |
| 3 | 1085 passed, 3 deselected, 0 failed | 8.64s |
| 4 | 1085 passed, 3 deselected, 0 failed | 8.08s |
| 5 | 1085 passed, 3 deselected, 0 failed | 7.84s |
| 6 | 1085 passed, 3 deselected, 0 failed | 8.10s |
| 7 | 1085 passed, 3 deselected, 0 failed | 8.82s |
| 8 | 1085 passed, 3 deselected, 0 failed | 9.37s |
| 9 | 1085 passed, 3 deselected, 0 failed | 8.39s |
| 10 | 1085 passed, 3 deselected, 0 failed | 8.65s |

Confirmation series on the release-document tree, same command:

| Run | Result | Time |
|-----|--------|------|
| 1 | 1085 passed, 3 deselected, 0 failed | 9.16s |
| 2 | 1085 passed, 3 deselected, 0 failed | 8.30s |
| 3 | 1085 passed, 3 deselected, 0 failed | 9.82s |
| 4 | 1085 passed, 3 deselected, 0 failed | 8.50s |
| 5 | 1085 passed, 3 deselected, 0 failed | 9.02s |
| 6 | 1085 passed, 3 deselected, 0 failed | 8.92s |
| 7 | 1085 passed, 3 deselected, 0 failed | 8.92s |
| 8 | 1085 passed, 3 deselected, 0 failed | 8.86s |
| 9 | 1085 passed, 3 deselected, 0 failed | 8.68s |
| 10 | 1 failed, 1084 passed, 3 deselected | 9.75s |

Run 10 of that confirmation series failed `tests/unit/test_phase15b_rag_learning_loop.py::test_concurrent_rag_attack_and_retest_do_not_leak_profile` at `assert retest["runtime"]["lookup_customer_tier_handler_count"] == 0` (`assert 1 == 0`). The profile and mode assertions above that line had already passed. The assertion was not weakened. That series is not a reliability pass. The tag was not created from it.

## After request-scoped attribution

The original test, 100 consecutive pytest processes, each exit examined without a masking pipeline: 100 passed, 0 failed. Pytest exit code was 0 for the stress script.

One full offline suite after the fix: `1086 passed, 3 deselected` in 8.72s. Process exit code 0.

Ten consecutive full suites after the fix. Each line is pytest's own exit code:

| Run | Exit | Result |
|-----|------|--------|
| 1 | 0 | 1086 passed, 3 deselected, 0 failed, 9.39s |
| 2 | 0 | 1086 passed, 3 deselected, 0 failed, 8.46s |
| 3 | 0 | 1086 passed, 3 deselected, 0 failed, 9.19s |
| 4 | 0 | 1086 passed, 3 deselected, 0 failed, 9.41s |
| 5 | 0 | 1086 passed, 3 deselected, 0 failed, 9.26s |
| 6 | 0 | 1086 passed, 3 deselected, 0 failed, 9.87s |
| 7 | 0 | 1086 passed, 3 deselected, 0 failed, 9.26s |
| 8 | 0 | 1086 passed, 3 deselected, 0 failed, 9.34s |
| 9 | 0 | 1086 passed, 3 deselected, 0 failed, 9.00s |
| 10 | 0 | 1086 passed, 3 deselected, 0 failed, 8.89s |

10/10. The extra passing test is `test_concurrent_rag_attribution_is_request_scoped`. No assertion was weakened. The three deselected tests remain the live Ollama, live Splunk, and live scanner markers.

That 10/10 series ran on the sources committed as `1c87dd9d5236fd51430d3a35fca37edb42cf0b1b`. A later documentation commit records the live search and does not change that code.

## Live search

The existing lab was fast-forwarded to `1c87dd9` and rebuilt with `./scripts/lab-up.sh --build --refresh-app --remote`. Volumes were not deleted. This is not a fresh-volume clean-room. Precheck result was WARN because the AgentSec ports were already published. Exit code 0. WARN is not PASS.

AcmeBank `/health` reported version `1.1.0`, status `healthy`, `ollama_reachable` true. Attack Service `/health` reported version `1.1.0`, status `healthy`. The Splunk app `app.conf` inside the container was `version = 1.1.0`. Model name `llama3.2:1b` was listed. Generation quality was NOT MEASURED. SERVICE READY is not searchable evidence. HEC HTTP 200 is not indexed evidence.

Splunk Search then returned indexed rows for the four run ids in the concurrency remediation review. RESOURCE IMPACT: NOT PROVEN.

## Not claimed

Screen reader: NOT TESTED. Physical keyboard: NOT MEASURED. True browser 200% zoom: NOT MEASURED. No WCAG claim. A clean-room clock for v1.1.0 is NOT BENCHMARKED until a fresh-volume run is recorded. The 2026-10-02 v1.0.0 clean-room is historical.
