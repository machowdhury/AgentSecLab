# AgentSec v1.1.0 — final review

Reviewed candidate: `9aaab66ce9d7f72c00439de9af94487389f4e0ac`

Independent pilot verdict accepted as given: PASS — READY FOR v1.1.0 RELEASE QUALIFICATION. BLOCKER 0, HIGH 0, MEDIUM 0, LOW 2. This qualification does not regrade that pilot.

## Version alignment

| Location | Why it changed |
|----------|----------------|
| `pyproject.toml` | Package version is the product version. |
| `src/agentsec/__init__.py` | Runtime `__version__` reported by the services. |
| `splunk_app/agentsec/default/app.conf` | Splunk app launcher version. |
| `tests/unit/test_phase17d_release.py` | The release test locks the product version and still locks schema `1.9.0`. |
| `README.md`, `docs/GETTING_STARTED.md`, `docs/QUICKSTART.md`, `docs/ARCHITECTURE.md`, `CHANGELOG.md`, `docs/KNOWN_LIMITATIONS.md` | Learner-facing current release identity. Historical `v1.0.0` and RC tags stay historical. |
| `docs/releases/V1_1_0_*.md` | Release notes, inventory, validation, manifest, and this review. |

Not changed: `SCHEMA_VERSION` `1.9.0`, `EXTERNAL_CONTRACT_VERSION` `1.0.0`, DET-MCP-001, CTRL-MCP-001, historical release notes, and historical review records.

## Accepted debt

- Dashboard Studio native tab focus: PLATFORM LIMITATION — SPLUNK 10.2. Not an AgentSec stylesheet defect.
- Screen reader: NOT TESTED.
- Physical keyboard Tab: NOT MEASURED.
- True browser 200% zoom: NOT MEASURED.
- Podman: NOT VALIDATED. Windows: NOT VALIDATED. Hardware minimums: NOT BENCHMARKED.
- `ollama/ollama:latest` remains unpinned. A model-pull TLS failure is an external dependency. DEGRADED is not PASS.

## Gate

The pre-fix confirmation series failed and is recorded in `V1_1_0_VALIDATION.md`. It was not erased.

After request-scoped handler attribution: original concurrency test 100/100, one full suite `1086 passed, 3 deselected`, and a later 10/10 full-suite series, each with pytest exit code 0. CTRL-MCP-001 was not modified. Schema stays `1.9.0`. ExternalEvidence stays `1.0.0`. DET-MCP-001 stays disabled.

A rebuilt existing lab, not a fresh-volume clean-room, produced four overlapping launches. Splunk Search indexed the CTRL-MCP-001 decision separately from `agentsec.mcp.started` on the ATTACK run. The RETEST run's indexed event names did not include `agentsec.mcp.started`. RESOURCE IMPACT: NOT PROVEN.
