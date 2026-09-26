# AgentSec v1.0.0-rc2 — validation

**Date:** 2026-09-26
**Candidate:** v1.0.0-rc2
**Independent review:** `docs/reviews/AGENTSEC_INDEPENDENT_RC2_VALIDATION.md` at `2eb3cce749100b08a5b85c77b615e6924474cbbc`, verdict `GO — CREATE RC2 CANDIDATE`
**Starting product commit:** `973bc00e910ed69b03465080e4dd94f1dab9076d`

This file records release checks. It does not prove production security effectiveness.

## 1. Executive summary

Version identity moved from RC1 to RC2 in the package, the Python module, and the Splunk app. Schema stayed 1.9.0. ExternalEvidence stayed 1.0.0. The seven LIVE labs stayed seven. Offline tests passed. No new LIVE attack was launched for this release. The already-running containers still report `1.0.0rc1` because their images were not rebuilt. UI smoke on that existing Splunk volume loaded the current dashboards at 1440 and 1024 with no page errors and no horizontal overflow.

Release decision: tag `v1.0.0-rc2` on the manifest-stamp commit. BLOCKER 0. HIGH 0.

## 2. Git baseline at start

MEASURED before edits.

| Ref | SHA |
|-----|-----|
| Branch | `develop` |
| HEAD | `2eb3cce749100b08a5b85c77b615e6924474cbbc` |
| origin/develop | `973bc00e910ed69b03465080e4dd94f1dab9076d` |
| main / origin/main | `e6115b6d1c03a1672b4364e84748c7840671fbfc` |
| `v1.0.0-rc1^{}` | `e6115b6d1c03a1672b4364e84748c7840671fbfc` |
| v1 tags | `v1.0.0-rc1` only |

The one-commit gap versus `origin/develop` was the local independent review. It was kept. It was not amended.

## 3. Version identity

| Field | Before | After | Class |
|-------|--------|-------|-------|
| `pyproject.toml` | `1.0.0rc1` | `1.0.0rc2` | CURRENT VERSION FIELD |
| `src/agentsec/__init__.py` | `1.0.0rc1` | `1.0.0rc2` | CURRENT VERSION FIELD |
| Splunk `app.conf` | `1.0.0-rc1` | `1.0.0-rc2` | CURRENT VERSION FIELD |
| `tests/unit/test_phase17d_release.py` | asserted RC1 strings | asserts RC2 strings | CURRENT VERSION FIELD |
| README, Quickstart, Getting Started, matrix, product boundary | said no RC2 tag yet | name this candidate `v1.0.0-rc2` and keep RC1 as the older tag | CURRENT RELEASE IDENTITY |
| `docs/releases/V1_0_0_RC1_*` and prior reviews | unchanged | unchanged | HISTORICAL RC1 |

Runtime schema `SCHEMA_VERSION` is `1.9.0`. `EXTERNAL_CONTRACT_VERSION` is `1.0.0`. Measured in-process: `1.0.0rc2 1.9.0 1.0.0` and 7 LIVE lab ids.

## 4. Invariants

CTRL-MCP-001 remains the tool PDP. This release did not edit authorization, adapters, detectors, dashboards, or schema. Saved searches remain three disabled stanzas. Enabled detectors: none.

## 5. Tests

Focused:

```text
uv run --extra test python -m pytest tests/unit/test_phase17d_release.py tests/unit/test_phase16d_academy.py tests/unit/test_external_evidence.py tests/unit/test_external_evidence_failures.py tests/unit/test_garak_external_evidence.py tests/unit/test_cisco_mcp_scanner.py tests/splunk/test_agentsec_home_dashboard.py tests/splunk/test_threat_modeling.py tests/splunk/test_privacy_data_governance.py tests/splunk/test_multi_stage_incident.py tests/splunk/test_advanced_capstone_mastery.py tests/splunk/test_lab_external_evaluation_garak_dashboard.py tests/unit/test_phase17a_mastery.py -q --tb=line -m "not live_ollama and not live_splunk"
```

Result: 97 passed in 0.55s. TESTED.

Full offline:

```text
uv run --extra test python -m pytest tests -q --tb=line -m "not live_ollama and not live_splunk"
```

Result: 1027 passed, 3 deselected in 13.15s. TESTED. Same pass count as the independent review. Pytest does not prove security effectiveness.

## 6. Live Splunk

OBSERVED on the already-running lab, not a rebuild and not a clean room.

- AcmeBank `/health` 200, `version` `1.0.0rc1`, profile `defended`, Ollama reachable.
- Attack Service `/health` 200, `version` `1.0.0rc1`, `schema_version` `1.9.0`, text `NOT PRODUCTION AUTHENTICATION`.
- Splunk login HTTP 200.

The health version is the image that was already running. Source is now `1.0.0rc2`. Those processes were not rebuilt in this phase. Class: OBSERVED stale image version. Not a claim that the running containers are the RC2 build.

No new LIVE lab was launched. Existing specimen evidence from earlier phases stays historical MEASURED or REPLAYED. It was not re-labeled as a fresh RC2 execution. External Cisco and garak evidence for this candidate remains REPLAYED / pack-based. NOT a fresh tool execution.

## 7. UI smoke

OBSERVED on the existing Splunk volume. Chrome headless. About 2 seconds per view. Page errors: 0.

Views: Home, Direct Prompt Injection, MCP, RAG, Memory, Goal, Identity, garak, Blue Team, L7, L8, L9, L10, Mastery Check.

At 1440 and 1024, each view URL loaded and horizontal overflow was false. Tabs were not all opened. 200% zoom was not repeated. Copy controls were not re-tested beyond native text. Class: PASS for this bounded smoke.

## 8. Accessibility

Screen reader: NOT TESTED. Keyboard was not re-measured. Overall: PARTIAL. Not WCAG.

## 9. Secret hygiene

Release edits were scanned for token, password assignment, private-key, and cloud-key patterns before the release commit. No secret values are written in the release notes, inventory, this file, or the manifest. `.env` is not committed. Class: PASS.

## 10. Links

Relative links in the README, Quickstart, Getting Started, the release matrix, the RC2 release notes, and the RC2 inventory resolved on disk. Class: PASS.

## 11. Known limitations retained

Path B visible. Early answer cards. Abrupt L6 search jump. Two evidence vocabularies. Clean-room not proven. Screen reader not tested. Ollama image unpinned. garak license backlog open. Default branch still `main`. No certification. External findings do not authorize. Empty results are not safe. Production IAM, delegation, and cryptographic identity are not modeled.

## 12. Clean room

NOT PROVEN. Required before final 1.0. Not a stop for this candidate. The independent review allowed it.

## 13. Release decision

No BLOCKER. No HIGH. Tag `v1.0.0-rc2` after the manifest stamp. Do not merge `main`. Do not create a GitHub Release. Do not tag `v1.0.0`.
