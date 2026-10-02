# AgentSec v1.0.0 — validation

This file records what was run. The annotated tag is created after the commit that contains this file is on `main`.

## Qualification (before the version string changed)

| Check | Result |
|-------|--------|
| Qualification commit | `4c2f7929a7dd0d6d14b06de35c0b5383af11ed52` |
| Peeled RC1 | `e6115b6d1c03a1672b4364e84748c7840671fbfc` |
| Peeled RC2 | `1be214b92f840f843aaf27fb2b9536f764dd7126` |
| Peeled RC3 | `6c7af8e87f96cda4ee929664fbb17ec763dd135c` |
| Offline suite ×10 | each `1065 passed, 3 deselected`, exit 0 |
| Wheel at qualification | `agentsec-1.0.0rc3-py3-none-any.whl` |
| Schema / ExternalEvidence | `1.9.0` / `1.0.0` |
| Clean-room service start | PROVEN, 2026-10-02, new volumes |
| AcmeBank on that run | degraded, model not listed |
| Attack Service on that run | healthy, `1.0.0rc3`, schema `1.9.0` |
| Model pull inside Ollama | FAIL, `x509: certificate signed by unknown authority` |
| Host curl to the model manifest URL | HTTP 200 |
| Screen reader | NOT TESTED |
| Secret hygiene | no new credential material |

DEGRADED was not recorded as a PASS for LIVE generation. The clean-room was not repeated for the version-string promotion.

## Promotion checks

| Check | Result |
|-------|--------|
| In-process version | `1.0.0` |
| Schema / ExternalEvidence | `1.9.0` / `1.0.0` |
| Focused release, academy, schema, ExternalEvidence, and workshop contracts | `53 passed` |
| Full offline suite | `1065 passed, 3 deselected` |
| Wheel | `agentsec-1.0.0-py3-none-any.whl` |
| Splunk package `app.conf` | `version = 1.0.0` |
| DET-MCP-001 | `disabled = 1`, `enableSched = 0` |
| Relative links in README, Quickstart, Getting Started, Known Limitations, and the v1.0.0 release files | 0 missing |
| `git diff --check` | clean |
| Secret scan of the promotion diff | no credential material |

LIVE labs remain 7. REPLAY academy surfaces remain 24.
