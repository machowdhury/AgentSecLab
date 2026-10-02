# AgentSec v1.0.0 — validation (prepared, not tagged)

This file records what was run. It does not create the tag.

| Check | Result |
|-------|--------|
| Peeled RC1 | `e6115b6d1c03a1672b4364e84748c7840671fbfc` |
| Peeled RC2 | `1be214b92f840f843aaf27fb2b9536f764dd7126` |
| Peeled RC3 | `6c7af8e87f96cda4ee929664fbb17ec763dd135c` |
| main | unchanged, same commit as RC1 |
| Offline suite ×10 | each `1065 passed, 3 deselected`, exit 0 |
| Wheel | `agentsec-1.0.0rc3-py3-none-any.whl` built |
| Schema / ExternalEvidence | `1.9.0` / `1.0.0` |
| Clean-room service start | PROVEN, 2026-10-02, new volumes |
| AcmeBank on that run | degraded, model not listed |
| Attack Service on that run | healthy, `1.0.0rc3`, schema `1.9.0` |
| Model pull inside Ollama | FAIL, `x509: certificate signed by unknown authority` |
| Host curl to the model manifest URL | HTTP 200 |
| Screen reader | NOT TESTED |
| `git diff --check` | clean |
| Secret hygiene | no new credential material |

DEGRADED was not recorded as a PASS for LIVE generation.
