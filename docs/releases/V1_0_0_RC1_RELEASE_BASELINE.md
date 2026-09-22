# AgentSec v1.0.0-rc1 — release baseline

**Do not treat this file as a git tag.** Tag happens only after the RC1 gate.

| Field | Value | Evidence |
|-------|--------|----------|
| Pre-commit HEAD | `355dd34ddc3da3705de2ced435c2181bcf2e0c8a` | OBSERVED (`git log`) |
| Branch | `develop` tracking `origin/develop` | OBSERVED |
| Candidate working tree | post-17C/17D uncommitted + RC1 docs (this release pack) | OBSERVED |
| Final tagged SHA | recorded in `V1_0_0_RC1_MANIFEST.md` after tag | |
| Schema | **1.9.0** | MEASURED (`agentsec.experiment.SCHEMA_VERSION`) |
| Product version | 1.0.0rc1 / Splunk app 1.0.0-rc1 | DOCUMENTED |
| Python | `requires-python >=3.11` | DOCUMENTED |
| Docker | Compose v2, profile `local` | DOCUMENTED |
| Splunk image tested | `splunk/splunk:10.2` `linux/amd64` | OBSERVED compose |
| Tags before this gate | none matching `v1*` | OBSERVED |

Published workshops, LIVE/REPLAY labs, detectors, and controls: see `V1_0_0_RC1_PRODUCT_INVENTORY.md`.

Known limitations: `docs/KNOWN_LIMITATIONS.md`.
