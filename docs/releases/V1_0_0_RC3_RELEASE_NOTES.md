# AgentSec v1.0.0-rc3 — release notes

AgentSec v1.0.0-rc3 is a local educational agentic-security academy. It is not final `v1.0.0` and not a production security product.

Splunk is the investigation workbench. AcmeBank runs the lab controls. The Attack Service is a closed localhost launcher and does not authorize tools. CTRL-MCP-001 remains the only tool policy decision point.

Schema **1.9.0**. ExternalEvidence **1.0.0**. Package **1.0.0rc3**. Splunk app **1.0.0-rc3**. Product version, schema version, and the external-evidence contract are independent.

`main` and annotated tag `v1.0.0-rc1` remain the earlier baseline (peeled commit `e6115b6d1c03a1672b4364e84748c7840671fbfc`). Annotated tag `v1.0.0-rc2` remains the previous candidate (peeled commit `1be214b92f840f843aaf27fb2b9536f764dd7126`). This candidate is `develop`. It was not merged into `main`.

## Since RC2

Eight bounded REPLAY workshops were added without renumbering L0–L10: human approval binding, credential lifetime, RAG purpose, memory isolation, asset inventory, component provenance, code-agent bounds, and change bounds. Their packets are SIMULATED or REPLAYED. They are not runtime enforcement and not a second PDP.

Studio dashboard `definition.title` is set to the view label. A missing title had rendered as `undefined | Splunk`. Measured titles on the running app include `Home | Splunk 10.2.7` and `Tool Authorization | Splunk 10.2.7`.

DET-MCP-001 stays disabled. Learner-facing MCP-001 text does not call that disabled search an enabled operational detection.

## Clean-room measurement

Measured 2026-10-01 from a fresh directory with new Compose volumes. The existing `agentseclab_*` volumes were not removed. `.env` was copied from `.env.example`. The start command was `docker compose -f docker-compose.yml -f docker-compose.local.yml --profile local --env-file .env up -d --build`.

| Mark | Clock (UTC) | From start |
|------|-------------|------------|
| Compose start | 2026-10-01T20:28:50Z | 0 |
| First containers running | 2026-10-01T20:28:55Z | 5s |
| Earliest retained Splunk healthy check | 2026-10-01T20:31:58Z | 3m 8s |
| Compose exit 0 | 2026-10-01T20:33:16Z | 4m 26s |
| Home sentence read from the running app | 2026-10-01T20:40:37Z | 11m 47s |

Host: Darwin 27.0.0 arm64, Docker 29.7.2, Compose v5.5.1. The source tree was `f4f9a43ff76658f3388e9345b04d4d5e16627ad0` plus the uncommitted candidate edits copied into that directory.

AcmeBank and Attack Service health reported version `1.0.0rc3`. Attack Service `schema_version` was `1.9.0`. The Splunk app file in the clean container was `version = 1.0.0-rc3`. REST returned HTTP 200 for `ws_agentsec_home` and `ws_lab_change_bounds`. The Home view contains “Splunk does not ALLOW or DENY”. The Change Bounds view contains “REPLAY”.

`docker exec agentsec_ollama ollama pull llama3.2:1b` failed: `x509: certificate signed by unknown authority` for `registry.ollama.ai`. AcmeBank stayed `degraded` with `ollama_reachable: false`. The Ollama image remains `ollama/ollama:latest`. No digest was recorded.

The clean-room project was then removed with `down -v` in that directory only. The original containers were started again on the original volumes.

## Validation

After the Studio title fix, ten consecutive offline suites each reported `1064 passed, 3 deselected`. The ten runs before that fix failed one deterministic title assertion. The final suite on the rc3 version strings reported `1064 passed, 3 deselected` in 10.18s.

Screen reader: not tested. This is not a WCAG claim.

## Accepted debt

- `ollama/ollama:latest` is unpinned.
- Garak license, probe fidelity, Cisco AI-BOM compatibility, mcp-scanner JSON stability, and OWASP, NIST, and ATLAS mappings stay on the external-validation backlog.
- The fresh-volume model pull failed on this host’s TLS path.
- No Docker OCI version label. Health and `app.conf` are the version sources.
