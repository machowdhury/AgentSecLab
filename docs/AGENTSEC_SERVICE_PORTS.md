# Service and port inventory (from compose)

Source: `docker-compose.yml` + `docker-compose.local.yml` (profile `local`). Do not copy port numbers from historical phase reports if compose changes.

| Service | Purpose | Container | Host bind | Port | Health | Learner-facing | Boundary |
|---------|---------|-----------|-----------|------|--------|----------------|----------|
| Splunk Web | Academy + Search | `agentsec_splunk` | 127.0.0.1 | 8000 | login page HTTP 200 / compose healthcheck | YES | Observation / SIEM lab UI. Not PDP. |
| Splunk HEC | Event ingest | `agentsec_splunk` | 127.0.0.1 | 8088 | `/services/collector/health/1.0` | NO (ingest) | Telemetry ingest. Health ≠ indexed search. |
| Splunk management | REST (inside container) | `agentsec_splunk` | not published | 8089 | n/a on host | NO | Operator scripts via `docker exec` |
| Attack Service | Closed educational launcher | `agentsec_attack_service` | 127.0.0.1 | 5001 | `/health` | YES | Unauthenticated localhost client. Cannot set grants/profile. |
| AcmeBank | Runtime / controls | `agentsec_acmebank` | 127.0.0.1 | 5000 | `/health` | health only | Enforcement / PDP for lab tools |
| OTel collector | Export to HEC | `agentsec_otel_collector` | 127.0.0.1 | 4317 gRPC, 4318 HTTP | process up | NO | Telemetry transport |
| Ollama | Local model | `agentsec_ollama` | **not published** | 11434 in-mesh | compose healthcheck | NO | Untrusted model. AcmeBank uses `http://ollama:11434` |
| splunk_app_init | Copy app into volume | `agentsec_splunk_app_init` | none | — | exit 0 | NO | Staging |
| splunk_hec_init | Create HEC token/index bind | `agentsec_splunk_hec_init` | none | — | exit 0 | NO | Staging |

All published ports are localhost. Do not remap to `0.0.0.0` for a workshop without a network-security review.
