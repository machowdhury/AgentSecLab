# Environment variables

Never commit `.env`. `.gitignore` includes `.env` and `.envrc`.

Values in `.env.example` are **lab defaults** for localhost Docker. They are not production secrets. Do not paste real cloud API keys into the tree.

## Required for canonical `lab-up.sh`

| Variable | Class | Notes |
|----------|-------|--------|
| `SPLUNK_PASSWORD` | secret (lab) | Splunk admin password. Complexity required by the Splunk image. |
| `SPLUNK_HEC_TOKEN` | secret (lab) | HEC ingest token used by collector init. |

Without these, `lab-up.sh` / `lab-ready.sh` fail.

## Non-secret configuration (compose / runtime)

| Variable | Class | Notes |
|----------|-------|--------|
| `COMPOSE_PROFILES` | required in example | `local` |
| `COMPOSE_FILE` | required in example | compose overlay pair |
| `AGENTSEC_SECURITY_PROFILE` | non-secret | Default `defended`; LIVE ATTACK/RETEST overlay is server-owned |
| `AGENTSEC_LAB_ID` | non-secret | Default `agentsec-local` |
| `AGENTSEC_TESTBED_MODE` | non-secret | Default `auto` |
| `AGENTSEC_OTEL_ENABLED` | non-secret | Default `true` |
| `OLLAMA_MODEL` | non-secret | Default `llama3.2:1b` |
| `OLLAMA_BASE_URL` | optional | Default mesh `http://ollama:11434` |
| `SPLUNK_IMAGE` | non-secret | Default `splunk/splunk:10.2` |
| `SPLUNK_PLATFORM` | non-secret | Default `linux/amd64` |
| `SPLUNK_HEC_ENDPOINT` | non-secret | Mesh HEC URL. Lab default is `https://agentsec_splunk:8088/services/collector/event` (container DNS + TLS). The compose service hostname `splunk` is not a reliable alias on this host. |
| `SPLUNK_HEC_INDEX` | non-secret | `agentsec_telemetry` |
| `SPLUNK_HEC_SOURCETYPE` | non-secret | `otel:agentic:json` |
| `SPLUNK_HEC_SOURCE` | non-secret | collector source name |
| `AGENTSEC_HEC_TLS_MODE` | non-secret | `LOCAL_SELF_SIGNED` (default) or `EXTERNAL_CERT`. See [HEC TLS](#hec-tls). |
| `AGENTSEC_HEC_CERT_FILE` / `AGENTSEC_HEC_KEY_FILE` | host paths | `EXTERNAL_CERT` only, to have the bundled Splunk serve your certificate. Never modified. Keep the key out of Git. |
| `AGENTSEC_HEC_CA_FILE` | host path | Trust bundle used by every HEC client. Required in `EXTERNAL_CERT`. Defaults to `.certs/hec-ca.crt` in local mode. |

### HEC TLS

HEC is always HTTPS with certificate and hostname verification on. There is no skip-verify setting for HEC.

- **`LOCAL_SELF_SIGNED`:** `scripts/hec-certs.sh` (run by `lab-up.sh`) creates a lab certificate once under `.certs/` (git-ignored, key mode 600) with SANs `agentsec_splunk`, `localhost`, `127.0.0.1`, and reuses it on later runs. Clients trust it only through the explicit CA file. It is never added to the OS trust store. To rotate, delete `.certs/` and rerun `lab-up.sh`, then recreate Splunk and the collector.
- **`EXTERNAL_CERT`:** the script only validates your files (readable, key matches certificate, not expired, required SANs, chains to the CA bundle) and never rewrites them. For an external HEC service you do not own, set only `AGENTSEC_HEC_CA_FILE` and `SPLUNK_HEC_ENDPOINT`; no private key is required and the remote Splunk is not modified. Run only the collector for that case.
- **Fast check:** `./scripts/hec-scheme-check.sh` detects a scheme or trust mismatch in seconds. `precheck.sh` runs it when a CA exists.
- The Splunk management API (8089) TLS behavior is unchanged and out of scope here.

## Development / test only

Pytest, Playwright, `uv`, optional live markers `live_ollama` / `live_splunk`. Learners do not need these.

## Attack Service (compose-set, not learner-edited mid-lab)

`AGENTSEC_BIND_HOST`, `ATTACK_SERVICE_PORT`, `ACMEBANK_URL`, `AGENTSEC_ARTIFACTS_DIR`, `AGENTSEC_SPLUNK_WEB_URL`.

Learners should not mutate environment variables during a published lab.
