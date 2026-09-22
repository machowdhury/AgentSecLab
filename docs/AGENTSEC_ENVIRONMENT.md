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
| `SPLUNK_HEC_ENDPOINT` | non-secret | Mesh HEC URL |
| `SPLUNK_HEC_INDEX` | non-secret | `agentsec_telemetry` |
| `SPLUNK_HEC_SOURCETYPE` | non-secret | `otel:agentic:json` |
| `SPLUNK_HEC_SOURCE` | non-secret | collector source name |
| `SPLUNK_HEC_TLS_SKIP_VERIFY` | non-secret | lab default true |

## Development / test only

Pytest, Playwright, `uv`, optional live markers `live_ollama` / `live_splunk`. Learners do not need these.

## Attack Service (compose-set, not learner-edited mid-lab)

`AGENTSEC_BIND_HOST`, `ATTACK_SERVICE_PORT`, `ACMEBANK_URL`, `AGENTSEC_ARTIFACTS_DIR`, `AGENTSEC_SPLUNK_WEB_URL`.

Learners should not mutate environment variables during a published lab.
