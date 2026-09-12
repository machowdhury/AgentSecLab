# AgentSec Splunk app

App id: `agentsec`  
Index: `agentsec_telemetry`  
Sourcetype: `otel:agentic:json`

## What is packaged

- `macros.conf` — `` `agentsec_index` `` (index + sourcetype). Phase 2C.1 validated searches still hardcode those values; the dashboard reuses those files, not this macro.
- `props.conf` — JSON extraction for `otel:agentic:json`.
- `indexes.conf` — `agentsec_telemetry`.
- `views/ws_lab_pi_001.xml` — Dashboard Studio workshop for LAB-PI-001 (GRID tabs).
- `savedsearches.conf` — **disabled placeholders** `Q-RUN` / `Q-DENY`. They are not the validated lab searches and are not this dashboard.

## LOCAL Docker

Do not copy this directory by hand. `./scripts/lab-up.sh` stages it into named volume `splunk_app_agentsec`. See `docs/LOCAL_DOCKER_LAB.md`.

## EXTERNAL Splunk

Install this folder (or a tarball of it) with the Splunk deployment mechanism you already use. Point the collector at your HEC endpoint/token/index. The local compose init container is not part of that path.

Studio source of truth: `learning/level_1/LAB-PI-001/dashboard.definition.json`. Rebuild: `python scripts/build_lab_pi_001_dashboard.py`.
