# AgentSec Splunk app

App id: `agentsec`  
Index: `agentsec_telemetry`  
Sourcetype: `otel:agentic:json`

Knowledge-object engineering: `.cursor/rules/33-splunk-agent-skills.mdc` then `.cursor/skills/splunk-ko-review/SKILL.md`. Inventory: `docs/SPLUNK_KNOWLEDGE_OBJECT_INVENTORY.md`. Do not rewrite validated SPL for style.

## What is packaged

- `macros.conf` — `` `agentsec_index` `` (index + sourcetype). Phase 2C.1 validated searches still hardcode those values; the dashboard reuses those files, not this macro.
- `props.conf` — JSON extraction for `otel:agentic:json`.
- `indexes.conf` — `agentsec_telemetry`.
- `views/ws_lab_pi_001.xml` — Dashboard Studio workshop for LAB-PI-001 (GRID tabs).
- `views/ws_lab_mcp_001.xml` — Dashboard Studio workshop for LAB-MCP-001 (GRID tabs). Rebuild: `python scripts/build_lab_mcp_001_dashboard.py`.
- `views/ws_lab_mcp_003.xml` — Dashboard Studio workshop for LAB-MCP-003 (GRID tabs). Rebuild: `python scripts/build_lab_mcp_003_dashboard.py`.
- `views/ws_lab_mcp_004.xml` — Dashboard Studio workshop for LAB-MCP-004 (GRID tabs). Rebuild: `python scripts/build_lab_mcp_004_dashboard.py`.
- `views/ws_lab_mcp_005.xml` — Dashboard Studio workshop for LAB-MCP-005 (GRID tabs). Rebuild: `python3 scripts/build_lab_mcp_005_dashboard.py`. No DET-MCP-005.
- `views/ws_lab_mcp_006.xml` — Dashboard Studio workshop for LAB-MCP-006 (GRID tabs). Rebuild: `python3 scripts/build_lab_mcp_006_dashboard.py`. No DET-MCP-006.
- `views/ws_lab_mcp_catalog.xml` — Dashboard Studio workshop for LAB-MCP-CATALOG (GRID tabs). Rebuild: `python3 scripts/build_lab_mcp_catalog_dashboard.py`. No DET-MCP-CATALOG.
- `savedsearches.conf` — **disabled** `AgentSec - MCP Execution After Authorization Deny` (`DET-MCP-001`). Placeholders `Q-RUN` / `Q-DENY` remain unvalidated and are not this dashboard.

## LOCAL Docker

Do not copy this directory by hand. `./scripts/lab-up.sh` stages it into named volume `splunk_app_agentsec`. See `docs/LOCAL_DOCKER_LAB.md`.

## EXTERNAL Splunk

Install this folder (or a tarball of it) with the Splunk deployment mechanism you already use. Point the collector at your HEC endpoint/token/index. The local compose init container is not part of that path.

Studio source of truth: `learning/level_1/LAB-PI-001/dashboard.definition.json`. Rebuild: `python scripts/build_lab_pi_001_dashboard.py`.
