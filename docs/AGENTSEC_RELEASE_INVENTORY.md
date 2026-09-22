# Release inventory (v1.0.0-rc1)

Classification: RELEASED | INTERNAL | HISTORICAL | EXPERIMENTAL | DEFERRED | NOT IMPLEMENTED

Do not assign historical phase reports as learner requirements.

## Schema

| Item | Class |
|------|--------|
| Telemetry schema 1.9.0 | RELEASED |
| Product version 1.0.0-rc1 | RELEASED (candidate) |

## Published Academy views

| View | Class |
|------|--------|
| ws_agentsec_home | RELEASED |
| ws_lab_pi_001 | RELEASED |
| ws_lab_mcp_001 | RELEASED |
| ws_lab_mcp_003 | RELEASED |
| ws_lab_mcp_004 | RELEASED |
| ws_lab_mcp_005 | RELEASED |
| ws_lab_mcp_006 | RELEASED |
| ws_lab_mcp_catalog | RELEASED |
| ws_lab_scanner_runtime_evidence | RELEASED |
| ws_lab_rag_context | RELEASED |
| ws_lab_memory_security | RELEASED |
| ws_lab_agent_goal_integrity | RELEASED |
| ws_lab_agent_delegation | RELEASED |
| ws_lab_agentsec_capstone | RELEASED |
| ws_agentsec_mastery | RELEASED |

## Labs

See [AGENTSEC_RELEASE_LAB_MATRIX.md](AGENTSEC_RELEASE_LAB_MATRIX.md). MIXED as a lab **type**: NOT IMPLEMENTED. LIVE dashboards may embed REPLAY specimens.

## Attack Service labs

Seven LIVE labs listed in the lab matrix. Closed launch contract: RELEASED.

## Guided investigations / Q-* / DET-*

| Item | Class |
|------|--------|
| Path A / Path B in published views | RELEASED |
| Q-* hunts embedded in Studio + savedsearches `Q-RUN`, `Q-DENY` | RELEASED |
| DET-MCP-001 (saved search, disabled) | RELEASED (educational, not enabled) |
| New detectors for RAG/memory/goal/capstone | NOT IMPLEMENTED (intentional) |

## Controls / runtime / Docker / Splunk app

Reference controls CTRL-* in runtime: RELEASED (educational). Docker compose local profile: RELEASED. Splunk app `splunk_app/agentsec`: RELEASED.

## Mastery / Capstone / learning metadata

Mastery Check, Capstone, `learning/academy/*`: RELEASED.

## Documentation

Learner: README, QUICKSTART, architecture, security boundary, troubleshooting, instructor, limitations: RELEASED. `docs/PHASE*.md`: HISTORICAL provenance. Cursor rules / skills: INTERNAL.

## Scripts / tests / screenshots

`scripts/lab-*.sh`: RELEASED. pytest: INTERNAL (developers). Playwright captures / `docs/screenshots/`: useful documentation / test artifact. `artifacts/`: gitignored, should not ship secrets.

## Deferred / not implemented

MLTK, HITL, real A2A, OAuth/OIDC/SPIFFE, progress persistence, certification, remote Attack Service, new attack domains: DEFERRED / NOT IMPLEMENTED.
