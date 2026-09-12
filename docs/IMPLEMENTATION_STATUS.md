# AgentSec implementation status

**Phase:** 2C.3 COMPLETE (LAB-PI-001 Dashboard Studio + UI Design System; screenshot/token validation)  
**Version:** 0.3.0  
**Validation:** `docs/PHASE2A_RUNTIME_VALIDATION.md`, `docs/PHASE2B_TRANSPORT_VALIDATION.md`, `docs/SPLUNK_DATA_VALIDATION.md`, `docs/PHASE2C_SPL_VALIDATION.md`, `docs/PHASE2C2_COMPARE_RUNS.md`, `docs/PHASE2C3_DASHBOARD.md`, `docs/LOCAL_DOCKER_LAB.md`, `docs/AGENTSEC_DESIGN_SYSTEM.md`  
**Last pytest:** 81 passed, 1 skipped (2026-09-11, this session)  
**Local lab READY:** OBSERVED `./scripts/lab-up.sh` named-volume staging (no manual cp/chown). `--refresh-app` used to reload Studio XML.

| Capability | Label | Proof |
|------------|-------|-------|
| `POST /process` four-agent pipeline | IMPLEMENTED | stub tests + live BASELINE |
| CTRL-INPUT-001 before Ollama | IMPLEMENTED | spy tests + live ATK-002 |
| Schema 1.0.0 emitters | IMPLEMENTED | validate_event + telemetry tests |
| OTLP sink lifecycle + force_flush | IMPLEMENTED | `tests/telemetry/test_export_honesty.py` |
| `export.json` does not infer Splunk from OTLP | IMPLEMENTED | pytest OBSERVED; live `splunk.verified=false` |
| Live OTLP → collector | OBSERVED | collector debug 22 + 6 log records |
| Live HEC → `index=agentsec_telemetry` | OBSERVED | Splunk `tstats` / `_raw` export |
| Splunk `_raw` JSON extraction | OBSERVED | first-class fields; `invariant.id` array/mv |
| BASELINE completeness vs `events.jsonl` | MEASURED | run `b3611d56-0d3f-4b2e-9a51-75ae36628155` (22=22) |
| Defended ATK-002 Splunk corroboration | MEASURED | run `78f05d1b-728e-4e70-8993-f5e365871f87` (6=6, no `llm.*`) |
| LAB-PI-001 investigation SPL (four queries) | VALIDATED | `docs/PHASE2C_SPL_VALIDATION.md`; live Splunk CLI |
| LAB-PI-001 workshop logic (ten-step flow) | IMPLEMENTED | `learning/level_1/LAB-PI-001/` |
| LAB-PI-001 Dashboard Studio (`ws_lab_pi_001`) | COMPLETE | GRID tabs; SPL bound; pytest MEASURED binding; Splunk Web 10/10 tabs OBSERVED; four token values MEASURED (`docs/screenshots/lab-pi-001/pass2_validation.json`); `/ui-review` pass 1+2 |
| AgentSec UI Design System | IMPLEMENTED | `docs/AGENTSEC_DESIGN_SYSTEM.md`; Flask tokens; `/ui-review` skill |
| Local Splunk app provisioning | ACCEPTED | named volume + `splunk_app_init`; `./scripts/lab-up.sh`; `lab-ready.sh` READY (design unchanged) |
| Vulnerable ATK-002 live + Splunk | OBSERVED / MEASURED | `f39fed12-de89-45ba-b684-5b6077942580` (22=22, 4 LLM) |
| Defended ATK-002 RETEST live + Splunk | OBSERVED / MEASURED | `bbe75cb8-0190-47d6-86be-5feba58ad5c0` (6=6, `RETEST`, 0 LLM) |
| Saved detections | NOT ATTEMPTED | out of Phase 2C.3 scope |
| MCP / A2A / RAG / memory / chains | ABSENT | out of scope |

Do not treat `otlp.ok` as Splunk verification. Do not treat Splunk missing `llm.*` as prevention without local completeness.
