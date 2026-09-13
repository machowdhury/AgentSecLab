# AgentSec implementation status

**Phase:** 2C.3 COMPLETE (LAB-PI-001 Dashboard Studio). **3B IMPLEMENTED** (LAB-MCP-001 runtime). **3C VALIDATED** (MCP transport + Q-MCP SPL). **3D VALIDATED** (LAB-MCP-001 workshop + `ws_lab_mcp_001`). **3E VALIDATED** (DET-MCP-001 disabled saved search). **4A DESIGN** (LAB-MCP-003). **4B IMPLEMENTED + LOCALLY VALIDATED** (MCP-003 runtime). **4C VALIDATED** (MCP-003 Splunk transport + Q-MCP / DET-MCP-001 reuse). **4D VALIDATED** (LAB-MCP-003 workshop + `ws_lab_mcp_003`).  
**Version:** 0.3.0  
**Validation:** `docs/PHASE2A_RUNTIME_VALIDATION.md`, `docs/PHASE2B_TRANSPORT_VALIDATION.md`, `docs/SPLUNK_DATA_VALIDATION.md`, `docs/PHASE2C_SPL_VALIDATION.md`, `docs/PHASE2C2_COMPARE_RUNS.md`, `docs/PHASE2C3_DASHBOARD.md`, `docs/LOCAL_DOCKER_LAB.md`, `docs/AGENTSEC_DESIGN_SYSTEM.md`, `docs/PHASE3B_MCP_RUNTIME_VALIDATION.md`, `docs/PHASE3C_MCP_SPLUNK_VALIDATION.md`, `docs/PHASE3D_MCP_WORKSHOP.md`, `docs/PHASE3E_MCP_DETECTION.md`, `docs/PHASE4B_MCP003_RUNTIME_VALIDATION.md`, `docs/PHASE4C_MCP003_SPLUNK_VALIDATION.md`, `docs/PHASE4D_MCP003_WORKSHOP.md`  
**Phase 3A docs:** `docs/MCP_PREDECESSOR_ANALYSIS.md`, `docs/MCP_ARCHITECTURE.md`, `docs/MCP_THREAT_MODEL.md`, `docs/MCP_LAB_PLAN.md`, `docs/MCP_EVENT_MODEL_PROPOSAL.md`, `docs/learning-notes/mcp-security-101.md`  
**Phase 3B docs:** `docs/MCP_RUNTIME_CONTRACT.md`, `docs/MCP_EVENT_MODEL.md`, `docs/PHASE3B_MCP_RUNTIME_VALIDATION.md`, `docs/learning-notes/mcp-runtime-101.md`  
**Phase 3C docs:** `docs/MCP_SPLUNK_FIELD_CONTRACT.md`, `docs/MCP_SEARCH_CONTRACT.md`, `docs/PHASE3C_MCP_SPLUNK_VALIDATION.md`, `docs/learning-notes/mcp-splunk-investigation.md`  
**Phase 3D docs:** `docs/PHASE3D_MCP_WORKSHOP.md`, `docs/learning-notes/mcp-workshop.md`, `docs/reviews/ui-review-ws-lab-mcp-001-2026-09-11.md`  
**Phase 3E docs:** `docs/PHASE3E_MCP_DETECTION.md`, `docs/learning-notes/mcp-detection-engineering.md`  
**Phase 4A docs:** `docs/MCP003_PREDECESSOR_ANALYSIS.md`, `docs/MCP003_SCOPE_MODEL.md`, `docs/MCP003_THREAT_MODEL.md`, `docs/MCP003_LAB_SPECIFICATION.md`, `docs/MCP003_EVENT_MODEL_REVIEW.md`, `docs/learning-notes/mcp-scope-security-101.md`  
**Phase 4B docs:** `docs/MCP003_RUNTIME_CONTRACT.md`, `docs/PHASE4B_MCP003_RUNTIME_VALIDATION.md`, `docs/learning-notes/mcp-scope-runtime.md`  
**Phase 4C docs:** `docs/PHASE4C_MCP003_SPLUNK_VALIDATION.md`, `docs/MCP003_SPLUNK_FIELD_VALIDATION.md`, `docs/learning-notes/mcp-scope-splunk.md`  
**Phase 4D docs:** `docs/PHASE4D_MCP003_WORKSHOP.md`, `docs/learning-notes/mcp-scope-workshop.md`, `docs/reviews/ui-review-ws-lab-mcp-003-2026-09-12.md`  
**Last pytest:** 194 passed, 2 deselected (2026-09-12, this session; live Ollama/Splunk markers excluded)  
**Local lab READY:** OBSERVED `./scripts/lab-up.sh` named-volume staging (no manual cp/chown). `--refresh-app` used to reload Studio XML.

| Capability | Label | Proof |
|------------|-------|-------|
| `POST /process` four-agent pipeline | IMPLEMENTED | stub tests + live BASELINE |
| CTRL-INPUT-001 before Ollama | IMPLEMENTED | spy tests + live ATK-002 |
| Schema 1.0.0 emitters | SUPERSEDED | Loan semantics kept; emitters now **1.1.0** |
| Schema 1.1.0 emitters | IMPLEMENTED | additive MCP events; pytest MEASURED |
| MCP runtime / LAB-MCP-001 | IMPLEMENTED | `POST /mcp/invoke`; CTRL-MCP-001 before handler; spy tests MEASURED (`docs/PHASE3B_MCP_RUNTIME_VALIDATION.md`) |
| MCP Splunk Q-MCP-* investigation SPL | VALIDATED | live CLI on fresh MCP run IDs; `docs/PHASE3C_MCP_SPLUNK_VALIDATION.md` |
| MCP Dashboard Studio (`ws_lab_mcp_001`) | VALIDATED | GRID 10 tabs; Q-MCP bind-only; pytest MEASURED; Splunk Web 10/10 OBSERVED; `/ui-review` pass 1+2 (`docs/PHASE3D_MCP_WORKSHOP.md`) |
| MCP DET-MCP-001 (execution after DENY) | VALIDATED | disabled saved search; live specimens 0 rows MEASURED; SIMULATED +1; `docs/PHASE3E_MCP_DETECTION.md` |
| MCP-003 / LAB-MCP-003 (scope escalation) | **IMPLEMENTED + LOCALLY VALIDATED** | runtime + pytest MEASURED; local A/B/C packs OBSERVED (`docs/PHASE4B_MCP003_RUNTIME_VALIDATION.md`). |
| MCP-003 Splunk (Q-MCP reuse + DET-MCP-001) | **VALIDATED** | fresh LIVE run IDs; transport COMPLETE; existing Q-MCP-* reused; DET-MCP-001 0 rows MEASURED; SIMULATED scope fixture; `docs/PHASE4C_MCP003_SPLUNK_VALIDATION.md`. No DET-MCP-003. |
| MCP-003 workshop / Dashboard Studio (`ws_lab_mcp_003`) | **VALIDATED** | GRID 10 tabs; Q-MCP bind-only; DET-MCP-001 reuse; pytest MEASURED; Splunk Web 10/10 OBSERVED; `/ui-review` pass 1+2 (`docs/PHASE4D_MCP003_WORKSHOP.md`). No DET-MCP-003. |
| MCP-004+ / remediations / ES notable | NOT ATTEMPTED | out of Phase 4D scope |
| A2A / RAG / memory / chains | ABSENT | out of scope |
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
| Saved detections | PARTIAL | `DET-MCP-001` disabled/validated. Loan `Q-RUN`/`Q-DENY` placeholders remain unvalidated. No ES notable. |
| LAB-MCP-001 Splunk completeness (fresh 3C runs) | MEASURED | A/B 7=7; C/D/E 6=6; E-HTTP 2=2; F 8=8 (`docs/PHASE3C_MCP_SPLUNK_VALIDATION.md`) |

Do not treat `otlp.ok` as Splunk verification. Do not treat Splunk missing `llm.*` as prevention without local completeness.
