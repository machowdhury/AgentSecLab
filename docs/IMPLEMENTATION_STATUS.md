# AgentSec implementation status

**Phase:** 2C.2 LAB-PI-001 workshop logic (no Dashboard Studio)  
**Version:** 0.3.0  
**Validation:** `docs/PHASE2A_RUNTIME_VALIDATION.md`, `docs/PHASE2B_TRANSPORT_VALIDATION.md`, `docs/SPLUNK_DATA_VALIDATION.md`, `docs/PHASE2C_SPL_VALIDATION.md`  
**Last pytest:** 70 passed, 1 skipped (2026-09-11)

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
| LAB-PI-001 workshop logic (ten-step flow) | IMPLEMENTED | `learning/level_1/LAB-PI-001/`; no Studio JSON |
| Dashboard Studio / detections | NOT ATTEMPTED | out of Phase 2C.2 scope |
| MCP / A2A / RAG / memory / chains | ABSENT | out of scope |

Do not treat `otlp.ok` as Splunk verification. Do not treat Splunk missing `llm.*` as prevention without local completeness.
