# AgentSec Phase 2 reuse ledger

AgentWatch Range is READ-ONLY. Phase 2 borrowed shapes, not a fork.

**Event/operation/dimension contract:** `SECURITY_EVENT_MODEL.md` (Phase 1B) is authoritative. This ledger records what was reused from AgentWatch; it is not the telemetry contract. `testbed.mode=LIVE` is not valid. `LIVE` is `execution.mode`.

## ORIGINAL FILE
`/Users/mahamudc/Documents/AgenticProject/apps/agents/agent_router.py`

**WHAT WAS REUSED:** Four sequential in-process agents, system-prompt roles, string handoff of prior output into the next prompt.

**WHAT CHANGED:** Agents are Intake → Credit → Risk → Compliance (no document-ingest id). Shared `agentsec.run.id`. Pipeline stops on input DENY before Ollama. No workflow/MCP/A2A guards.

**WHY:** Keep the loan-pipeline teaching model. Fix the missing run-level correlation and the “four agents = A2A” confusion.

---

## ORIGINAL FILE
`/Users/mahamudc/Documents/AgenticProject/apps/agents/llm_client.py`

**WHAT WAS REUSED:** HTTP `POST /api/generate` to Ollama, health check against `/api/tags`, optional OTLP log export idea.

**WHAT CHANGED:** Injectable client (`OllamaClient` / `StubLLM`). Input control is not inside the HTTP client. No AcmeSentinel HARD_DENY after inference. No `incident_id` per hop. Events match `security_event.schema.json`.

**WHY:** Tests must prove DENY with zero model calls. Output HARD_DENY after generate taught the wrong DENY lesson.

---

## ORIGINAL FILE
`/Users/mahamudc/Documents/AgenticProject/apps/app_runtime.py`

**WHAT WAS REUSED:** Flask `/health`, `/api/v1/process`, `/api/v1/agents`, in-memory recent-run lookup, localhost lab service on port 5000.

**WHAT CHANGED:** No Cisco/MAESTRO/export/campaign routes. HTTP cannot set profile, `run.id`, `testbed.mode`, or skip controls. First-lab baseline is an explicit benign request (`testbed.mode=BASELINE`).

**WHY:** Attack Service must remain an untrusted client. AgentWatch `/api/v1/config` advertised unwired guard flags.

---

## ORIGINAL FILE
`/Users/mahamudc/Documents/AgenticProject/apps/exploit_ui.py`

**WHAT WAS REUSED:** Separate Flask process that only HTTP-POSTs into the bank app (port 5001).

**WHAT CHANGED:** One attack (ATK-002). No Top 10, 51 techniques, chains, Cisco, or MAESTRO. No Ollama import.

**WHY:** Phase 2 is one live injection path. The 51-technique catalog mixed LIVE and SIMULATED proof.

---

## ORIGINAL FILE
`/Users/mahamudc/Documents/AgenticProject/apps/framework/traffic_simulator.py`

**WHAT WAS REUSED:** Benign Canadian-loan style strings. BASELINE as a testbed intent distinct from ATTACK.

**WHAT CHANGED:** Always full four-agent pipeline. Mode is a function argument, not an HTTP field. No HEC-only simulated baseline emitter. First-lab baseline is an explicit benign request (`testbed.mode=BASELINE`, `execution.mode=LIVE`, `telemetry.fidelity=OBSERVED`).

**WHY:** Baseline must be real AcmeBank traffic. HTTP BASELINE would let an attacker hide in the baseline KPI.

---

## ORIGINAL FILE
`/Users/mahamudc/Documents/AgenticProject/config/otel-collector-config.yaml`

**WHAT WAS REUSED:** OTLP receiver → batch → Splunk HEC + file archive. Sourcetype `otel:agentic:json`.

**WHAT CHANGED:** Index `agentsec_telemetry`. `deployment.environment=lab`. No pprof. No second `security` index. Metrics stay debug-only.

**WHY:** One evidence store. Do not label the lab “production.”

---

## ORIGINAL FILE
`/Users/mahamudc/Documents/AgenticProject/docker-compose.yml` and `docker-compose.local.yml`

**WHAT WAS REUSED:** Five-service mesh (bank, attack, ollama, collector, Splunk), healthchecks, local profile, HEC init sidecar.

**WHAT CHANGED:** Service names `acmebank` / `attack_service`. Host ports bound to `127.0.0.1`. No baseline_hec SIMULATED emitter. Secrets only from `.env`.

**WHY:** Same understandable mesh. Reduce accidental internet exposure and fake HEC proof.

---

## ORIGINAL FILE
`/Users/mahamudc/Documents/AgenticProject/apps/Dockerfile.banking` and `Dockerfile.attack`

**WHAT WAS REUSED:** python:3.11-slim, curl, non-root `appuser`, one process per image.

**WHAT CHANGED:** Copies `src/agentsec` + schema. No framework/data/cisco trees.

**WHY:** Smallest useful images for Phase 2.

---

## ORIGINAL FILE
`/Users/mahamudc/Documents/AgenticProject/scripts/ollama_init.sh`

**WHAT WAS REUSED:** Serve, wait, pull `OLLAMA_MODEL`.

**WHAT CHANGED:** Removed Foundation-Sec / Cisco optional pull.

**WHY:** User forbade Cisco tools in Phase 2.

---

## ORIGINAL FILE
`/Users/mahamudc/Documents/AgenticProject/scripts/splunk_hec_init.sh`

**WHAT WAS REUSED:** Wait for mgmt API, enable HEC, disable SSL in-mesh, create index + token, HTTP ingest probe.

**WHAT CHANGED:** One index (`agentsec_telemetry`). Password and token required from env (no committed default in the script).

**WHY:** Lab credentials must not live in git as copy-paste production lookalikes.

---

## ORIGINAL FILE
`/Users/mahamudc/Documents/AgenticProject/apps/requirements.txt`

**WHAT WAS REUSED:** Flask, requests, OpenTelemetry SDK + OTLP HTTP exporter.

**WHAT CHANGED:** Dropped YAML (no 51-technique registry). Added jsonschema for closed events.

**WHY:** Event normalization is the Phase 2 contract.

---

## Not reused (DROP / later)

Technique registry, MCP/A2A/memory/RAG/HITL/workflow guards, AcmeSentinel HARD_DENY, Cisco routes, MLTK, Studio dashboards, baseline HEC simulator, control attestation matrices.
