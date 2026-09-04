# AgentWatch Range — Migration Inventory

**Phase:** AgentSec Phase 0 (archaeology only)  
**Predecessor:** AgentWatch Range (`/Users/mahamudc/Documents/AgenticProject`, git remote `github.com/machowdhury/AgentwatchRange`)  
**AgentSec rule:** AgentWatch is READ-ONLY. Do not copy it blindly.  
**This document:** classifies every meaningful component as REUSE, REFACTOR, REDESIGN, or DROP.

No AgentWatch code was migrated. No AgentSec application code was written.

---

## How to read this inventory

| Class | Meaning |
|-------|---------|
| **REUSE** | Keep the idea and most of the artifact. Rebrand, rename fields, keep the shape. |
| **REFACTOR** | Keep the idea and much of the code, but restructure, wire missing flags, or fix correlation. |
| **REDESIGN** | Keep the teaching concept. Rewrite the implementation so it matches AgentSec invariants. |
| **DROP** | Do not bring into AgentSec. Historical, duplicated, or misleading. |

Evidence labels used in this inventory:

| Label | Meaning |
|-------|---------|
| **OBSERVED** | Confirmed by reading files or running a structural check in this Phase 0 pass |
| **DOCUMENTED** | Stated in AgentWatch docs |
| **INFERRED** | Architectural conclusion from code, not live runtime proof |
| **NOT MEASURED** | Would require a live stack, Splunk query, or attack run that was not executed here |

AgentSec `docs/MASTER_SPEC.md` currently contains only section headings (Mission, Architecture, Curriculum, …). It is not yet a filled specification. That is recorded under “What must be solved before Phase 1” in `docs/MIGRATION_PRIORITY.md`.

---

## What AgentWatch actually is

**OBSERVED + DOCUMENTED.** A Docker lab, not a production AI-security product.

ACME Bank story: four agents speed up loan approvals. Learners attack that pipeline, watch lab controls allow or block, and hunt the result in Splunk.

**Runtime (always on in local profile):**

| Container | Port | Role |
|-----------|------|------|
| `banking_app` | 5000 | Flask 4-agent loan pipeline |
| `attack_panel` | 5001 | Adversarial UI that POSTs into banking_app |
| `ollama` | 11434 | Live LLM (`llama3.2:1b` default) |
| `otel_collector` | 4317 / 4318 | OTLP → Splunk HEC |
| `splunk` | 8000 / 8088 | SIEM (compose profile `local`) |

**Honest limitation (DOCUMENTED in `docs/CONCEPTS.md`):** AcmeGate and AcmeSentinel are lab regex middleware, not Cisco product binaries. Attack outcomes are non-deterministic because the model is small and live. Framework mappings are educational, not certification.

---

## APPLICATION

### Banking application

| Component | Path | What it is | Class | Evidence |
|-----------|------|------------|-------|----------|
| Banking Flask runtime | `apps/app_runtime.py` | Loan API, health, sessions, route registration | **REFACTOR** | OBSERVED |
| Banking dashboard | `apps/templates/dashboard.html` | Operator UI for legitimate requests | **REFACTOR** | OBSERVED |
| Banking Dockerfile | `apps/Dockerfile.banking` | Non-root Python 3.11 image | **REUSE** | OBSERVED |
| Python deps | `apps/requirements.txt` | Flask, requests, OTel SDK | **REUSE** | OBSERVED |

**Legitimate path (DOCUMENTED + OBSERVED):** `POST /api/v1/process` → sequential four agents → Ollama → OTel → Splunk.

**Weakness (OBSERVED):** Recent sessions are an in-memory ring of 50. Restart loses history. `/api/v1/config` exposes `ACME_*_GUARD_ENABLED` but `llm_client.py` never reads those env vars — guards always run.

### Agent router

| Component | Path | What it is | Class | Evidence |
|-----------|------|------------|-------|----------|
| Pipeline + agent defs | `apps/agents/agent_router.py` | Ordered in-process loop, not a network router | **REFACTOR** | OBSERVED |

**OBSERVED order:** intake → doc ingest → credit risk → compliance.

**OBSERVED handoff:** string concatenation of previous agent output into the next prompt. There is no HTTP, queue, MCP, or A2A protocol between agents.

**OBSERVED correlation gap:** `run_agent_pipeline()` shares `session_id` but does **not** pass a shared `incident_id` into `call_ollama()`. Non-baseline calls mint a new `ACME-INC-*` per agent.

### Four-agent architecture

| Agent ID | Role | Trust label in code | Class |
|----------|------|---------------------|-------|
| `acme-agent-intake-001` | Customer intake | `external_dmz` | **REFACTOR** (keep 4-role teaching model) |
| `acme-agent-docingest-002` | Document extraction | `internal_processing` | **REFACTOR** |
| `acme-agent-creditrisk-003` | Credit risk | `privileged_internal` | **REFACTOR** |
| `acme-agent-compliance-004` | Compliance | `privileged_internal` | **REFACTOR** |
| `acme-shadow-slm-edge-001` | Shadow SLM (registry only) | teaching asset for Scenario 4 | **REUSE** as inventory fiction |

Trust labels are metadata. They are not enforced network enclaves. **INFERRED:** AgentSec should treat them as teaching names until real trust boundaries exist.

### Ollama

| Component | Path | What it is | Class | Evidence |
|-----------|------|------------|-------|----------|
| LLM client | `apps/agents/llm_client.py` | HTTP `/api/generate`, OTel, guards | **REFACTOR** | OBSERVED |
| Model pull | `scripts/ollama_init.sh` | Pulls `OLLAMA_MODEL` | **REUSE** | OBSERVED |
| Approved catalog | `data/approved_slm_catalog.json` | Approved vs shadow models | **REUSE** | OBSERVED |

**DOCUMENTED:** All four agents share one model. There is no per-agent model routing.

**OBSERVED:** Timeouts and connection errors return error strings; output inspection does not run on those paths.

### State

| Component | Path | Storage | Class | Evidence |
|-----------|------|---------|-------|----------|
| Pipeline sessions | `app_runtime.py` | In-process list | **REFACTOR** | OBSERVED |
| Attack log | `exploit_ui.py` | In-process list | **REFACTOR** | OBSERVED |
| Session facts / drift | `apps/framework/memory_policy.py` | In-process dict | **REDESIGN** | OBSERVED |
| A2A granted/used scope | `apps/framework/a2a_verifier.py` | In-process dict | **REDESIGN** | OBSERVED |
| Kill-chain results | `apps/framework/api_routes.py` | In-process dict | **REFACTOR** | OBSERVED |
| RAG catalog | `apps/framework/rag_store.py` | Static list, no vector DB | **REDESIGN** | OBSERVED |

No database. Process restart wipes workflow memory. That is acceptable for a lab, but AgentSec must not pretend it is durable agent memory.

---

## ATTACKS

### Attack Panel

| Component | Path | What it is | Class | Evidence |
|-----------|------|------------|-------|----------|
| Attack Flask app | `apps/exploit_ui.py` | Thin proxy to banking_app | **REFACTOR** | OBSERVED |
| Attack UI | `apps/templates/exploit_ui.html` | Tabs: Top 10, All 51, Chains, Custom, Workshop | **REFACTOR** | OBSERVED |
| Attack Dockerfile | `apps/Dockerfile.attack` | Separate container | **REUSE** | OBSERVED |

Unauthenticated by design. Fine for localhost. Not portable as a shared range without a trust-boundary decision.

Custom attack (`POST /api/custom`) hits the live LLM and defaults to `testbed_mode=BANKING_LIVE`. It does not attach `technique_id` or `campaign_week`.

### Technique registry

| Component | Path | What it is | Class | Evidence |
|-----------|------|------------|-------|----------|
| Registry YAML | `apps/framework/data/technique_registry.yaml` | **51** techniques (`AML.T0000`–`T0065` + `T0070`–`T0075`) | **REUSE** | OBSERVED (51 `technique_id` entries) |
| Taxonomy loader | `apps/framework/taxonomy.py` | Flat schema → OTel / CSV | **REUSE** | OBSERVED |
| YAML sync | `scripts/sync_technique_registry_yaml.py` | Registry round-trip | **REUSE** | OBSERVED |
| Technique audit | `docs/TECHNIQUE_AUDIT.md` | Redundancy / tier notes | **REUSE** | DOCUMENTED |
| Playbooks | `apps/framework/technique_playbooks.py` | Mode, payload, hunt SPL | **REFACTOR** | OBSERVED (module docstring still says “45”) |
| Executor | `apps/framework/technique_executor.py` | LIVE HTTP / SIMULATED OTel / HYBRID | **REUSE** | OBSERVED |
| Top 10 payloads | `apps/framework/attack_payloads.py` | Campaign weeks 1–10 | **REUSE** | OBSERVED |
| Emerging six | `apps/framework/emerging_threats.py` | AML.T0070–T0075 fixtures | **REUSE** | OBSERVED |
| Learning tiers | `apps/framework/learning_tiers.py` | Tier badges and redundancy map | **REUSE** | OBSERVED |

**Count mismatch (OBSERVED vs DOCUMENTED):** Code and YAML are 51. Several docs, UI strings, and `sync_mitre_atlas_heatmap_dashboard.py` still say 45.

### Custom attacks and chains

| Component | Path | What it is | Class | Evidence |
|-----------|------|------------|-------|----------|
| Custom payload API | `exploit_ui.py` `/api/custom` | Free-form live attack | **REUSE** | OBSERVED |
| Kill-chain engine | `apps/framework/chain_engine.py` | Six chains KC-A001–F001, shared `incident_id` | **REUSE** | OBSERVED |
| Chain API | `apps/framework/api_routes.py` | Execute / fetch results | **REFACTOR** | OBSERVED |
| First Win workshop | `exploit_ui.html` `WORKSHOPS.first_win` | Scenarios 6 → 5 → 9 | **REUSE** | OBSERVED |

UI banner still implies five chains (A–E). Code has six (includes KC-F001).

### LIVE / HYBRID / SIMULATED

This is one of the strongest AgentWatch ideas. **REUSE** the model. Do not collapse it.

| `testbed_mode` | Hits Ollama? | Typical source |
|----------------|--------------|----------------|
| `CAMPAIGN_LIVE` | Yes | Top 10 Attack Panel |
| `TECHNIQUE_LAB_LIVE` | Yes | Technique executor LIVE leg |
| `TECHNIQUE_LAB_SIMULATED` | No | Technique executor SIM leg |
| `KILL_CHAIN_ACTIVE` | No (OTel stages) | Chain engine |
| `SINGLE_TECHNIQUE` | No | Force-emit API |
| `BASELINE_TRAFFIC` | Yes, benign | Traffic simulator |
| `BANKING_LIVE` | Yes | Manual / custom |

Playbook mode rules (OBSERVED in `technique_playbooks.py`): Top 10 → LIVE; recon/resource/staging → SIMULATED; many execution/exfil stages → LIVE; supply-chain and leftovers → HYBRID; emerging IDs can override.

**Research-integrity rule for AgentSec:** SIMULATED and chain OTel legs must never be labeled MEASURED live control proof.

`POST /api/v1/framework/emit/<id>` force-emits SIMULATED events. **REFACTOR** or isolate — it is easy to misread as a live attack.

---

## SECURITY

Canonical live path (OBSERVED in `llm_client.py`):

```text
HTTP → run_workflow_guards()     [PRE-LLM, can block]
     → acmegate_validate_input() [PRE-LLM, can block]
     → Ollama /api/generate      [dangerous operation]
     → acmesentinel_inspect_output() [POST-LLM, suppresses output]
     → evaluate_controls()       [POST-HOC evidence tags]
     → trigger_containment()     [W10 sim only]
```

| Surface | Path | Real or simulated? | Before dangerous op? | Class | Evidence |
|---------|------|--------------------|----------------------|-------|----------|
| Unified workflow guard | `workflow_guard.py` | Real orchestration of lab scanners | Yes | **REUSE** structure | OBSERVED |
| AcmeGate (input) | `llm_client.py` | Real regex | Yes | **REFACTOR** | OBSERVED |
| AcmeSentinel (output) | `llm_client.py` | Real regex | **No** — after inference | **REFACTOR** | OBSERVED |
| MCP gateway | `mcp_gateway.py` | Pattern scan; **no MCP server** | Yes, if markers present | **REDESIGN** | OBSERVED |
| A2A verifier | `a2a_verifier.py` | String/DID markers; **no crypto** | Yes, if `INTER-AGENT` / `did:acme:` | **REDESIGN** | OBSERVED |
| Memory policy | `memory_policy.py` | Regex block + in-process facts | Write patterns yes; drift detect-only | **REFACTOR** | OBSERVED |
| RAG store | `rag_store.py` | Probe scoring; **no retrieval** | Never blocks | **REDESIGN** | OBSERVED |
| Orchestration guard | `orchestration_guard.py` | Foundry-style marker strings | Yes, if markers present | **REFACTOR** | OBSERVED |
| HITL gate | `hitl_gate.py` | Amount regex; default **disabled** | When enabled, yes | **REFACTOR** | OBSERVED |
| Control validator | `control_validator.py` + `control_matrix.yaml` | Post-hoc NIST tagging | No | **REUSE** as measurement | OBSERVED |
| SOAR simulator | `soar_simulator.py` | Sleep + QUARANTINE field | After the fact | **DROP** as control; **REUSE** field names | OBSERVED |

**INV-008 / fail-open notes (OBSERVED):**

- `HITL_GATE_ENABLED` defaults to false → high-value path emits `hitl_bypassed=true` and does **not** block. Intentional teaching gap.
- A2A / orchestration / MCP **fail open** if the attacker omits the lab markers.
- Docs claim `ACME_*_GUARD_ENABLED` can disable guards. **OBSERVED:** `llm_client.py` does not read those variables. Compose sets them; the LLM path ignores them.
- Cisco `LAB_MODE=enforce` has `should_block_from_cisco_scan()` with **no callers**. Documented blocking is not implemented.

**Tests:** **OBSERVED** — no `pytest` / `unittest` / `tests/` in AgentWatch. No automated proof that any control blocks before the dangerous operation.

AgentSec must not claim DENY for AcmeSentinel-style output blocks as if inference never happened. The model already ran.

---

## OBSERVABILITY

| Component | Path | What it is | Class | Evidence |
|-----------|------|------------|-------|----------|
| Collector config | `config/otel-collector-config.yaml` | OTLP in, HEC + JSONL out; metrics debug-only | **REUSE** | OBSERVED |
| LLM OTel | `apps/agents/llm_client.py` | GenAI spans + structured logs | **REFACTOR** | OBSERVED |
| Traffic simulator | `apps/framework/traffic_simulator.py` | Benign real pipeline ticks | **REUSE** | OBSERVED |
| Baseline HEC emitter | `apps/framework/baseline_hec_emitter.py` | Heterogeneous sourcetypes | **REUSE** | OBSERVED |
| Baseline service | `scripts/baseline_hec_service.py` | Loop emitter | **REUSE** | OBSERVED |
| Third-party emitter | `scripts/emit_thirdparty_telemetry.py` | Ad-hoc schema demo | **REUSE** | OBSERVED |
| Agent registry snapshot | `apps/framework/agent_registry.py` | Inventory events | **REUSE** | OBSERVED |
| Campaign enrichment | `apps/framework/campaign_enrichment.py` | Week-specific fields | **REFACTOR** | OBSERVED |
| Campaign manifest | `apps/framework/campaign_manifest.py` | Week metadata | **REUSE** | OBSERVED |

### Indexes and sourcetypes

| Index | Sourcetype | Role |
|-------|------------|------|
| `acme_agentic_telemetry` | `otel:agentic:json` | Primary live path |
| `acme_agentic_telemetry` | `acme:agentic:thirdparty:json` | Fake third-party schema |
| `acme_agentic_telemetry` | `acme:agentic:registry:json` | Agent inventory |
| `security` | `acme:agentic:sim:json` | Simulated vendor-style events |

### Correlation IDs (OBSERVED)

| ID | Exists? | Correlates 4-agent live run? |
|----|---------|------------------------------|
| `run.id` / `run_id` | **No** | N/A |
| `session_id` | Yes in APIs | Shared in pipeline |
| `session.id` | Yes on OTel logs | Splunk props extract `session_id` — name mismatch |
| `incident_id` | Yes | **New per agent call** unless caller passes one |
| `trace_id` | Yes | New root span per LLM call |
| `parent_trace_id` | Kill chains only | Good for **simulated** chains |
| `campaign_week` | Top 10 / playbooks | Scenario tag, not a run ID |
| `testbed_mode` | Yes | Filter baseline vs attack |

**INFERRED:** AgentSec should introduce `run.id` (required by AgentSec research rules) and propagate one incident/trace tree per orchestrated run. Do not assume AgentWatch already does this.

---

## SPLUNK

**OBSERVED:** `scripts/validate_splunk_app.sh` was executed in this Phase 0 pass. Studio XML/JSON checks passed. The script **failed** at the end on leftover `OrchestraACME` strings inside the Phase 8 rename scripts themselves. Structural dashboard quality is real; the packaging gate is not currently green.

Live Splunk search results: **NOT MEASURED**.

### Apps

| App | Path | Role | Class |
|-----|------|------|-------|
| Canonical | `splunk_app/splunk_compliance_app/` (`acme_genai_compliance`) | 15 views, lookups, macros, saved searches | **REUSE** as reference SOC layer |
| Legacy | `splunk_app/App-Agentic-Compliance/` | One classic sim matrix | **DROP** |
| Install guide | `splunk_app/INSTALL.md` | Local / Cloud / Enterprise | **REUSE** (rebrand) |

### Dashboards (canonical app)

| View | Studio? | Purpose | Class |
|------|---------|---------|-------|
| `executive_governance.xml` | Studio v2 | CISO readiness / registry / HITL | **REUSE** |
| `exercise_runner.xml` | Studio v2 | Tier 0–6 notebook (~218 searches) | **REUSE** |
| `compliance_overview.xml` | Studio v2 | KPI + gaps | **REUSE** |
| `cross_app_normalization.xml` | Studio v2 | `norm_*` teaching | **REUSE** |
| `technique_coverage_matrix.xml` | Studio v2 | 51-technique three-state matrix | **REUSE** |
| `threat_hunting.xml` | Studio v2 | Playbook hunts | **REUSE** |
| `nist_rmf_compliance.xml` | Studio v2 | Framework scores | **REFACTOR** (verify mappings; no 800-17) |
| `detection_efficacy.xml` | Studio v2 | Coverage / MTTD | **REUSE** |
| `control_attestation.xml` | Studio v2 | Control pass/fail panels | **REUSE** as evidence UI |
| `mltk_anomaly_hunting.xml` | Studio v2 | CTSM / anomaly workshop | **REFACTOR** (optional module) |
| `actor_chain_narrative.xml` | Studio v2 | Kill-chain story | **REUSE** |
| `mitre_atlas_heatmap.xml` | Studio v2 | Tactic × technique | **REFACTOR** (stale “45” copy) |
| `killchain_timeline.xml` | Studio v2 | Incident stage order | **REUSE** |
| `dataset_export.xml` | Studio v2 | HuggingFace export readiness | **REFACTOR** / optional |
| `splunk_cloud_setup.xml` | Classic v1.1 | Setup HTML | **REUSE** content, rebrand |
| Legacy `compliance_matrix.xml` | Classic dark | Sim ledger | **DROP** |

Generator pattern (`scripts/sync_*_dashboard.py` + `studio_dashboard_common.py` + `splunk_studio_xml.py`): **REUSE**. Source of truth is Python, not hand-edited Studio JSON.

### SPL, macros, lookups

| Asset | Notes | Class |
|-------|-------|-------|
| `default/macros.conf` | ~27 macros including `acme_genai_index`, `acme_control_block`, `acme_campaign_w1`–`w10`, `acme_session_window` | **REUSE** (rename `acme_*` → `agentsec_*`) |
| `default/savedsearches.conf` | 31 searches, all `disabled=1` | **REUSE** core detections; optionalize MLTK |
| `default/lookups/` | 13 CSVs (framework, playbooks, control matrix, exercise content, …) | **REUSE** after regenerating from AgentSec taxonomy |
| `default/props.conf` | JSON KV + `norm_*` calculated fields | **REUSE** |
| Join / `appendcols` | Common in coverage and attestation dashboards | **REFACTOR** if volume grows |
| `transaction` / `map` | Not used as SPL commands in the canonical app | — |

Workshop content lives in Attack Panel + Exercise Runner + `docs/WORKSHOP.md`, not a separate Splunk app.

**SPL validation status:** Field names are engineered against this lab schema (**DOCUMENTED**). AgentSec rule “never claim SPL works unless validated” still applies — **NOT MEASURED** against a live index in this pass.

---

## INTEGRATIONS

| Integration | Path | Wired? | Class | Evidence |
|-------------|------|--------|-------|----------|
| Cisco overlay compose | `docker-compose.cisco.yml` | Yes, when merged | **REUSE** overlay pattern | OBSERVED |
| Cisco Python | `apps/framework/cisco_integration.py` | Teach-mode scans + simulated fields | **REFACTOR** | OBSERVED |
| Cisco routes | `apps/framework/cisco_routes.py` | Status / AIBOM / MCP / Foundation-Sec | **REUSE** | OBSERVED |
| Cisco docs | `docs/CISCO_INTEGRATION.md` | Overstates enforce mode | **REFACTOR** | OBSERVED |
| Host CLI install | `scripts/install_cisco_tools.sh`, `apps/requirements-cisco.txt` | Not in Docker image | **REUSE** optional | OBSERVED |
| AI BOM fixture | `data/aibom/acme_agent_manifest.json` | Loaded by enrichment | **REUSE** | OBSERVED |
| MCP catalog fixture | `data/mcp/acme_banking_mcp.json` | Includes adversarial tool | **REUSE** | OBSERVED |
| MAESTRO API | `apps/framework/maestro_workshop.py` | Architecture export + routes | **REUSE** | OBSERVED |
| CSA MAESTRO UI | External Node app, not in compose | Documented only | **REUSE** as optional workshop | DOCUMENTED |
| Foundation-Sec-8B | Ollama optional second model | API wired; pull opt-in | **REUSE** optional | OBSERVED |
| CTSM / MLTK | Simulated Python fields + Splunk `fit` if apps installed | Hybrid | **REFACTOR** | DOCUMENTED |
| Galileo | Simulated scores in `rag_store.py` | Name-only | **REUSE** hunt fields, label SIMULATED | OBSERVED |
| DefenseClaw OSS | Not embedded; lab renamed to AcmeSentinel | Reference only | **DROP** embedding | DOCUMENTED |
| Skill Scanner OSS | Not embedded | Documented only | **DROP** until redesigned | DOCUMENTED |

Base `docker-compose.yml` does not inject `CISCO_INTEGRATION_ENABLED` into `banking_app`. `.env.example` can imply Cisco is on when the overlay is not used.

---

## QUALITY

| Area | Finding | Class | Evidence |
|------|---------|-------|----------|
| Automated tests | None | **REDESIGN** from scratch for AgentSec | OBSERVED |
| Splunk packaging gate | `validate_splunk_app.sh` — useful, currently fails Phase 8 leftover grep | **REUSE** then fix | OBSERVED (failed this pass) |
| Package script | `scripts/package_splunk_app.sh` | **REUSE** | OBSERVED |
| Lookup/exercise sync | `sync_splunk_lookups.py`, `sync_exercise_content.py` | **REUSE** | OBSERVED |
| Compose files | `docker-compose.yml` + local/external/cisco overlays | **REUSE** | OBSERVED |
| `.env.example` | Lab defaults for Splunk password, HEC token, Flask secret | **REUSE** pattern; never copy defaults into AgentSec as “production” | OBSERVED |
| Docs | 15+ markdown guides, strong honesty in CONCEPTS | **REUSE** selectively; fix 45 vs 51 | OBSERVED |
| Bulk rename scripts | `phase6/8/15_bulk_rename.py` | **DROP** (archaeology only) | OBSERVED |
| Duplicate Splunk app | `App-Agentic-Compliance` | **DROP** | OBSERVED |
| Duplicate agent maps | `AGENTS` in router and playbooks | **REFACTOR** | OBSERVED |
| `prevbuild/` | gitignored, not in workspace | **DROP** | OBSERVED |
| AgentWatch Cursor rules | None | — | OBSERVED |

Lab secret **names** (defaults are public and documented for localhost only): `SPLUNK_PASSWORD`, `SPLUNK_HEC_TOKEN`, `FLASK_SECRET_KEY`. Hardcoded fallbacks exist in compose and several Python emitters. AgentSec must not treat these as real credentials. Cloud-VM docs correctly warn to rotate before exposing ports.

---

## Mapping to AgentSec invariants (INFERRED)

| Invariant | AgentWatch status |
|-----------|-------------------|
| INV-001 Delegated authorization | Scope tracking is in-memory and marker-driven. Not real delegation. |
| INV-002 Data cannot grant authority | RAG never blocks; retrieved “docs” are strings in the user message. |
| INV-003 Memory trust isolation | Write phrases can block; drift is detect-only; store is a dict. |
| INV-004 Privileged action attribution | `incident_id` exists but is not stable across the live 4-agent pipeline. |
| INV-005 Agent identity integrity | A2A “passport” is regex. Fail-open without markers. |
| INV-006 Workflow integrity | Sequential Python loop, not an authorized state machine. |
| INV-007 Evidence integrity | OTel vocabulary is rich; correlation holes and SIMULATED events weaken reconstruction. |
| INV-008 Fail-safe decisions | Several paths fail open (HITL default, missing markers, unwired Cisco enforce, unused guard env). |

---

## Related AgentSec documents

- `docs/MIGRATION_PRIORITY.md` — what to reuse first and what must be solved before Phase 1
- `docs/learning-notes/how-agentwatch-works.md` — teaching note for this archaeology
- `docs/MASTER_SPEC.md` — not yet a filled spec
