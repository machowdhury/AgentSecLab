# AgentWatch Range — Migration Inventory

**Phase:** AgentSec Phase 0 (archaeology only)  
**Predecessor (read-only):** `/Users/mahamudc/Documents/workspace/AgentwatchRange`  
**This pass:** source inspection of the AgentWatch Range tree. No AgentWatch files were modified. No AgentSec application code, SPL, or dashboards were created. No dependencies were installed. Live attacks, live Splunk queries, and packaging scripts were **not executed**.

**Status of this document:** IMPLEMENTED (documentation of a predecessor). Nothing below is an AgentSec implementation claim.

---

## How to read this inventory

| Class | Meaning |
|-------|---------|
| **REUSE** | Keep the idea and most of the artifact. Rebrand. Keep the shape. |
| **REFACTOR** | Keep the idea and much of the design, but restructure, wire flags, or fix correlation. |
| **REDESIGN** | Keep the teaching concept. Rewrite the mechanism so it matches AgentSec invariants. |
| **DROP** | Do not bring into AgentSec. Historical, duplicated, or misleading as a control. |

Evidence labels (AgentSec research integrity):

| Label | Meaning |
|-------|---------|
| **OBSERVED** | Confirmed by reading files in this Phase 0 pass |
| **DOCUMENTED** | Stated in AgentWatch docs |
| **INFERRED** | Architectural conclusion from code, not live runtime proof |
| **NOT MEASURED** | Would require a live stack, Splunk query, or attack run |

Execution honesty (attacks and controls):

| Label | Meaning |
|-------|---------|
| **LIVE** | Hits the banking app / Ollama path |
| **HYBRID** | Some live path plus fabricated or marker telemetry |
| **SIMULATED** | Emits OTel or markers without executing the claimed attack or protocol |
| **REPLAYED** | Attestation or synthetic events that look like outcomes after the fact |

SPL honesty (never assume SPL is correct):

| Label | Meaning |
|-------|---------|
| **VALIDATED** | A successful Splunk run is recorded in the repo |
| **PLAUSIBLE BUT UNVALIDATED** | Looks coherent; fields may exist; no execution proof |
| **BROKEN** | Obvious field mismatch or contradiction in source |
| **UNKNOWN** | Cannot tell from source |

**OBSERVED:** No in-repo Splunk query execution log exists. Treat all AgentWatch SPL as **PLAUSIBLE BUT UNVALIDATED** unless marked **BROKEN**.

---

## What actually exists

**OBSERVED + DOCUMENTED.** AgentWatch Range is a Docker learning lab, not a production AI-security product.

| Container | Port | Role | Always on in local profile? |
|-----------|------|------|-----------------------------|
| `banking_app` | 5000 | Flask 4-agent loan pipeline | Yes |
| `attack_panel` | 5001 | Adversarial UI that POSTs into banking_app | Yes |
| `ollama` | 11434 | Live LLM (`llama3.2:1b` default) | Yes |
| `otel_collector` | 4317 / 4318 | OTLP → Splunk HEC | Yes |
| `splunk` | 8000 / 8088 | SIEM | Compose profile `local` |

**Honest limitation (DOCUMENTED in AgentWatch `docs/CONCEPTS.md`, OBSERVED in code):** AcmeGate and AcmeSentinel are lab regex middleware, not Cisco product binaries. Agents do not call each other over a network. Trust labels are metadata, not enclaves. Framework mappings are editorial YAML, not certification.

**What actually works (INFERRED from code; NOT MEASURED live):**

- Legitimate `POST /api/v1/process` runs four sequential Ollama calls.
- Attack Panel Top 10 and custom payloads POST into that same path.
- Workflow guards and AcmeGate can block **before** Ollama when markers/regex match.
- AcmeSentinel can suppress output **after** Ollama returns.
- Baseline traffic simulator calls the real LLM path with `testbed_mode=BASELINE_TRAFFIC`.
- Kill chains and SIMULATED techniques can light up Splunk without calling Ollama.
- Splunk app ships 15 views, lookups, macros, and 29 disabled saved searches.

**What is simulated vs implemented:** see component cards. Short version: the loan loop and regex input/output guards are LIVE. MCP, A2A, RAG, Foundry, AIBOM drift, CTSM scores, and SOAR quarantine are SIMULATED or HYBRID marker systems.

---

## APPLICATION

### Banking Flask runtime

| Field | Value |
|-------|-------|
| **COMPONENT** | `apps/app_runtime.py` |
| **PURPOSE** | Flask entry: health, pipeline, single-agent, sessions, config, traffic controls; mounts framework/Cisco/MAESTRO/dataset routes |
| **CURRENT STATUS** | Complete lab app. Unauthenticated. In-memory session ring (50). |
| **LIVE / HYBRID / SIMULATED / REPLAYED** | LIVE host |
| **STRENGTHS** | Clear route mounting; health includes Ollama; small surface for a range |
| **WEAKNESSES** | No auth; Flask secret fallback in source; `/api/v1/config` exposes infra URLs and **displayed** guard flags that are not wired |
| **SECURITY CONCERNS** | Open execute APIs; config leakage; lab-default secret if env unset. **Hardcoded-credentials rule:** lab defaults exist in compose/env examples and Flask fallback strings. Do not copy them into AgentSec as production secrets. Load from env/secret store only. |
| **TEST COVERAGE** | None |
| **SPLUNK DEPENDENCY** | Indirect via OTel |
| **MIGRATION DECISION** | **REFACTOR** |
| **RATIONALE** | Keep a small Flask (or equivalent) shell. Do not treat this file as AgentSec architecture. |
| **PRIORITY** | P1 |

**OBSERVED routes on :5000:** `/health`, `/`, `/api/v1/process`, `/api/v1/agent/<id>`, `/api/v1/sessions`, `/api/v1/ollama/health`, `/api/v1/agents`, `/api/v1/config`, plus campaign, controls, registry, traffic, framework, Cisco, MAESTRO, dataset routes.

### Banking dashboard

| Field | Value |
|-------|-------|
| **COMPONENT** | `apps/templates/dashboard.html` |
| **PURPOSE** | Operator UI for legitimate loan requests |
| **CURRENT STATUS** | Functional; shows tokens, latency, guard status, trace IDs |
| **LIVE / HYBRID / SIMULATED / REPLAYED** | LIVE |
| **STRENGTHS** | Makes the four-agent hop visible |
| **WEAKNESSES** | Legacy vendor-style labels; no CSP |
| **SECURITY CONCERNS** | Lab UI only |
| **TEST COVERAGE** | None |
| **SPLUNK DEPENDENCY** | None |
| **MIGRATION DECISION** | **REFACTOR** |
| **RATIONALE** | Keep a simple operator view. Rebuild copy for AgentSec names. |
| **PRIORITY** | P3 |

### Agent router / orchestration

| Field | Value |
|-------|-------|
| **COMPONENT** | `apps/agents/agent_router.py` → `run_agent_pipeline()` |
| **PURPOSE** | Ordered in-process loop: intake → doc ingest → credit risk → compliance |
| **CURRENT STATUS** | Works as a teaching pipeline. Not a network router. |
| **LIVE / HYBRID / SIMULATED / REPLAYED** | LIVE |
| **STRENGTHS** | Stops on block; agent metadata includes trust labels for teaching |
| **WEAKNESSES** | Handoff is string concatenation. **Does not pass `incident_id` into `call_ollama()`.** Each agent mints a new `ACME-INC-*` unless baseline mode. No parent trace. |
| **SECURITY CONCERNS** | Trust labels are not enforced. Prompt injection travels as concatenated context (INV-003 later). |
| **TEST COVERAGE** | None |
| **SPLUNK DEPENDENCY** | Per-agent logs; pipeline hunts that assume one incident are wrong |
| **MIGRATION DECISION** | **REFACTOR** |
| **RATIONALE** | Keep sequential 4-role teaching model. Propagate `run.id` + one `incident_id`. Document as in-process, not A2A. |
| **PRIORITY** | P0 |

**OBSERVED order:** `acme-agent-intake-001` → `acme-agent-docingest-002` → `acme-agent-creditrisk-003` → `acme-agent-compliance-004`.

### Ollama / LLM client

| Field | Value |
|-------|-------|
| **COMPONENT** | `apps/agents/llm_client.py` |
| **PURPOSE** | HTTP `POST /api/generate`, AcmeGate, AcmeSentinel, OTel spans/logs, control evaluation |
| **CURRENT STATUS** | Core LIVE path. Guard env flags documented, not read. |
| **LIVE / HYBRID / SIMULATED / REPLAYED** | LIVE |
| **STRENGTHS** | Real model I/O; GenAI semantic fields; workflow guards before LLM; rich logs |
| **WEAKNESSES** | 120s timeout hardcoded; infra errors return placeholder strings (fail-open); `span_id=0` on logs; `deployment.environment=production` hardcoded; unused imports |
| **SECURITY CONCERNS** | Output DENY after inference. `skip_acmesentinel` API bypass. I/O previews (200 chars) in telemetry. |
| **TEST COVERAGE** | None |
| **SPLUNK DEPENDENCY** | Primary `otel:agentic:json` producer |
| **MIGRATION DECISION** | **REFACTOR** |
| **RATIONALE** | Keep Ollama client + OTel emission. Honor security profiles. Emit `run.id`. Fail-closed option on infra errors. |
| **PRIORITY** | P0 |

**OBSERVED call order in `call_ollama()`:** workflow guards → AcmeGate → Ollama → AcmeSentinel → control validator → optional SOAR (week 10).

**OBSERVED:** `ACME_INPUT_GUARD_ENABLED` / `ACME_OUTPUT_GUARD_ENABLED` are returned by `get_config()` only. They are **not** read in `llm_client.py`.

### State

| Field | Value |
|-------|-------|
| **COMPONENT** | In-memory stores: `_recent_sessions`, `_SESSION_FACTS`, `_chain_results`, attack_log |
| **PURPOSE** | UI history, memory-drift demo, chain result cache, panel log |
| **CURRENT STATUS** | Process-local. Lost on restart. |
| **LIVE / HYBRID / SIMULATED / REPLAYED** | LIVE stores of lab state |
| **STRENGTHS** | Simple; no extra database (aligns with AgentSec core rules) |
| **WEAKNESSES** | Not durable; not a real memory system |
| **SECURITY CONCERNS** | Memory policy “trust” is an in-process dict |
| **TEST COVERAGE** | None |
| **SPLUNK DEPENDENCY** | Durable evidence is Splunk, not these stores |
| **MIGRATION DECISION** | **REUSE** (ring buffer idea) / **REDESIGN** (memory as security object) |
| **RATIONALE** | Session display can stay in-memory. Do not pretend this is INV-003 memory. |
| **PRIORITY** | P2 |

### API layer (Attack Panel)

| Field | Value |
|-------|-------|
| **COMPONENT** | `apps/exploit_ui.py` + `apps/templates/exploit_ui.html` |
| **PURPOSE** | Top 10, 51 techniques, chains, custom payload, workshop tabs; HTTP proxy to banking app |
| **CURRENT STATUS** | Operational. Default chain execute uses `hybrid_live: true`. Banking API default is `hybrid_live: false`. |
| **LIVE / HYBRID / SIMULATED / REPLAYED** | LIVE proxy; techniques/chains per playbook mode |
| **STRENGTHS** | Clean split from banking process; workshop-friendly |
| **WEAKNESSES** | No auth; in-memory log (200); copy drift (“45” vs 51); does not pass a shared `incident_id` on Top 10 POSTs |
| **SECURITY CONCERNS** | Unauthenticated adversarial injection into the bank URL |
| **TEST COVERAGE** | None |
| **SPLUNK DEPENDENCY** | Indirect; panel log is not indexed |
| **MIGRATION DECISION** | **REFACTOR** |
| **RATIONALE** | Keep an Attack Service. Generate `run.id` client-side and persist returned IDs. |
| **PRIORITY** | P1 |

### Baseline traffic

| Field | Value |
|-------|-------|
| **COMPONENT** | `apps/framework/traffic_simulator.py` |
| **PURPOSE** | Background benign LLM traffic with `testbed_mode=BASELINE_TRAFFIC` |
| **CURRENT STATUS** | Autostart via `maybe_autostart()` |
| **LIVE / HYBRID / SIMULATED / REPLAYED** | LIVE |
| **STRENGTHS** | Attacks are visible against real noise; waits for Ollama |
| **WEAKNESSES** | Duplicated request templates in `scripts/baseline_traffic_generator.py`; baseline logs omit `incident_id` |
| **SECURITY CONCERNS** | Synthetic PII-like fields in logs |
| **TEST COVERAGE** | None |
| **SPLUNK DEPENDENCY** | High — hunts must exclude `BASELINE_TRAFFIC` |
| **MIGRATION DECISION** | **REUSE** |
| **RATIONALE** | Proven teaching idea. One generator, not two. |
| **PRIORITY** | P0 |

### Baseline HEC emitter

| Field | Value |
|-------|-------|
| **COMPONENT** | `apps/framework/baseline_hec_emitter.py`, `scripts/baseline_hec_service.py`, `scripts/emit_thirdparty_telemetry.py` |
| **PURPOSE** | Direct Splunk HEC events for sim/third-party/registry sourcetypes |
| **CURRENT STATUS** | Working standalone loops |
| **LIVE / HYBRID / SIMULATED / REPLAYED** | SIMULATED |
| **STRENGTHS** | Teaches cross-schema normalization |
| **WEAKNESSES** | Lab HEC token fallbacks in source; fake token counts |
| **SECURITY CONCERNS** | Predictable lab credentials in defaults (**do not copy secret values**) |
| **TEST COVERAGE** | None |
| **SPLUNK DEPENDENCY** | Direct |
| **MIGRATION DECISION** | **REUSE** as labeled SIMULATED noise / **DROP** from the first proving loop |
| **RATIONALE** | Valuable later for SIEM teaching. Dangerous if mixed with LIVE control proof. |
| **PRIORITY** | P3 |

### Docker / Ollama init / catalog

| Field | Value |
|-------|-------|
| **COMPONENT** | `docker-compose*.yml`, `apps/Dockerfile.*`, `scripts/ollama_init.sh`, `data/approved_slm_catalog.json` |
| **PURPOSE** | Five-service mesh; model pull; approved vs shadow catalog |
| **CURRENT STATUS** | Compose overlays (local / external Splunk / cisco) are a good pattern. Catalog JSON is **unused** at runtime (shadow SLM hardcoded in registry). |
| **LIVE / HYBRID / SIMULATED / REPLAYED** | LIVE runtime; catalog is dead data |
| **STRENGTHS** | Non-root images; overlays instead of extra platforms |
| **WEAKNESSES** | Lab credential defaults; catalog not loaded |
| **SECURITY CONCERNS** | Default Splunk admin / HEC token / Flask secret in compose and `.env.example` |
| **TEST COVERAGE** | None |
| **SPLUNK DEPENDENCY** | Local profile includes Splunk |
| **MIGRATION DECISION** | **REUSE** compose overlay pattern; **REFACTOR** Dockerfiles; **DROP** unused catalog or wire it |
| **RATIONALE** | AgentSec core rules already forbid extra platforms. Keep this simplicity. |
| **PRIORITY** | P1 |

---

## ATTACK SYSTEM

**OBSERVED technique counts** (`technique_playbooks._execution_mode` + registry): **51** techniques = **26 LIVE / 14 HYBRID / 11 SIMULATED**. **REPLAYED executor mode does not exist.** Fallback payloads tagged “LAB REPLAY” are still LIVE HTTP to Ollama if executed.

Top 10 campaign scenarios: all LIVE. Kill chains: 6 (`KC-A001` … `KC-F001`). Emerging: AML.T0070–T0075.

MITRE ATLAS / OWASP / MAESTRO / NIST fields live in YAML. **OBSERVED:** editorial, not verified against framework APIs. AgentSec must treat them as educational until `docs/FRAMEWORK_MAPPING_MODEL.md` proofs exist.

### Technique registry

| Field | Value |
|-------|-------|
| **COMPONENT** | `apps/framework/data/technique_registry.yaml` + `taxonomy.py` |
| **PURPOSE** | Canonical technique metadata → OTel flatten → Splunk lookup CSV |
| **CURRENT STATUS** | 51 entries; import-time learning-tier assert |
| **LIVE / HYBRID / SIMULATED / REPLAYED** | Metadata |
| **STRENGTHS** | One taxonomy, many consumers; `to_otel_attributes()` |
| **WEAKNESSES** | Header/docs sometimes say 45 or 84; mappings unvalidated |
| **SECURITY CONCERNS** | None as data |
| **TEST COVERAGE** | Tier distribution assert only |
| **SPLUNK DEPENDENCY** | High |
| **MIGRATION DECISION** | **REUSE** schema |
| **RATIONALE** | Best SSOT idea in the predecessor. Do not port all 51 in Phase 1. |
| **PRIORITY** | P0 (schema) / P2 (full catalog) |

### Technique executor / playbooks

| Field | Value |
|-------|-------|
| **COMPONENT** | `technique_executor.py`, `technique_playbooks.py` |
| **PURPOSE** | LIVE HTTP vs SIMULATED OTel vs HYBRID both; coverage matrix |
| **CURRENT STATUS** | Central execution engine |
| **LIVE / HYBRID / SIMULATED / REPLAYED** | All three; no REPLAYED |
| **STRENGTHS** | Explicit mode field; `execute_all`; chain narrative |
| **WEAKNESSES** | Live path HTTP self-loop to `banking_app:5000`; HYBRID can emit contradictory guard outcomes under one `incident_id`; `execute_all` is long-running |
| **SECURITY CONCERNS** | Unauthenticated flood |
| **TEST COVERAGE** | None |
| **SPLUNK DEPENDENCY** | High |
| **MIGRATION DECISION** | **REFACTOR** |
| **RATIONALE** | Keep mode labels. Add `telemetry.fidelity`. In-process live calls. |
| **PRIORITY** | P1 |

### Attack payloads / campaign

| Field | Value |
|-------|-------|
| **COMPONENT** | `attack_payloads.py`, `campaign_manifest.py`, `campaign_enrichment.py`, `learning_tiers.py`, `emerging_threats.py` |
| **PURPOSE** | Top 10 stories, week metadata, week-specific OTel injection, curriculum tiers, T0070–T0075 |
| **CURRENT STATUS** | Complete for the 10-week campaign |
| **LIVE / HYBRID / SIMULATED / REPLAYED** | Top 10 LIVE; enrichment HYBRID/SIMULATED |
| **STRENGTHS** | Surfaces > prompts; First Win pedagogy; honest SIMULATED redundancy notes in `TECHNIQUE_AUDIT.md` |
| **WEAKNESSES** | Enrichment fabricates AIBOM/Galileo/CTSM-shaped fields; duplicates MCP/A2A checks |
| **SECURITY CONCERNS** | Simulated hash mismatch can be mistaken for supply-chain failure |
| **TEST COVERAGE** | Sync script tier counts |
| **SPLUNK DEPENDENCY** | Critical for campaign macros |
| **MIGRATION DECISION** | **REUSE** Top 10 + tiers; **REFACTOR** enrichment (label SIMULATED fields) |
| **RATIONALE** | Curriculum spine is proven. Fabricated Cisco/Galileo fields are not. |
| **PRIORITY** | P1 (Top 10) / P2 (enrichment) |

### Chain engine

| Field | Value |
|-------|-------|
| **COMPONENT** | `apps/framework/chain_engine.py` |
| **PURPOSE** | Multi-stage OTel sequencing with shared `incident_id` + `parent_trace_id` |
| **CURRENT STATUS** | 6 chains; POST synthetic OTLP logs |
| **LIVE / HYBRID / SIMULATED / REPLAYED** | SIMULATED (default); HYBRID when Attack Panel sets `hybrid_live` |
| **STRENGTHS** | Best correlation pattern in the lab; Splunk kill-chain timeline depends on it |
| **WEAKNESSES** | Hardcoded `custom_fields` (including `HARD_DENY`) without LLM; not real traces |
| **SECURITY CONCERNS** | Teaches hunts that can “detect” events that never happened |
| **TEST COVERAGE** | None |
| **SPLUNK DEPENDENCY** | Critical |
| **MIGRATION DECISION** | **REFACTOR** |
| **RATIONALE** | Keep shared incident for multi-stage stories. Label fidelity. Never use chain OTel as control proof. |
| **PRIORITY** | P1 |

---

## SECURITY CONTROLS

For every control: claimed property, where the check runs, whether it is **before** the dangerous operation, missing-context behavior, fail-open, and what test proves it (**none** unless noted).

### Workflow guard

| Field | Value |
|-------|-------|
| **COMPONENT** | `apps/framework/workflow_guard.py` → `run_workflow_guards()` |
| **PURPOSE** | Pre-LLM composite gate: MCP, orchestration, A2A, memory, RAG alert, HITL |
| **CURRENT STATUS** | Invoked first in `call_ollama()`; early return on `blocked=True` |
| **LIVE / HYBRID / SIMULATED / REPLAYED** | HYBRID |
| **STRENGTHS** | Correct **placement** (before Ollama). Composable surfaces. |
| **WEAKNESSES** | Surfaces skip unless markers present. RAG never blocks. Privilege/skill paths telemetry-only. |
| **SECURITY CONCERNS** | Missing trigger → ALLOW (INV-008 risk). |
| **TEST COVERAGE** | None |
| **SPLUNK DEPENDENCY** | `workflow.*` fields |
| **MIGRATION DECISION** | **REUSE** placement; **REFACTOR** policy |
| **RATIONALE** | This is the skeleton AgentSec reference controls should keep. |
| **PRIORITY** | P0 |

- **Claimed property:** block unsafe tool/A2A/memory/HITL before inference  
- **Check location:** `run_workflow_guards()` before Ollama  
- **Before dangerous op:** yes, when it blocks  
- **Missing context:** `blocked=False`  
- **Fail-open:** yes, default  
- **Test:** none  

### AcmeGate (input)

| Field | Value |
|-------|-------|
| **COMPONENT** | `llm_client.acmegate_validate_input()` |
| **PURPOSE** | Block unsanitized / injection-like input |
| **CURRENT STATUS** | Lab regex. **Not** Cisco CodeGuard. Always runs (env flag unwired). |
| **LIVE / HYBRID / SIMULATED / REPLAYED** | LIVE |
| **STRENGTHS** | Before LLM; exception stops inference |
| **WEAKNESSES** | Regex evasion; documented disable flag does not work |
| **SECURITY CONCERNS** | Easy miss; over-block risk on finance language |
| **TEST COVERAGE** | None |
| **SPLUNK DEPENDENCY** | `acme_input_guard.*` |
| **MIGRATION DECISION** | **REFACTOR** as a **reference** input control |
| **RATIONALE** | Keep check-before-use. Add tests. Wire profiles. Do not market as a product. |
| **PRIORITY** | P0 |

- **Claimed property:** unsanitized input cannot reach the model  
- **Before dangerous op:** yes  
- **Missing context / no match:** ALLOW  
- **Fail-open:** yes for unlisted attacks  
- **Test:** none  

### AcmeSentinel (output)

| Field | Value |
|-------|-------|
| **COMPONENT** | `llm_client.acmesentinel_inspect_output()` |
| **PURPOSE** | HARD_DENY jailbreak signatures in model output |
| **CURRENT STATUS** | Lab regex. **Not** Cisco DefenseClaw. Runs **after** Ollama. Bypass: `skip_acmesentinel`. |
| **LIVE / HYBRID / SIMULATED / REPLAYED** | LIVE (check-after-use) |
| **STRENGTHS** | Emits ERROR log + span exception on match |
| **WEAKNESSES** | Inference already happened. AgentSec rule: never report DENY if the dangerous operation succeeded. |
| **SECURITY CONCERNS** | Post-hoc suppression labeled as HARD_DENY |
| **TEST COVERAGE** | None |
| **SPLUNK DEPENDENCY** | `acme_output_guard.action` |
| **MIGRATION DECISION** | **REFACTOR** |
| **RATIONALE** | Keep output inspection as a teaching control. Telemetry must say “after inference.” Do not call it pre-op DENY. |
| **PRIORITY** | P0 |

- **Claimed property:** malicious output is denied  
- **Before dangerous op:** **no**  
- **Fail-open:** no match → PASS; model already ran  
- **Test:** none  

### MCP gateway

| Field | Value |
|-------|-------|
| **COMPONENT** | `apps/framework/mcp_gateway.py` |
| **PURPOSE** | Block out-of-scope / shell-like tool invocations; detect poisoned manifests |
| **CURRENT STATUS** | Regex + substring allowlist. `data/mcp/acme_banking_mcp.json` is a static catalog for optional Cisco scan, **not** a live MCP server. |
| **LIVE / HYBRID / SIMULATED / REPLAYED** | HYBRID |
| **STRENGTHS** | Before LLM when shell patterns match |
| **WEAKNESSES** | Unknown tools pass. No MCP protocol. |
| **SECURITY CONCERNS** | INV-001 not actually enforced |
| **TEST COVERAGE** | None |
| **SPLUNK DEPENDENCY** | `tool.scope_violation`, `mcp.gateway.*` |
| **MIGRATION DECISION** | **REDESIGN** |
| **RATIONALE** | Need a real allowlist or an honestly labeled SIMULATED lab with a tiny MCP stub. |
| **PRIORITY** | P1 |

- **Claimed property:** agents cannot invoke unapproved tools  
- **Before dangerous op:** yes, but the “tool” is a string, not an invocation  
- **Missing context:** `MCP-GW-PASS`, `blocked=False`  
- **Fail-open:** yes  
- **Test:** none  

### A2A verifier

| Field | Value |
|-------|-------|
| **COMPONENT** | `apps/framework/a2a_verifier.py` |
| **PURPOSE** | Cryptographic passport / DID / provenance for inter-agent messages |
| **CURRENT STATUS** | Marker + truncated hash prefix. Default `passport_valid = True`. Only consulted for two privileged agents when `INTER-AGENT` or `did:acme:` appears. |
| **LIVE / HYBRID / SIMULATED / REPLAYED** | SIMULATED |
| **STRENGTHS** | Can block before LLM when forgery markers present |
| **WEAKNESSES** | Not W3C DID, not mTLS, not real signatures. **Crypto note:** truncated SHA-256 prefix compare is not a signature scheme. Do not treat as authenticated identity (INV-005). |
| **SECURITY CONCERNS** | Fail-open default passport |
| **TEST COVERAGE** | None |
| **SPLUNK DEPENDENCY** | `cryptographic_passport_valid`, `a2a.*` |
| **MIGRATION DECISION** | **REDESIGN** |
| **RATIONALE** | Keep the lesson (agent impersonation). Use an explicit delegation object or labeled SIMULATED. |
| **PRIORITY** | P1 |

- **Claimed property:** forged inter-agent messages are rejected  
- **Before dangerous op:** only if the surface triggers  
- **Missing context:** skip entire check  
- **Fail-open:** yes (`passport_valid=True`)  
- **Test:** none  

### Agent registry / AIBOM

| Field | Value |
|-------|-------|
| **COMPONENT** | `agent_registry.py`, `data/aibom/acme_agent_manifest.json`, `campaign_enrichment._aibom_fields()` |
| **PURPOSE** | Inventory snapshot; supply-chain drift telemetry |
| **CURRENT STATUS** | Registry does not gate execution. Drift is `"SYSTEM UPDATE"` substring. Optional `aibom` CLI is host-only. |
| **LIVE / HYBRID / SIMULATED / REPLAYED** | LIVE listing; SIMULATED validation |
| **STRENGTHS** | Teaching inventory including shadow SLM row |
| **WEAKNESSES** | Placeholder hashes; unused `approved_slm_catalog.json` |
| **SECURITY CONCERNS** | Agents run regardless of manifest |
| **TEST COVERAGE** | None |
| **SPLUNK DEPENDENCY** | Registry index / `cisco_aibom_status` |
| **MIGRATION DECISION** | **REUSE** inventory idea; **REDESIGN** enforcement |
| **RATIONALE** | Snapshot API is useful. Do not claim SBOM enforcement. |
| **PRIORITY** | P2 |

- **Claimed property:** unapproved / drifted agents cannot run  
- **Before dangerous op:** **no**  
- **Fail-open:** always  
- **Test:** none  

### HITL

| Field | Value |
|-------|-------|
| **COMPONENT** | `apps/framework/hitl_gate.py` |
| **PURPOSE** | Human approval for high-value loan actions |
| **CURRENT STATUS** | Env flag **works**. Default `HITL_GATE_ENABLED=false` → required but **not blocked**. Only on compliance agent. Amount parsed by regex. |
| **LIVE / HYBRID / SIMULATED / REPLAYED** | HYBRID (live when enabled) |
| **STRENGTHS** | Clear vulnerable vs enforced demo; telemetry `hitl_bypassed` |
| **WEAKNESSES** | Default fail-open; missing amount → pass |
| **SECURITY CONCERNS** | INV-008 / INV-006: high-value auto-approve is the default profile |
| **TEST COVERAGE** | None |
| **SPLUNK DEPENDENCY** | `hitl_*` fields |
| **MIGRATION DECISION** | **REFACTOR** |
| **RATIONALE** | Keep as an explicit **vulnerable** profile. Defended profile must REQUIRE_APPROVAL before the action. |
| **PRIORITY** | P0 |

- **Claimed property:** high-value actions need a human  
- **Before dangerous op:** yes when enabled  
- **Missing amount:** ALLOW  
- **Fail-open:** default yes  
- **Test:** none  

### Memory policy

| Field | Value |
|-------|-------|
| **COMPONENT** | `apps/framework/memory_policy.py` |
| **PURPOSE** | Block persistent memory writes; detect multi-turn trust decay |
| **CURRENT STATUS** | Regex write-block before LLM. Drift is alert-only (`len(facts) >= 4` and low average trust). In-memory dict. |
| **LIVE / HYBRID / SIMULATED / REPLAYED** | HYBRID |
| **STRENGTHS** | Write patterns blocked pre-LLM |
| **WEAKNESSES** | Drift never blocks; not durable memory |
| **SECURITY CONCERNS** | INV-003 not enforced for drift |
| **TEST COVERAGE** | None |
| **SPLUNK DEPENDENCY** | `memory.*` |
| **MIGRATION DECISION** | **REFACTOR** writes; **REDESIGN** trust-tagged memory |
| **RATIONALE** | Phase 1 can omit durable memory. Later: trust labels on records. |
| **PRIORITY** | P2 |

- **Claimed property:** untrusted memory cannot become instruction  
- **Before dangerous op:** write regex yes; drift no  
- **Fail-open:** drift and missing patterns  
- **Test:** none  

### RAG

| Field | Value |
|-------|-------|
| **COMPONENT** | `apps/framework/rag_store.py` |
| **PURPOSE** | Detect RAG exfil probes (Galileo-style) |
| **CURRENT STATUS** | Regex probe counter. Alert only. No vector store. Doc-ingest agent only. |
| **LIVE / HYBRID / SIMULATED / REPLAYED** | SIMULATED |
| **STRENGTHS** | Hunt telemetry |
| **WEAKNESSES** | Never blocks; no retrieval ACLs |
| **SECURITY CONCERNS** | INV-002 not present (there is no RAG) |
| **TEST COVERAGE** | None |
| **SPLUNK DEPENDENCY** | `galileo_observe_alert` |
| **MIGRATION DECISION** | **REDESIGN** or omit in Phase 1 |
| **RATIONALE** | Do not teach “Galileo blocked exfil” from an alert-only regex. |
| **PRIORITY** | P2 |

- **Claimed property:** retrieval exfil is observed / stopped  
- **Before dangerous op:** check exists, **does not stop** the op  
- **Fail-open:** by design  
- **Test:** none  

### Orchestration / workflow Foundry guard

| Field | Value |
|-------|-------|
| **COMPONENT** | `apps/framework/orchestration_guard.py` |
| **PURPOSE** | Reject unauthorized orchestrator override |
| **CURRENT STATUS** | No-op unless `FOUNDRY_TRACE_STATE` or `orchestrator_override` in text |
| **LIVE / HYBRID / SIMULATED / REPLAYED** | SIMULATED |
| **STRENGTHS** | Blocks before LLM when markers present |
| **WEAKNESSES** | No real workflow state machine |
| **SECURITY CONCERNS** | INV-006 not enforced |
| **TEST COVERAGE** | None |
| **SPLUNK DEPENDENCY** | `foundry.*` |
| **MIGRATION DECISION** | **REDESIGN** |
| **RATIONALE** | AgentSec needs authorized state transitions, not Foundry string theater. |
| **PRIORITY** | P2 |

- **Claimed property:** pipeline cannot be overridden from the prompt  
- **Before dangerous op:** only if markers present  
- **Missing context:** PASS  
- **Fail-open:** yes  
- **Test:** none  

### Control validator

| Field | Value |
|-------|-------|
| **COMPONENT** | `control_validator.py` + `control_matrix.yaml` |
| **PURPOSE** | Post-hoc PASS/FAIL/NOT_APPLICABLE from field bag |
| **CURRENT STATUS** | Measurement, not enforcement. Missing fields → NOT_APPLICABLE. Missing matrix → empty list. |
| **LIVE / HYBRID / SIMULATED / REPLAYED** | REPLAYED attestation |
| **STRENGTHS** | Separates evidence from blocking. Feeds Splunk attestation. |
| **WEAKNESSES** | String/prefix matching; no `control.id` on the event (see Splunk BROKEN join) |
| **SECURITY CONCERNS** | Dashboards can look attested without a control having run |
| **TEST COVERAGE** | None |
| **SPLUNK DEPENDENCY** | Hard |
| **MIGRATION DECISION** | **REUSE** as measurement; never as enforcement |
| **RATIONALE** | Honest idea. Emit per-control IDs if AgentSec attests. |
| **PRIORITY** | P1 |

- **Claimed property:** NIST controls were tested  
- **Before dangerous op:** **no** (after)  
- **Missing context:** NOT_APPLICABLE, not FAIL  
- **Fail-open:** yes for attestation  
- **Test:** none  

### SOAR simulator

| Field | Value |
|-------|-------|
| **COMPONENT** | `apps/framework/soar_simulator.py` |
| **PURPOSE** | Emit quarantine playbook telemetry |
| **CURRENT STATUS** | Sleep + fake latency. Triggered after LLM on campaign week 10. Does not isolate anything. |
| **LIVE / HYBRID / SIMULATED / REPLAYED** | SIMULATED |
| **STRENGTHS** | Closed-loop narrative for workshops |
| **WEAKNESSES** | After the fact; no containment |
| **SECURITY CONCERNS** | False sense of response |
| **TEST COVERAGE** | None |
| **SPLUNK DEPENDENCY** | `containment.action` |
| **MIGRATION DECISION** | **DROP** as a control; optional later SIMULATED response lab |
| **RATIONALE** | Violates honesty if copied as “SOAR quarantined the agent.” |
| **PRIORITY** | P4 |

- **Claimed property:** compromised agent is contained  
- **Before dangerous op:** **no**  
- **Fail-open:** always (nothing is contained)  
- **Test:** none  

---

## OBSERVABILITY

**Does telemetry record what happened or what was intended?**  
**INFERRED:** LIVE `call_ollama()` logs mostly record what happened (tokens, latency, previews, actual guard flags). SIMULATED/chain paths record **intended story fields**, including preset `HARD_DENY`. HYBRID can mix both under one `incident_id`.

| Field | LIVE path | SIMULATED / chain |
|-------|-----------|-------------------|
| `run.id` | **Does not exist** | **Does not exist** |
| `attack.id` | **Does not exist** | **Does not exist** |
| `incident_id` | New per agent unless passed; omitted on baseline logs | Shared across chain stages |
| `session.id` | Emitted | Varies |
| `session_id` | Used in APIs; Splunk EXTRACT looks for this JSON key | — |
| Traces | Real OTel spans per LLM call | Synthetic `traceId` on log records |
| Metrics | Collector debug only, not Splunk | — |

### OTel collector

| Field | Value |
|-------|-------|
| **COMPONENT** | `config/otel-collector-config.yaml` |
| **PURPOSE** | Logs + traces → Splunk HEC; metrics → debug; file archive |
| **CURRENT STATUS** | Working pattern |
| **LIVE / HYBRID / SIMULATED / REPLAYED** | LIVE pipeline |
| **STRENGTHS** | Apps do not speak Splunk SDK |
| **WEAKNESSES** | Traces as HEC events, not APM; CORS `*` on OTLP HTTP |
| **SECURITY CONCERNS** | Lab TLS skip-verify defaults |
| **TEST COVERAGE** | None |
| **SPLUNK DEPENDENCY** | Critical |
| **MIGRATION DECISION** | **REUSE** |
| **RATIONALE** | Proven shape. Add fidelity routing later. |
| **PRIORITY** | P0 |

---

## SPLUNK

**Apps:** `splunk_compliance_app` (`acme_genai_compliance` v2.12.2) canonical; `App-Agentic-Compliance` v1.1.0 labeled legacy.

**Dashboards OBSERVED:** 15 in canonical app + 1 legacy = 16.

| Studio (`version="2"`) | Classic (`version="1.1"`) |
|------------------------|---------------------------|
| `executive_governance.xml` | 13 other canonical views |
| `exercise_runner.xml` | plus `splunk_cloud_setup.xml` |
| | `cross_app_normalization.xml` forces `theme="dark"` |

**Correction vs older notes:** practitioner dashboards are **not** mostly Studio. Only **2 of 15** canonical views are Dashboard Studio.

**Lookups:** 13 static CSVs, synced from Python — **not** live-derived.

**Saved searches:** 29, all `disabled=1`. Real alert metadata when enabled. Dashboards use **separate inline SPL**.

**SPL class for the suite:** **PLAUSIBLE BUT UNVALIDATED**, except:

| Issue | Class |
|-------|-------|
| `props.conf` EXTRACT `session_id` from `"session_id"` while LIVE logs emit `"session.id"` | **BROKEN** |
| `nist_rmf_compliance.xml` joins `control.id`; events emit `control.failed_ids` / status, not `control.id` | **BROKEN** |
| `package_splunk_app.sh` VERSION vs `app.conf` 2.12.2 | packaging drift (would fail validator check if run) |
| MLTK `fit ctsm_forecast` without MLTK+CTSM | **UNKNOWN** at runtime |
| Exercise Runner “reveal” text | hardcoded CSV, not telemetry |

**“What happened”:** Exercise explanations and actor-chain `rogue_actor_story` are **pre-authored**. Hunt tables can be live. AgentSec rule: “What happened?” must be derived from actual telemetry.

| Field | Value |
|-------|-------|
| **COMPONENT** | Canonical Splunk app + generators + `validate_splunk_app.sh` |
| **PURPOSE** | Hunt, coverage, attestation, workshops, executive view |
| **CURRENT STATUS** | Mature teaching suite; Cloud-vetting oriented |
| **STRENGTHS** | Macros for index portability; lookup SSOT; Exercise Runner pedagogy; codegen for Studio |
| **WEAKNESSES** | Classic majority; field mismatches; no SPL tests; version drift |
| **SECURITY CONCERNS** | No secrets in SPL; customer HEC is external |
| **TEST COVERAGE** | Packaging/XML/color checks only — **not SPL** |
| **SPLUNK DEPENDENCY** | Self |
| **MIGRATION DECISION** | **REUSE** macros/lookup/codegen ideas; **REFACTOR** field contract; **REDESIGN** most Classic views in Studio later; **DROP** legacy app |
| **RATIONALE** | Do not import 15 dashboards on day one. Port the loop: baseline → hunt → evidence. |
| **PRIORITY** | P0 (index + a few validated searches) / P2 (full suite) |

---

## INTEGRATIONS

| Integration | Classification | Migration |
|-------------|----------------|-----------|
| Lab regex AcmeGate / AcmeSentinel | IMPLEMENTED (lab) | REFACTOR as reference controls |
| Cisco AI BOM CLI | PARTIALLY IMPLEMENTED (local manifest); REFERENCED ONLY in default Docker | Optional later |
| MCP Scanner CLI | PARTIALLY IMPLEMENTED (local JSON); REFERENCED ONLY in default Docker | REDESIGN MCP itself |
| DefenseClaw | REFERENCED ONLY | DROP name; keep AcmeSentinel |
| Skill Scanner | REFERENCED ONLY (string `UNSIGNED_SKILL`) | DROP for v1 |
| A2A tooling | SIMULATED | REDESIGN |
| MAESTRO lab APIs | PARTIALLY IMPLEMENTED | REUSE maps later |
| CSA MAESTRO UI | REFERENCED ONLY (external Node app) | Optional |
| CTSM / MLTK | SIMULATED scores + REFERENCED Splunk algo | Optional |
| Foundation-Sec-8B | PARTIALLY IMPLEMENTED (optional Ollama pull) | Optional |
| Cisco commercial platform | REFERENCED ONLY (`docker-compose.cisco.yml` is env flags) | Do not copy the claim |
| `LAB_MODE=enforce` / `should_block_from_cisco_scan()` | Dead code — **never called** | DROP claim or wire it |

---

## QUALITY

| Area | OBSERVED |
|------|----------|
| Unit / integration / security / telemetry tests | **Zero** `test_` / pytest / unittest files |
| Splunk validation | `validate_splunk_app.sh` (structure). **Not run in this pass.** Does not execute SPL. |
| Secrets | Lab defaults in compose, `.env.example`, Flask fallback, HEC emitter fallbacks |
| Error handling | Cisco module relatively careful; Ollama errors fail-open; many Flask routes unauthenticated |
| Duplicated logic | Baseline templates; MCP/A2A in workflow_guard + campaign_enrichment; Cisco preflight triple scan |
| Dead code | `should_block_from_cisco_scan`, `approved_slm_catalog.json` unused, `export_splunk_events_to_jsonl` unwired, phase rename scripts |
| Documentation accuracy | Honest on regex-not-product. Overclaims: commercial Cisco platform, enforce mode, dashboard counts in REFERENCE.md, “45 vs 51”, Studio-everywhere myth |

---

## Decision rollup

| Decision | Count (meaningful components) |
|----------|-------------------------------|
| **REUSE** | Registry schema, Top 10 stories, learning tiers, baseline LIVE traffic, OTel→HEC, compose overlays, control matrix as measurement, Splunk macros/lookup codegen, Exercise Runner *idea*, CONCEPTS-style limitations |
| **REFACTOR** | Banking shell, router correlation, LLM client, Attack Panel, HITL profiles, input/output regex as labeled reference controls, executor fidelity, chain engine labels, Splunk field contract |
| **REDESIGN** | MCP, A2A, RAG, Foundry orchestration, memory trust, AIBOM enforcement, most Classic dashboards for AgentSec Studio standard |
| **DROP** | Legacy Splunk app, phase bulk-rename scripts, SOAR-as-control, Skill Scanner/DefenseClaw embedding, unused catalog (or wire it), copying all 51 generic payloads, enforce-mode claim, commercial Cisco claim |

No AgentWatch code was migrated.
