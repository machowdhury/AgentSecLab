# AgentSec expansion architecture

**Status:** Phase 8A DESIGN / RESEARCH ONLY.  
**Does not implement integrations, runtime, schema, SPL, detections, or dashboards.**  
**Schema remains 1.4.0.** Splunk remains the investigation/evidence plane, not the authorization plane.

Parents: `docs/ARCHITECTURE.md`, `docs/INTEGRATION_ARCHITECTURE.md`, `docs/SECURITY_INVARIANTS.md`, `docs/SPLUNK_ENGINEERING_GOVERNANCE.md`.

Companions: `AGENTSEC_OPEN_SOURCE_SECURITY_ECOSYSTEM.md`, `AGENTSEC_ATTACK_RESEARCH_PIPELINE.md`, `AGENTSEC_TELEMETRY_ROADMAP.md`, `AGENTSEC_ANALYTICS_ROADMAP.md`, `AGENTSEC_LEARNING_ARCHITECTURE.md`, `AGENTSEC_BUILD_VS_INTEGRATE.md`, `AGENTSEC_ROADMAP_2026.md`.

---

## What this phase decides

AgentSec is a complete MCP authorization teaching range for one coded bank workflow:

prompt injection → tool grant → scope → resource → result trust → confused deputy.

The next problem is not “add MCP-007 because the number exists.” The next problem is how AgentSec becomes a broader agentic-security **learning, testing, detection, and SOC-evidence** platform without becoming a web page of tool links.

Every future integration must answer:

| Question | Required answer |
|----------|-----------------|
| What security property does this test? | An AgentSec invariant or a named control decision |
| What evidence does it produce? | Events, artifacts, or imported findings with an evidence class |
| What invariant does it exercise? | INV-001–INV-008, or a new invariant proposed with a lab |
| What can Splunk investigate? | Indexed fields, after a field contract |
| What can the learner observe / hunt / defend / retest? | The ten-step workshop, not a screenshot of a vendor UI |
| What proof distinguishes prevention from telemetry silence? | Runtime handler/LLM spy first; Splunk corroborates |

Rejected architecture: “a UI containing links to security tools.”

---

## Current AgentSec capability map

Traced to `src/agentsec/` and validated labs. Labels are IMPLEMENTED / PARTIAL / PLANNED / ABSENT. Documentation alone is not proof.

| Capability | Status | Implementation evidence | Gap |
|------------|--------|-------------------------|-----|
| Prompt / input security | **IMPLEMENTED** | `CTRL-INPUT-001` in `src/agentsec/controls.py`; LAB-PI-001; DENY before Ollama | Teaching regex, not a product IPS |
| MCP tool authorization | **IMPLEMENTED** | `CTRL-MCP-001` in `mcp/authorize.py`; LAB-MCP-001 | Coded allow-list, not IAM |
| MCP scope authorization | **IMPLEMENTED** | requested vs `allowed_scope`; LAB-MCP-003 | Equality helper, not subset algebra |
| MCP resource authorization | **IMPLEMENTED** | `authorize_resource`; LAB-MCP-004 | Fixture catalog only |
| MCP result trust | **IMPLEMENTED** | `CTRL-MCP-RESULT-001`; LAB-MCP-005 | Interpreter is lab-only |
| Confused deputy / delegation | **IMPLEMENTED** | `CTRL-DELEGATION-001`; LAB-MCP-006 | One hop; no chain; `allowed_tools` not indexed |
| Identity | **PARTIAL** | Coded `AgentSpec` ids; allow-list; MCP-006 caller/deputy labels | No A2A, no crypto passport, hop-1 deputy not first-class |
| Telemetry | **IMPLEMENTED** | Schema 1.4.0; OTLP logs; HEC; `agentsec_telemetry` / `otel:agentic:json` | One sourcetype; no scanner/RAG/A2A events |
| Evidence bundles | **IMPLEMENTED** | `artifacts/<run-id>/` via `evidence.py` | No scanner or A2A packs |
| Splunk investigation | **IMPLEMENTED** | Q-PI / Q-MCP hunts; live validated | Field contract required before new SPL |
| Detection engineering | **PARTIAL** | `DET-MCP-001` disabled; Splunk KO governance | One predicate; hunts must not auto-promote |
| Dashboard Studio | **IMPLEMENTED** | Six GRID workshops | Bind-only validated SPL |
| Attack simulation | **PARTIAL** | Attack Service (PI); `/mcp/invoke` fixtures | No red-team generator; no RAG/A2A payloads |
| Policy / control model | **PARTIAL** | Coded `McpPolicy` objects; two profiles | No policy language, no Cisco policy bundles |
| Learning / workshop model | **IMPLEMENTED** | LEARN→PROVE; `/ui-review`; `/logic-proof` | No research-lab track yet |
| A2A | **ABSENT** | `agents.py` is in-process handoff, documented not A2A | New protocol + identity |
| RAG | **ABSENT** | No retriever | New store + INV-002 lab |
| Agent memory (trust-tagged) | **ABSENT** | `MemorySink` is telemetry, not agent memory | INV-003 still future-facing |
| Supply-chain scanning | **ABSENT** in runtime | Predecessor AgentWatch had optional CLI; AgentSec core does not call scanners | Import path not built |
| MLTK / time-series | **PLANNED** | `docs/INTEGRATION_ARCHITECTURE.md` | No metrics index |
| Cisco commercial overlay | **PLANNED** | Teach-mode later; core has zero vendor runtime dependency | Must stay optional |
| ES notables | **ABSENT** | DET-MCP-001 is not an ES notable | Do not add to complete a lab |

---

## Security surfaces that exist vs surfaces that do not

Already governed in runtime (before the dangerous operation):

```text
HTTP body  → CTRL-INPUT-001 → LLM
MCP invoke → CTRL-MCP-001 (tool/scope/resource)
MCP result → CTRL-MCP-RESULT-001 (data ≠ grant)
Deputy call → CTRL-DELEGATION-001 → CTRL-MCP-001 → handler
```

Not yet a trust boundary in AgentSec:

- MCP **tool description / catalog** (Invariant-style tool poisoning)
- MCP **server provenance** (who published this server)
- **Agent Card** / A2A identity (`a2aproject/A2A` 1.0.0)
- Retrieved RAG chunks
- Durable memory records
- Package / model / pickle artifacts
- Scanner verdicts (must not silently become DENY)

---

## Integration law

Prefer **BUILD** for: security-property modeling, safe fixtures, control placement, telemetry, evidence, investigation, detection reasoning, workshops.

Prefer **INTEGRATE / WRAP / IMPORT OUTPUT** for: mature scanners, red-team harnesses, AI BOM, eval frameworks.

Never:

- Embed DefenseClaw as if it were AcmeBank
- Treat scanner FAIL as MEASURED runtime DENY unless a tested pre-op caller exists
- Invent Splunk fields to display a scanner UI
- Bump schema to “look ready” for A2A

Optional tracks remain overlays (`docs/INTEGRATION_ARCHITECTURE.md`):

```text
Core lab (required)
  AcmeBank + Attack Service + Ollama + OTel + Splunk ingest

Optional
  ├─ OPEN-SOURCE LAB INTEGRATION     CLI scanners, imported JSON as evidence
  ├─ OPTIONAL CISCO ENRICHMENT       AI Defense inspect API, Foundation-Sec model
  └─ OPTIONAL SPLUNK ENTERPRISE      ES, AI Toolkit / CDTSM, notables
```

Core must run without commercial Cisco or Splunk ES.

---

## Next-domain ranking (do not auto-lab all)

| Domain | Rank after MCP-006 | Why |
|--------|--------------------|-----|
| MCP tool-description / catalog poisoning | **1 — next** | Completes MCP trust; scanners exist; no new protocol |
| MCP server provenance / rug-pull | 2 | Same surface; needs pinning/hash telemetry |
| Agent identity (INV-005 deepen) | 3 | Dependency for honest A2A; avoid crypto theater |
| A2A / inter-agent messages (ASI07) | 4 | Real protocol (`a2aproject/A2A`); needs identity + schema |
| Indirect prompt injection via retrieved content | 5 | Distinct from MCP-005 result-trust; needs RAG fixture |
| Memory poisoning (INV-003) | 6 | Needs durable store |
| Credential / token delegation | 7 | Easy to fake; only after identity |
| Package / pickle / model provenance | 8 | Supply-chain track; import scanner output |
| Authorization drift / config drift | 9 | Needs time-series of grants |
| Excessive agency / long-running anomalies | 10 | Needs metrics; deterministic rules first |
| Multi-agent collusion | later | Easy to simulate dishonestly |
| Delegation chains beyond one hop | later | MCP-006 already taught the property |

---

## Cisco + Splunk architecture (non-exclusive)

Verified names (2026-09-15):

| Name | What it actually is |
|------|---------------------|
| Cisco AI Defense OSS org | https://github.com/cisco-ai-defense (17 public repos) |
| mcp-scanner | Scan MCP servers/tools (YARA / LLM / optional AI Defense inspect API) |
| skill-scanner | Scan agent skills |
| aibom | AI Bill of Materials from source/containers |
| defenseclaw | Governance layer for OpenClaw/agent runtimes (CLI + gateway + policy). **Not** AgentSec’s control plane |
| a2a-scanner | Scan A2A agents |
| Foundation-Sec-8B family | Cisco Foundation AI open-weight security LLM (Hugging Face `fdtn-ai`) |
| Antares | Small models for **vulnerability localization in code**, not agent SOC |
| Cisco Deep Time Series Model (CDTSM) | Splunk AI Toolkit preview; `apply CDTSM`; Hugging Face `cisco-ai/cisco-time-series-model-1.0` |
| Splunk AI Toolkit | Current name for former MLTK (v6 documents Agent Launchpad) |

Antares is **not** the next AgentSec SOC model. It localizes CVEs in repos. Foundation-Sec remains the optional second Ollama model for hunt-assist, not authorization.

---

## Splunk KO roadmap (design only — no objects in 8A)

Follow: QUESTION → EVIDENCE → TELEMETRY → FIELD CONTRACT → KO.

Do not create searches, detections, macros, CIM maps, data models, or dashboards in this phase.

Future categories, only when a lab produces the telemetry:

- Investigation / hunt searches (reuse Q-MCP where the question is unchanged)
- Detections only after the detection gate
- Optional second sourcetype for **imported scanner JSON**
- Macros after revalidation (do not silently rewrite Q-* onto `` `agentsec_index` ``)
- CIM: keep AgentSec authorization fields **NOT APPLICABLE** unless an honest map exists
- Metrics index later for behavioral track
- Dashboards only after live validation + `/splunk-ko-review` + `/ui-review`

---

## Recommended next phase (not started)

**Phase 8B — MCP catalog integrity / tool-description poisoning (DESIGN).**

Not MCP-007-by-number. See `docs/AGENTSEC_ROADMAP_2026.md`.

---

## Stop

No runtime, schema, SPL, detection, or workshop implementation in Phase 8A.
