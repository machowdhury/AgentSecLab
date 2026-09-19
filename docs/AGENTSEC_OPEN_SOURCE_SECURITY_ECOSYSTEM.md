# AgentSec open-source security ecosystem

**Status:** Phase 8A RESEARCH. Inspected 2026-09-15.  
**Not an integration plan by itself.** Strategies: `docs/AGENTSEC_BUILD_VS_INTEGRATE.md`.  
**Do not invent projects.** Names below were verified via GitHub org/repos, project READMEs, or current product docs.

Catalog date is a snapshot. Re-verify before any wire-up.

---

## Cisco AI Defense OSS (`github.com/cisco-ai-defense`)

Public org (17 repos). Core lab must not require these.

| Repo | Purpose (from project, not nickname) | Class | Strategy |
|------|--------------------------------------|-------|----------|
| **mcp-scanner** | Python scanner for MCP servers/tools. Engines: YARA, LLM analysis, optional Cisco AI Defense inspect API. Module `mcpscanner`. | SECURITY SCANNER | **CALL EXTERNALLY** then **IMPORT OUTPUT** as labeled evidence. Do not let a finding become runtime DENY unless a later lab tests a pre-op caller. |
| **skill-scanner** | Scanner for Agent Skills (tool/skill packages). Highest stars in the org. | SECURITY SCANNER | **CALL EXTERNALLY / IMPORT OUTPUT** when AgentSec has a skill/catalog lab. Not useful until that surface exists. |
| **aibom** | AI Bill of Materials: models, agents, tools, MCP clients/servers, datasets, prompts, guardrails, secrets from source/containers. CLI `cisco-aibom`. | SUPPLY CHAIN | **CALL EXTERNALLY / IMPORT OUTPUT**. Inventory evidence, not authorization. |
| **defenseclaw** | Governance for OpenClaw/agentic runtimes: scan capabilities, inspect traffic, export audit evidence. Python CLI + Go gateway + policy bundles. Wraps skill/MCP scanners. | POLICY / CONTROL | **REFERENCE ONLY** for now. Do **not** embed as AcmeBank. Optional overlay later only with a tested caller. AgentSec already forbids implying AcmeSentinel is DefenseClaw. |
| **a2a-scanner** | Scan A2A agents for threats. Org description verified; README fetch returned empty on 2026-09-15. | SECURITY SCANNER | **REFERENCE ONLY** until AgentSec has an A2A lab. Then CALL EXTERNALLY. |
| **model-provenance-kit** | Assess model provenance. | SUPPLY CHAIN | **CALL EXTERNALLY** on an optional model-scan lab. |
| **adversarial-hubness-detector** | Scanner for adversarial hubs in RAG / vector DBs. | SECURITY SCANNER | **CALL EXTERNALLY** when RAG exists. |
| **pickle-fuzzer** | Fuzz pickle-serialized ML artifacts. | SECURITY SCANNER / RED TEAMING | **CALL EXTERNALLY** on a model-artifact lab. |
| **ai-defense-cli** | CLI bundling model-scan, mcp-scan, ai-bom for CI. | SECURITY SCANNER | **CALL EXTERNALLY** as an optional operator path. |
| **ai-defense-python-sdk** | SDK for commercial AI Defense inspect APIs. | POLICY / CONTROL | **OPTIONAL CISCO ENRICHMENT** only. Not core. |
| **ai-defense-langchain-middleware** | LangChain middleware for AI Defense. | POLICY / CONTROL | **DO NOT INTEGRATE** into AcmeBank (not LangChain). REFERENCE if a later adapter exists. |
| **ai-defense-google-adk** | Google ADK plugin: LLM and MCP inspection callbacks. | POLICY / CONTROL | **DO NOT INTEGRATE** (AgentSec is not ADK). |
| **ai-defense-hybrid** | Sparse public description. | — | **REFERENCE ONLY** until docs are readable. |
| **securebert2** | Security language model weights/code. | EVALUATION / MODEL | **REFERENCE ONLY**. Not a lab control. |
| **fpr-model-calibration** | Calibrate detector scores to a fixed FPR. | DETECTION SUPPORT | **REFERENCE ONLY** (research). |
| **litellm** (fork) | LiteLLM gateway fork. | NOT USEFUL FOR AGENTSEC | **DO NOT INTEGRATE**. AgentSec uses Ollama directly. |
| **.github** | Org files. | — | Ignore. |

### Foundation / Antares (Cisco Foundation AI, not the AI Defense org)

Verified on Hugging Face `fdtn-ai` and Cisco blogs:

| Project | Actual purpose | Strategy |
|---------|----------------|----------|
| **Foundation-Sec-8B** / Instruct / Reasoning | Open-weight cybersecurity LLMs. Optional second Ollama model. | **WRAP** as optional hunt-assist. Never authorization. Label model id in telemetry. |
| **Antares-350M / 1B** | Vulnerability **localization in codebases**, not agent SOC investigation. | **DO NOT INTEGRATE** into AgentSec core labs. REFERENCE if a later code-agent lab exists. |

Predecessor AgentWatch optionally pulled Foundation-Sec. AgentSec Phase 2 reuse **removed** that pull on purpose. Re-adding it is an optional overlay, not a default image.

---

## Other verified OSS (useful)

| Project | Org / home | Class | Strategy | Why AgentSec cares |
|---------|------------|-------|----------|-------------------|
| **Garak** | NVIDIA (`github.com/NVIDIA/garak`) | RED TEAMING / SECURITY SCANNER | **CALL EXTERNALLY / USE AS ATTACK FIXTURE** | Model-level probes. Do not treat a Garak hit as AgentSec runtime DENY. Import report → evidence. |
| **PyRIT** | Microsoft | RED TEAMING | **USE AS ATTACK FIXTURE / CALL EXTERNALLY** | Multi-turn orchestration. Map only fixtures that exercise an AgentSec invariant. |
| **Promptfoo** | promptfoo | EVALUATION / RED TEAMING | **USE AS TEST ORACLE** | CI regressions on CTRL-INPUT-001 / system prompts. Optional. |
| **Inspect AI** | UK AISI (`inspect-ai`) | EVALUATION | **REFERENCE ONLY** then optional CALL EXTERNALLY | Heavy eval harness. Not the first integration. |
| **AgentDojo** | ETH/research (verify tag at wire-up) | EVALUATION / DATASET | **USE AS ATTACK FIXTURE** | Tool-use robustness. Only after AgentSec has an LLM-selected tool path (today tools are coded, not model-chosen). |
| **CyberSecEval** | Meta Purple Llama | EVALUATION / DATASET | **USE AS ATTACK FIXTURE** | Cybersecurity LLM evals. Not runtime. |
| **NeMo Guardrails** | NVIDIA | POLICY / CONTROL | **REFERENCE ONLY** | Runtime rails. AgentSec teaches *placement*, not replacing CTRL-* with Colang. |
| **Guardrails AI** | Guardrails AI | POLICY / CONTROL | **REFERENCE ONLY** | Same reason. |
| **LlamaFirewall** | Meta PurpleLlama | POLICY / CONTROL | **REFERENCE ONLY / WRAP later** | PromptGuard / AlignmentCheck / CodeShield. Optional comparison to CTRL-INPUT-001; do not replace the teaching control silently. |
| **mcp-scan** (Invariant Labs) | `github.com/invariantlabs-ai/mcp-scan` | SECURITY SCANNER | **CALL EXTERNALLY / IMPORT OUTPUT** | Tool poisoning, rug-pull pinning, cross-origin. Complements Cisco mcp-scanner. Do not send lab tool names to a cloud API in default core. |
| **OpenTelemetry GenAI / MCP semconv** | OpenTelemetry + MCP SDK | OBSERVABILITY / TELEMETRY SOURCE | **INTEGRATE** (already partial) | AgentSec already emits `gen_ai.*` and MCP fields. Align future A2A/MCP spans with published semconv; do not fork names. |
| **a2aproject/A2A** | Linux Foundation (Google-contributed) | IDENTITY / AUTHORIZATION (protocol) | **INTEGRATE later** | Protocol 1.0.0, JSON-RPC over HTTP, Agent Cards. AgentSec A2A lab should speak this, not a fake regex “A2A”. |
| **OWASP GenAI Top 10 2026** + **ASI 2026** | OWASP | LEARNING SUPPORT | **REFERENCE ONLY** | Mapping source. Not executable. |
| **MITRE ATLAS** | MITRE | LEARNING SUPPORT | **REFERENCE ONLY** | Mapping source. Revalidate IDs before teaching. |

---

## Verified but limited / not first-wave

| Project | Notes | Strategy |
|---------|-------|----------|
| Lakera Guard | Commercial. Gandalf is a game. | **DO NOT INTEGRATE** product. REFERENCE for teaching. |
| Protect AI ModelScan | Pickle/model scan; ecosystem moved under Cisco-related AI security. Prefer Cisco pickle-fuzzer / model-provenance-kit when choosing one. | **CALL EXTERNALLY** only if still independently maintained at wire-up. |
| Trail of Bits | Consulting + specialized tools; no AgentSec-shaped agent range found in this pass. | **REFERENCE ONLY** |
| Microsoft Agent Framework / Semantic Kernel | App frameworks, not SOC labs. | **DO NOT INTEGRATE** |
| Google ADK | App framework. Cisco already has a plugin. | **DO NOT INTEGRATE** |
| NIST AI RMF / AI 600-1 | Frameworks, not code. | **REFERENCE ONLY** |
| Splunk Enterprise Security | Commercial. | **OPTIONAL SPLUNK ENTERPRISE** — notables later, never required for core |

---

## Explicitly not useful as AgentSec core

- Embedding DefenseClaw gateway as the bank
- LiteLLM as a new LLM hop
- Antares as a Splunk investigator
- Any scanner whose only UI is “open this URL”
- Cluster/Cloud admin skills from the Splunk Agent Skills catalog (already out of KO scope)

---

## Splunk / Cisco analytics (optional Enterprise)

| Name | Purpose | Strategy |
|------|---------|----------|
| **Splunk AI Toolkit** (former MLTK) | In-Splunk ML / agents | OPTIONAL SPLUNK ENTERPRISE after event-derived metrics exist |
| **Cisco Deep Time Series Model (CDTSM)** | Zero-shot forecast/anomaly on metric series (`apply CDTSM`) | OPTIONAL; not a replacement for DET-MCP-001. Hugging Face `cisco-ai/cisco-time-series-model-1.0` |

---

## Integration quality bar (every tool)

If an OSS project cannot produce **one** of:

- a safe AgentSec fixture
- imported findings with evidence class OBSERVED or SIMULATED
- a control decision **before** a dangerous operation
- Splunk-investigable fields after a field contract

then strategy is REFERENCE ONLY.

Default evidence class for scanner CLI output: **OBSERVED** for “the CLI ran and emitted JSON,” **not** “the MCP server is malicious in production,” and **not** runtime DENY.
