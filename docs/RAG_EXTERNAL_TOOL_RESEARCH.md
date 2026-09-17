# RAG / retrieved-context — external tool research

**Status:** Phase 10A DESIGN / RESEARCH. **No integration.**  
**Research date:** 2026-09-16.  
**Evidence class:** **DOCUMENTED**.

Parents: `docs/RAG_PREDECESSOR_ANALYSIS.md`, `docs/AGENTSEC_BUILD_VS_INTEGRATE.md`, `docs/EXTERNAL_AGENT_SECURITY_TOOL_LANDSCAPE.md`.

Do not rebuild capabilities that strong open-source projects already provide **unless** AgentSec’s teaching property is unique (INV-002 + Splunk reconstruction). The unique AgentSec slice is: **retrieved bytes must not become authority**, with deterministic authz evidence. Most RAG-security tools classify or filter **text**. That is complementary, not a replacement.

---

## Classification key

| Label | Meaning |
|-------|---------|
| **BUILD** | AgentSec should own this (runtime grant, overlay, OTEL, Splunk contracts). |
| **INTEGRATE** | Call externally later; import output as independent evidence. Not 10A/10B required. |
| **REFERENCE** | Teach from docs/incidents; do not wire. |
| **NOT RELEVANT** | Wrong problem, unsafe, or already closed in another chapter. |

---

## Tools and projects

| Project | What it is | RAG-specific? | Classification | Notes |
|---------|------------|---------------|----------------|-------|
| **AgentSec CTRL-RAG-CONTEXT-001 + CTRL-MCP-001 composition** | Observation + server-owned grant | Yes (this lab) | **BUILD** | Unique teaching. Do not outsource authorization to a filter. |
| **Deterministic fixture retriever** | JSON/Markdown exact-id | Lab | **BUILD** | Smallest honest retrieve. |
| **NVIDIA NeMo Guardrails retrieval rails** | Inspect/transform chunks before prompt merge | Yes | **REFERENCE** (later overlay **INTEGRATE**) | Closest OSS “context rail.” Must not become CTRL-MCP-001. Docs describe retrieval rails separately from input/output. |
| **Cisco AI Defense inspect / NeMo inspect** | Prompt/response inspect API | Indirect PI related | **REFERENCE** | Already constrained in scanner chapter. Inspect FAIL ≠ DENY. Not a retriever. |
| **Cisco mcp-scanner** | Static MCP YARA | No | **NOT RELEVANT** | Catalog chapter complete. Do not extend into RAG. |
| **Snyk Agent Scan** | MCP/skill scanner | No | **NOT RELEVANT** | Not started; not RAG. |
| **Microsoft Prompt Shields / Azure AI Content Safety** | Direct + indirect PI classifiers | Related | **REFERENCE** | Commercial. MSRC 2025: pair with **permissions**. Matches AgentSec lesson. |
| **EchoLeak / Copilot incidents** | Zero-click indirect PI | Related | **REFERENCE** | Do not recreate M365 exfil. |
| **PoisonedRAG code / paper** | Corpus poisoning optimizer | Yes | **REFERENCE** | Do not import the attack optimizer as a lab kernel. Optional later research reproduction, SIMULATED vs OBSERVED labeled. |
| **AgentPoison** | Memory/KB backdoor | Related | **REFERENCE** | Memory path is INV-003, out of 10A. |
| **garak** (NVIDIA) | LLM vulnerability scanner, injection probes | Related | **INTEGRATE** later | Probe suite for *model* behavior. Not authorization. Evidence: OBSERVED_SCANNER-class, separate sourcetype. |
| **Promptfoo red-team** | Prompt/RAG eval + injection tests | Related | **INTEGRATE** later | Useful for “did the model obey?” specimens — **not** the INV-002 proof. |
| **PyRIT** (Microsoft) | AI red teaming | Related | **INTEGRATE** later | Orchestrates probes. Not a grant engine. |
| **LLM Guard / Protect AI** | Input/output scanners, secret detection | Related | **REFERENCE** | Sanitization claims must be real transforms if ever used. |
| **Rebuff / Vigil / Horde** | PI detection | Related | **REFERENCE** | Classifiers; FP-prone as detectors. |
| **Llama Guard / Granite Guardian** | Safety classifiers | Related | **REFERENCE** | Content policy, not tool grants. |
| **LangChain / LangGraph** | Orchestration + RAG adapters | Infra | **REFERENCE** | Optional later adapter around AgentSec controls. Not 10B kernel. |
| **Haystack / LlamaIndex** | RAG frameworks | Infra | **REFERENCE** | Same. |
| **Chroma / FAISS / Qdrant / pgvector** | Vector stores | Infra | **REFERENCE** | 10B proof = fixtures. Optional teaching overlay; pgvector conflicts with “no unnecessary DB.” |
| **hubness-detector / embedding anomaly** | PoisonedRAG-adjacent research | Corpus integrity | **REFERENCE** | Later analytics chapter, not 10B invariant. |
| **OWASP LLM Top 10 / Agentic Top 10** | Taxonomies | Yes | **REFERENCE** | Mapping only. |
| **MITRE ATLAS** | Adversarial ML techniques | Unverified RAG ids | **REFERENCE** | AML.T0070 official page **404** on 2026-09-16 → UNMAPPED / REQUIRES REVALIDATION. |
| **NIST AI 600-1** | GenAI risk profile | Related | **REFERENCE** | Indirect PI language. |
| **DefenseClaw** | Agent firewall | No | **NOT RELEVANT** | Prior chapter: not core. |
| **Invariant mcp-scan / pinning** | MCP catalog pin | No | **NOT RELEVANT** | Rug-pull track, not RAG. |

---

## BUILD vs INTEGRATE for Phase 10B

**BUILD (required for the lab):** fixture corpus, deterministic retriever, observation control, per-run overlay, composition with CTRL-MCP-001, hash/preview telemetry, tests.

**INTEGRATE (explicitly not 10B):** NeMo retrieval rails, Promptfoo, garak, inspect APIs, vector DBs.

**Do not BUILD:** a production PI classifier, a PoisonedRAG optimizer, a second authorization engine, full-document Splunk indexing.

---

## Preference

Prefer **not** to rebuild NeMo-style retrieval rails as a product. If a later overlay wants a chunk classifier, **call NeMo or Prompt Shields** and label output independent evidence — same SCANNER FINDING ≠ AUTHZ honesty.

The AgentSec-owned property remains: **even if the classifier misses, authorization must not widen.**
