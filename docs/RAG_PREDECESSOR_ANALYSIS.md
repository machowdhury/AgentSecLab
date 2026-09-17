# RAG / retrieved-context predecessor analysis

**Status:** Phase 10A **DESIGN / RESEARCH ONLY**. No runtime. Schema **1.5.0 unchanged**.  
**Lab (planned):** LAB-RAG-001. Attack id **RAG-001**.  
**Primary invariant:** INV-002.  
**Evidence class:** **DOCUMENTED** research. AgentSec current behavior cited below is **OBSERVED**.  
**Research date:** 2026-09-16.

This phase does **not** extend MCP catalog poisoning. Catalog 8A–9E is complete for its designed path.

---

## What this research is for

Can content retrieved from an external knowledge source cause an agent to acquire or exercise authority that server-owned policy did not grant?

MCP-005 already asked that question for **tool results**. Catalog asked it for **tool metadata**. RAG asks it for **retrieved documents**. Same invariant, different trust boundary.

---

## REUSE / REFACTOR / REDESIGN / DROP

Inspected: `docs/IMPLEMENTATION_STATUS.md`, `docs/AGENTSEC_ROADMAP_2026.md`, INV-001–008, MCP-005 result-trust, MCP-CATALOG metadata-trust, schema 1.5.0, Splunk KO inventory, AcmeBank `/process` loan flow, Ollama path, evidence bundles, vulnerable/defended overlay machinery.

| Asset | Decision | Why |
|-------|----------|-----|
| INV-002 | **REUSE** | Exact property: retrieved content cannot independently authorize privileged actions. No new invariant. |
| CTRL-MCP-001 | **REUSE** | Downstream grant for any MCP follow-on. Do not invent a second authorization engine. |
| Per-run overlay pattern (`ResultDerivedOverlay`, `MetadataDerivedOverlay`) | **REUSE pattern** | One closed follow-on, no global `allowed_tools` mutation, labeled `vulnerable_profile_fail_open:*`. 10B would add a third overlay type, not copy MCP-005 text. |
| `agentsec.content.hash` + `content.preview` (≤200) | **REUSE fields** | Hash/preview already exist. They are **unbound** to RAG documents today. |
| A/B/C BASELINE/ATTACK/RETEST + defended/vulnerable | **REUSE** | ATTACK and RETEST must share the same malicious bytes. |
| Closed lab interpreter (not LLM as invariant) | **REUSE** | Catalog and MCP-005 already refuse to make “did the model obey?” the proof. |
| Follow-on `lookup_customer_tier` (registered, not granted) | **REUSE** | Harmless handler. Same teaching tool as MCP-005 / catalog. |
| Evidence packs, `run.id`, `sequence`, handler spies | **REUSE** | Reconstruction and non-execution proof. |
| Q-MCP-AUTHZ / Q-MCP-EXECUTED / DET-MCP-001 | **REUSE later** | After 10C field discovery. Not this phase. No SPL now. |
| CTRL-MCP-RESULT-001 | **DO NOT REUSE for RAG** | Wrong channel. Tool-result trust ≠ retrieved-document trust. |
| CTRL-MCP-METADATA-001 | **DO NOT REUSE for RAG** | Wrong channel. Catalog `description` ≠ knowledge-base document. |
| `agentsec.mcp.result.trust` / `mcp.metadata.trust` | **DO NOT OVERLOAD** | Closed enums bound to other events. Overload would lie. |
| AcmeBank loan `/process` + Ollama | **DO NOT BOLT ON** | Loan path has no retriever. RAG lab should be a dedicated retrieve-then-request flow, like `mcp_tool_lab` was dedicated. |
| AgentWatch `rag_store.py` Galileo regex | **DROP / REDESIGN** | `docs/MIGRATION_INVENTORY.md`: SIMULATED probe counter, never blocks, no vector store, INV-002 absent. Do not teach “Galileo blocked exfil.” |
| LangChain / LangGraph as the lab runtime | **NOT REQUIRED** | Educational later overlay. Security property must not depend on a framework. |
| Stochastic embeddings as the first proof | **DEFER** | First proof must be deterministic fixture retrieval. |
| Durable agent memory (INV-003) | **OUT OF SCOPE** | ASI06 includes memory; Phase 10A is retrieved context, not a persistent memory store. |
| Catalog poisoning / scanners / rug-pull / A2A | **DO NOT CONTINUE** | Hard stop. |

---

## Industry findings (sources dated where practical)

### Indirect prompt injection vs RAG poisoning

**Indirect prompt injection:** attacker-controlled text is retrieved or otherwise ingested and then placed into the model context. The victim user did not type the instruction. NIST AI 600-1 (July 2024, `NIST.AI.600-1`) describes indirect prompt injection as occurring when adversaries inject prompts into data likely to be retrieved, without a direct interface. Microsoft MSRC (2025-07) calls it one of the most widely reported AI-security techniques and maps it to OWASP LLM01:2025.

**RAG poisoning:** the knowledge corpus / index itself is contaminated so that *future* queries retrieve attacker-chosen chunks. PoisonedRAG (Zou et al., arXiv 2402.07867, USENIX Security 2025) showed a few injected texts can steer answers for target questions. This is a **corpus integrity** problem. It is related to, but not identical to, a single-run “this retrieved chunk contains an instruction” lab.

Phase 10A’s first lab is the **instruction-in-retrieved-document → follow-on request** cut (indirect PI / context injection). Corpus-scale retrieval optimization (PoisonedRAG white-box embeddings) is **later**, and must not be required for the INV-002 proof.

### OWASP LLM Top 10 2025

| Id | Title | Relation |
|----|-------|----------|
| **LLM01:2025 Prompt Injection** | Direct and indirect; OWASP example includes a modified document in a RAG repository | **DIRECT** |
| **LLM08:2025 Vector and Embedding Weaknesses** | Embedding/vector-store integrity | **RELATED**, not the first lab (no embeddings in 10B proof) |
| **LLM04:2025 Data and Model Poisoning** | Training / fine-tune / embedding-data poison | **RELATED** (different lifecycle than runtime retrieval) |

Fetched: OWASP GenAI LLM01 page and Top 10 for LLM Applications 2025 PDF (genai.owasp.org / owasp.org), reviewed 2026-09-16.

### OWASP Agentic Top 10 2026

| Id | Title | Relation |
|----|-------|----------|
| **ASI06: Memory & Context Poisoning** | Corrupt stored/retrieved context (RAG stores, memory, summaries) so future reasoning/tool use is biased | **RELATED** |
| **ASI01 Goal Hijack** | Direct goal manipulation | **RELATED** if retrieved text hijacks goals; first lab still INV-002 authority, not goal engine |
| **ASI02 Tool Misuse** | Tools used beyond intent | **RELATED** if follow-on executes |

Official PDF: OWASP Top 10 For Agentic Applications 2026 (`genai.owasp.org`, downloaded 2026-09-16). ASI06 explicitly lists RAG/embeddings poisoning and cites PoisonedRAG and AgentPoison. Phase 10A **does not implement memory poisoning**. The first lab is **single-run retrieved context**, which is the RAG-store *read* path, not INV-003 durable memory.

### MITRE ATLAS

Official `https://atlas.mitre.org/techniques/AML.T0070` returned **HTTP 404** on 2026-09-16. ATLAS homepage (`atlas.mitre.org`) is live (197 techniques claimed). Third-party mirrors (GTK Cyber, Zenity 2025 collaboration notes) describe **AML.T0070 RAG Poisoning** and **AML.T0064 Gather RAG-Indexed Targets**.

**Verdict:** ATLAS RAG technique IDs are **UNMAPPED / REQUIRES REVALIDATION** against a live official ATLAS technique page. Do not ship AML.T0070 as a verified mapping.

**AML.T0020 Poison Training Data** appears in MITRE SAFE-AI PDF on atlas.mitre.org. That is **training-data** poisoning. **Do not force** T0020 onto retrieved-context runtime.

### NIST

NIST AI RMF Generative AI Profile (`NIST.AI.600-1`, 2024) documents direct vs indirect prompt injection and retrieved-data influence. **RELATED** (risk profile, not a lab control).

### Vendor / incident literature (teaching, not integration)

| Source | Date | Finding | Use |
|--------|------|---------|-----|
| Microsoft MSRC “How Microsoft defends against indirect prompt injection” | 2025-07 | Defense-in-depth: probabilistic Prompt Shields + deterministic permissions/labels | **REFERENCE**. Deterministic authorization is the AgentSec lesson. |
| EchoLeak (CVE-2025-32711) / Aim Labs | 2025 | Zero-click Copilot indirect PI via retrieved email content | **REFERENCE**. Out of lab scope (no real M365, no exfil). |
| ConfusedPilot (arXiv 2408.04870) | 2024 | RAG integrity/confidentiality issues in Copilot-class systems | **REFERENCE** |
| Greshake et al. indirect PI (established class) | 2023+ | Indirect PI via retrieved web/docs | **RELATED** class |
| AgentPoison (arXiv 2407.12784) | 2024 | Poisoning memory *or* knowledge bases of LLM agents | **RELATED**; memory path deferred |
| NVIDIA NeMo Guardrails | docs 2025–2026 | **Retrieval rails** inspect/transform retrieved chunks before prompt merge | **REFERENCE** for later; not 10B runtime |
| Cisco AI Defense + NeMo | Cisco blog / NeMo docs | Inspect API on **input/output** rails; not documented as the RAG chunk rail | **REFERENCE**. Do not integrate. Inspect FAIL ≠ AgentSec DENY. |

### Academic / OSS attacks we will **not** recreate as the first lab

- PoisonedRAG optimization against million-document corpora
- Embedding-space backdoors
- Real credential theft / shell / filesystem
- Cross-tenant vector bleed (ASI06 example) — later, needs multi-tenant store

---

## Distinctions AgentSec must keep

| Problem | What is untrusted | Trust boundary | Existing lab |
|---------|-------------------|----------------|--------------|
| Direct PI | User message | `acmebank.http_api` / CTRL-INPUT-001 | LAB-PI-001 |
| Tool result as grant | Handler output | `mcp.tool.result` / CTRL-MCP-RESULT-001 | LAB-MCP-005 |
| Tool metadata as grant | Catalog `description` | `mcp.catalog.metadata` / CTRL-MCP-METADATA-001 | LAB-MCP-CATALOG |
| **Retrieved document as grant** | Knowledge-base bytes | **proposed** `rag.retrieved.context` | **LAB-RAG-001 (planned)** |
| Durable memory as instruction | Stored memory record | INV-003 | **Not 10A** |

**TOOL RESULT IS DATA** (MCP-005).  
**RETRIEVED CONTEXT IS DATA** (Phase 10).  
Related INV-002 properties. Different channels. Do not overload RESULT-001 or METADATA-001.

---

## What AgentSec must not copy from predecessors

- Regex “RAG exfil probe” as a control (AgentWatch).
- Treating a configured knowledge base as trusted instructions.
- Making LLM obedience the security invariant.
- Scanner/guardrail FAIL as runtime DENY.
- Full-document logging as evidence.

---

## Open research items (not blockers for 10A design)

1. Official ATLAS technique page for RAG poisoning (404 today).
2. Whether 10C Splunk should add a dedicated hunt or bind Q-MCP only after field discovery.
3. Whether a later embeddings overlay is worth a separate lab id.

**Do not start Phase 10B from this file.** No Agent Scan. No rug-pull. No A2A. No memory poisoning.
