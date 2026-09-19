# Agent memory security — predecessor analysis

**Status:** Phase 11A **DESIGN / RESEARCH ONLY**. No runtime. Schema **1.6.0 unchanged**.  
**Lab (planned):** LAB-MEMORY-001. Attack id **MEMORY-001**.  
**Primary invariant:** INV-003 (inspected, not invented).  
**Evidence class:** **DOCUMENTED** research. AgentSec current behavior cited below is **OBSERVED**.  
**Research date:** 2026-09-17.

This phase does **not** reopen catalog 8A–9E or RAG 10A–10E. Those chapters are complete for their designed paths.

---

## What this research is for

Can **persisted agent memory** influence a **later** agent run so that authority is acquired or exercised outside server-owned policy?

RAG already asked a related question for **retrieved documents in one run**. Memory asks it for **state that survives the run**. Same family of “text is not a grant.” Different trust boundary. Different evidence (cross-run write → recall).

---

## INV-003 — inspect, do not redefine

Repository definition (`.cursor/rules/20-security.mdc`, schema `invariant.id` enum):

> **INV-003 Memory Trust Isolation**  
> Untrusted memory cannot silently become trusted instruction.

Phase 11A **reuses this sentence**. The lab does not replace it with a new invariant.

**How the lab uses it:** recalled memory remains **data**. It must not be treated as a trusted instruction stream, a grant list, an identity, or an approval. If recalled text influences a follow-on **REQUEST**, INV-002 still applies: data cannot independently authorize privileged actions. CTRL-MCP-001 remains the grant.

Do not collapse INV-003 into INV-002. INV-002 is about retrieved/result/catalog **content**. INV-003 is about **persisted memory** becoming instruction without an explicit trust promotion. Both can be true on the same RECALL run.

---

## REUSE / REDESIGN / DROP / NOT APPLICABLE

Inspected: INV-001–008, LAB-RAG-001, MCP-005, catalog, schema 1.6.0, `MemorySink`, Splunk KO inventory, overlay pattern, DET-MCP-001, ROADMAP “memory poisoning” row.

| Asset | Decision | Why |
|-------|----------|-----|
| **INV-003** | **REUSE** | Exact property. Do not invent INV-009. |
| **INV-002** | **REUSE (composition)** | Recalled memory that forms a REQUEST still cannot mint a GRANT. |
| **INV-001 / INV-004 / INV-005** | **NOT APPLICABLE for first lab** | No new delegation, attribution, or impersonation proof. Identity fields for memory owner/tenant wait for the identity/A2A chapter. |
| **INV-007** | **REUSE (evidence duty)** | Write and recall must be reconstructable. |
| **INV-008** | **REUSE** | Missing memory context must not fail-open to ALLOW except the labeled lab overlay. |
| **CTRL-MCP-001** | **REUSE** | Only grant engine for the follow-on tool. |
| Per-run overlay (`*DerivedOverlay`) | **REUSE pattern** | One closed follow-on on the **RECALL** run. Label `vulnerable_profile_fail_open:memory_derived_authority`. Do not copy RAG overlay text. |
| `content.hash` + `content.preview` (≤200) | **REUSE fields (later bind)** | Exist unbound to memory records today. |
| A/B/C + same malicious bytes | **REUSE** | ATTACK and RETEST memory fingerprint must match. |
| Closed lab interpreter | **REUSE** | Not “did the LLM obey?” as the invariant. |
| Follow-on `lookup_customer_tier` | **REUSE** | Harmless handler. Same teaching tool as RAG / MCP-005. |
| Evidence packs, handler spies | **REUSE** | Non-execution proof remains handler count. |
| Q-MCP-AUTHZ / Q-MCP-EXECUTED / DET-MCP-001 | **REUSE later** | After field discovery. No SPL in 11A. |
| **CTRL-RAG-CONTEXT-001** | **DO NOT REUSE** | Wrong channel. Retrieved document ≠ persisted memory. |
| `agentsec.rag.context.*` | **DO NOT OVERLOAD** | Closed RAG enums. Overload would lie. |
| **CTRL-MCP-RESULT-001 / METADATA-001** | **DO NOT REUSE** | Tool result / catalog description ≠ memory record. |
| AcmeBank `/process` + Ollama | **DO NOT BOLT ON** | No memory store. Dedicated write/recall lab. |
| **`MemorySink`** (`src/agentsec/telemetry.py`) | **NOT APPLICABLE** | In-process **telemetry buffer**, not agent long-term memory. Do not teach it as INV-003. |
| LangChain / LangGraph / AutoGen / CrewAI memory | **NOT REQUIRED** | Optional later adapter. Security property must not depend on a framework. |
| Vector DB / embeddings | **DEFER** | First proof: deterministic fixture store. |
| Shared / multi-tenant / A2A memory | **OUT OF SCOPE** | Identity/A2A chapter. |
| RAG chapter 10A–10E | **KEEP CLOSED** | Do not reopen. |
| Catalog / scanner / rug-pull | **DO NOT CONTINUE** | Hard stop. |

---

## MEMORY VS RAG (must stay separate)

| | LAB-RAG-001 (done) | LAB-MEMORY-001 (planned) |
|--|--------------------|---------------------------|
| Untrusted object | Retrieved document / chunk | Persisted memory record |
| When it exists | Created outside this run (corpus) | Written in a **prior** run |
| Trust boundary | `rag.retrieved.context` | proposed `agent.memory.store` |
| Observation control | CTRL-RAG-CONTEXT-001 | proposed CTRL-MEMORY-CONTEXT-001 |
| Correlation | One `run.id` | Write `run.id` + recall `run.id` |
| Industry name overlap | ASI06 *context* / LLM01 indirect PI | ASI06 *memory* / ATLAS memory (unofficial ids) |
| Invariant | INV-002 | INV-003 (+ INV-002 on follow-on) |

A RAG retrieve in run N is **not** a memory write. A memory recall in run N+1 is **not** a retriever.

---

## Industry findings (sources dated)

### OWASP Agentic Top 10 2026 — ASI06

**VERIFIED** taxonomy (official PDF `genai.owasp.org`, reviewed 2026-09-17; Microsoft hve-core ASI06 skill mirrors the same definition).

ASI06: Memory & Context Poisoning — corrupt stored/retrieved context (conversation snapshots, memory tools, embeddings, RAG stores, shared memory) so **future** reasoning or tool use is biased.

AgentSec **splits** ASI06:

- RAG store **read** in one run → already taught as LAB-RAG-001 (INV-002).
- **Durable memory write then later recall** → this chapter (INV-003).

Do not map the whole of ASI06 onto one detector.

### OWASP LLM Top 10 2025

| Id | Relation |
|----|----------|
| LLM01 Prompt Injection (indirect) | **RELATED** — memory can be the persistence layer for an earlier injection |
| LLM04 Data and Model Poisoning | **RELATED** (training/fine-tune; not this lab) |
| LLM08 Vector/Embedding | **RELATED**, not first lab |

Fetched: genai.owasp.org / prior AgentSec RAG research 2026-09-16, reaffirmed 2026-09-17.

### NIST

**NIST.AI.600-1** (July 2024): direct vs **indirect prompt injection** (inject into data likely to be **retrieved**); **data poisoning** of training sets. Does **not** name “agent memory poisoning” as a distinct control family.

**Verdict:** **RELATED**. Map as retrieved/untrusted input that later becomes stored state — not a NIST technique ID.

### MITRE ATLAS

Official `https://atlas.mitre.org/techniques/AML.T0080` and `.../AML.T0080.000` returned **HTTP 404** on **2026-09-17**.

Third-party mirrors (GTK Cyber, Startup Defense “ATLAS 2026.07” reproduction, RiskAtlas) describe **AML.T0080 AI Agent Context Poisoning** with sub-technique **AML.T0080.000 Memory**.

**Verdict:** **UNMAPPED / REQUIRES REVALIDATION** against a live official ATLAS page. Do not ship AML.T0080.000 as a verified mapping.

### Academic / research (REFERENCE, not lab kernel)

| Source | Date | Finding | Class |
|--------|------|---------|-------|
| AgentPoison (arXiv 2407.12784) | 2024 | Poison memory *or* KB of LLM agents | **RELATED** |
| A-MemGuard (arXiv 2510.02373, ICML 2026; GitHub TangciuYueng/AMemGuard) | 2025–2026 | Defense: consensus + dual “lesson” memory | **RELATED** / later INTEGRATE research |
| MPBench / “From Untrusted Input to Trusted Memory” (arXiv 2606.04329) | 2026 | Write channels; prompt-injection defenses miss memory poisoning | **RELATED** |
| OWASP GenAI blog “Memory Is a Feature. It Is Also an Attack Surface” | 2026-05-13 | Persistence is the ASI06 cut | **RELATED** |

### Vendor / framework (do not implement)

| Source | Finding | Class |
|--------|---------|-------|
| Microsoft MSRC indirect PI (2025-07) | Permissions, not classifiers, are the grant | **REFERENCE** (same AgentSec lesson) |
| LangGraph checkpointing | Workflow **state snapshots**, not semantic long-term memory | **RELATED** — do not equate with INV-003 store |
| LangChain memory / ChatMessageHistory | Conversation buffers | **RELATED** |
| OpenAI / Claude “memory” product features | User-scoped persistent notes | **RELATED** product analog; not a protocol |
| AutoGen / CrewAI | Shared or agent-scoped state varies by version | **UNMAPPED** without pinning a version in 11B |

### Microsoft / Google / Cisco

No 11A integration. Cisco AI Defense inspect remains **input/output** evidence, not a memory grant. Google Secure AI Framework language on data poisoning is **RELATED** at profile level, not a lab control.

---

## Distinctions AgentSec must keep

| Problem | Untrusted object | Boundary | Lab |
|---------|------------------|----------|-----|
| Direct PI | User message | CTRL-INPUT-001 | LAB-PI-001 |
| Tool result as grant | Handler output | CTRL-MCP-RESULT-001 | LAB-MCP-005 |
| Catalog description | Tool metadata | CTRL-MCP-METADATA-001 | LAB-MCP-CATALOG |
| Retrieved document | Knowledge bytes | CTRL-RAG-CONTEXT-001 | LAB-RAG-001 |
| **Persisted memory as instruction** | Memory record | **CTRL-MEMORY-CONTEXT-001 (planned)** | **LAB-MEMORY-001 (planned)** |
| Cross-agent / A2A memory | Peer agent state | INV-005 / ASI07 | **Not 11A** |

---

## Hard stop

Do not start Phase 11B from this file. No runtime. No schema 1.7.0. No SPL. No DET-MEMORY. No Studio. No A2A. No rug-pull. No embeddings.
