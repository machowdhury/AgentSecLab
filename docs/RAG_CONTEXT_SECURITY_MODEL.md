# RAG context security model

**Status:** Phase 10A **DESIGN**. Runtime **ABSENT**. Schema **1.5.0 unchanged**.  
**Primary invariant:** INV-002.  
**Evidence class:** **DOCUMENTED**.

Parents: `docs/RAG_PREDECESSOR_ANALYSIS.md`, `docs/MCP005_RESULT_TRUST_MODEL.md`, `docs/MCP_CATALOG_POISONING_SECURITY_MODEL.md`.

---

## WHAT IS IT?

**Retrieved-context security** asks whether bytes pulled from a knowledge source — a document, chunk, web page, or policy article — may change what the agent is allowed to do.

The retrieval can be **valid**. The document can be **the right document for the query**. Validity of retrieval is not permission.

## WHY DOES IT EXIST?

RAG exists so models can answer from data they were not trained on. That data is **attacker-reachable** whenever the corpus, crawler, upload path, or connector is. Industry names this **indirect prompt injection** (OWASP LLM01:2025) and, when the corpus is contaminated, **RAG poisoning**.

Authorization is still a server-owned grant. A knowledge base is a **source of data**, not a source of authority.

## HOW DOES IT WORK? (planned)

```
User question
      |
      v
Retriever  (deterministic fixture in 10B)
      |
      v
Retrieved document  (DATA)
      |
      v
Context observation  (CTRL-RAG-CONTEXT-001)
      |
      v
Agent reasoning / closed lab interpreter
      |
      v
Follow-on REQUEST
      |
      v
CTRL-MCP-001  (server-owned authorization)
      |
   +--+--+
   |     |
 ALLOW  DENY
   |     |
 execute X
```

**REQUEST ≠ GRANT.** Retrieved text may influence whether a request is formed. It cannot mint `allowed_tools`, scopes, resources, identity, delegation, approvals, profile, or control configuration.

## WHERE DOES IT SIT IN AGENTSEC?

After MCP catalog / scanner (8A–9E). Parallel to MCP-005, not a child of catalog poisoning.

| Lab | Untrusted object | Observation control | Authz control |
|-----|------------------|---------------------|---------------|
| LAB-MCP-005 | Tool result body | CTRL-MCP-RESULT-001 | CTRL-MCP-001 |
| LAB-MCP-CATALOG | Catalog `description` | CTRL-MCP-METADATA-001 | CTRL-MCP-001 |
| **LAB-RAG-001** | Retrieved document | **CTRL-RAG-CONTEXT-001** | **CTRL-MCP-001** |

AcmeBank loan `/process` is **not** the 10B vehicle. It has no retriever. The planned vehicle is a dedicated retrieve-then-request lab with the same harmless `lookup_customer_tier` follow-on used by MCP-005.

## WHAT IS THE TRUST BOUNDARY?

Proposed: `rag.retrieved.context`.

Three distinct facts:

| Fact | Example | Does it grant tools? |
|------|---------|----------------------|
| **Source provenance** | `rag.local.fixture` | No |
| **Content trust** | `untrusted_data` | No |
| **Authorization** | CTRL-MCP-001 / coded `allowed_tools` | Yes — server-owned |

Configured retriever ≠ trusted instructions. Do **not** invent `trusted_document=true` because the document came from the configured store.

## WHAT COULD AN ATTACKER CONTROL?

In the lab: the **document body** in a fixture corpus (operator-selected NORMAL vs MALICIOUS).

Not: security profile, global grants, `run.id`, `control.decision`, caller identity, catalog, schema.

## WHAT CAN GO WRONG?

| Failure | AgentSec stance |
|---------|-----------------|
| Retrieved instruction treated as policy | Vulnerable overlay only; defended never |
| LLM “obeys” the note | Not the invariant |
| Observation labeled ALLOW | Forbidden (`retrieved_context_is_data` is OBSERVE) |
| Fake SANITIZE / QUARANTINE | Forbidden unless bytes are actually transformed / consumption blocked |
| Global grant mutation | Forbidden |
| Full document in Splunk | Forbidden (privacy) |

## WHAT TELEMETRY SHOULD EXIST?

See `docs/RAG_EVENT_MODEL_REVIEW.md`. Schema 1.5.0 **cannot** honestly emit a RAG observation (closed enums). **SCHEMA BUMP JUSTIFIED** for 10B. Not implemented in 10A.

Reuse: `run.id`, `sequence`, `agent.id`, `content.hash`, `content.preview`.

Do not reuse: `mcp.result.trust`, `mcp.metadata.trust`.

## HOW WILL SPLUNK SHOW IT?

Design questions only: `docs/RAG_DETECTION_MODEL.md`. No SPL in 10A.

## WHAT CONTROL COULD CHANGE THE RESULT?

Defended: no overlay. Same malicious document → same REQUEST → CTRL-MCP-001 **DENY** `tool_not_granted`. Handler count 0.

Vulnerable: per-run overlay only. Same REQUEST → **ALLOW**. Handler count 1. Global grants unchanged.

CTRL-RAG-CONTEXT-001 remains **OBSERVE** `retrieved_context_is_data` for valid documents in BASELINE, ATTACK, and RETEST. The retrieved document is never authorized. Overlay ALLOW is **CTRL-MCP-001** only.

## WHAT TEST PROVES THE LOGIC? (planned for 10B)

Same SHA-256 of the malicious document in ATTACK and RETEST. ATTACK handler 1. RETEST handler 0. Global `allowed_tools` still `{lookup_policy}` (or the RAG lab’s granted set — never includes `lookup_customer_tier`).

LLM compliance is **not** that test.

---

## Security property (locked)

**Can content retrieved from an external knowledge source cause an agent to acquire or exercise authority that was not granted by server-owned policy?**

Defended expectation: **NO.**

Retrieved content may influence reasoning or generate a request. It cannot independently modify:

- allowed tools
- allowed scopes
- allowed resources
- caller identity
- principal identity
- delegation
- approvals
- authorization policy
- security profile
- control configuration

---

## Observation control (justified — not implemented)

**CTRL-RAG-CONTEXT-001** is justified. Existing RESULT-001 / METADATA-001 would mis-label the channel.

| Profile | Decision | Reason |
|---------|----------|--------|
| Defended / Vulnerable (valid document) | **OBSERVE** | `retrieved_context_is_data` |
| Unknown / malformed / retrieval failure | **ERROR** | `unknown_document` / `malformed_retrieval_object` / `retrieval_failure` |

Do **not** emit `ALLOW` on CTRL-RAG-CONTEXT-001. 10A's ATTACK table that listed observation ALLOW is **superseded**: vulnerable behavior is the per-run overlay on CTRL-MCP-001 (`vulnerable_profile_fail_open:retrieved_context_derived_authority`).  
Do **not** use `ALLOW` + `retrieved_context_is_data`.  
Do **not** claim SANITIZE unless content is transformed.  
Do **not** claim QUARANTINE unless consumption is prevented.

Observation does not replace CTRL-MCP-001.

---

## Overlay vocabulary

Catalog used `metadata_derived_authority`. MCP-005 used `result_derived_grant`. RAG should use:

`vulnerable_profile_fail_open:retrieved_context_derived_authority`

**Authority** is the better word: the document does not issue a coded grant object; the vulnerable profile incorrectly treats retrieved text as if it widened authority. Explicit **LAB** fail-open. Not a production control.

---

## Retrieval model (planned 10B)

Smallest honest system: **JSON/Markdown fixture corpus + deterministic retriever** (exact document id or exact query key). No stochastic nearest-neighbor for the security proof.

Embeddings / FAISS / Chroma / Qdrant: **optional later teaching overlay**. See lab specification.

LangChain/LangGraph: **document where they would fit later**. Not required for INV-002.

---

## Invariant mapping

| Invariant | Role |
|-----------|------|
| INV-001 | Follow-on still cannot exceed the (possibly overlaid) grant |
| **INV-002** | **Primary.** Retrieved context is data. |
| INV-003 | Out of scope (durable memory) |
| INV-004 | Follow-on must remain attributable |
| INV-007 | Retrieval + observation + authz + execute reconstructable |
| INV-008 | Missing retrieval context must not fail-open to ALLOW except the labeled vulnerable overlay |

---

## Security review (design)

Any unresolved authority-widening issue is BLOCKER/HIGH.

| Issue | Verdict | Notes |
|-------|---------|-------|
| Client-supplied trust (`trusted_document=true`) | **PASS** | Forbidden. Trust is server classification `untrusted_data`. |
| Retrieval-derived grants | **PASS (defended)** / **LAB-ONLY (vulnerable)** | Vulnerable uses per-run overlay only, labeled fail-open. No global mutation. |
| Prompt-derived grants | **PASS** | User question does not mint tools. Direct PI remains LAB-PI-001. |
| Global policy mutation | **PASS** | Designed out. Overlay is per-run. |
| Fake SANITIZE semantics | **PASS** | Not claimed. Observation is OBSERVE, not transform. |
| Fake trusted-document labels | **PASS** | Not in the model. Provenance ≠ trust. |
| Full document logging | **PASS (design)** | Hash + preview ≤200. Production redaction documented. |
| Unknown source behavior | **PASS** | Planned ERROR; no fail-open grant. |
| Malformed retrieval object | **PASS** | Planned ERROR; no overlay. |
| Hash mismatch | **PASS** | ATTACK/RETEST must match; 10B tests. |
| Retrieval failure | **PASS** | No follow-on, no grant. |
| Authorization failure | **PASS** | DENY, handler 0, no execution start. |
| Execution failure | **N/A / later** | If handler starts then errors: `mcp.failed` ≠ prevention. Same honesty as MCP labs. |
| LLM nondeterminism | **PASS** | Not the invariant. Closed interpreter for REQUEST. |
| Cross-run state leakage | **PASS (design)** | Overlay must be per-run; 10B must not persist grants. |

No BLOCKER/HIGH open on the **design**. Runtime absence is expected (10B NOT STARTED).

---

## Framework mapping (evidence-based)

| Framework | Id | Relation | Evidence |
|-----------|-----|----------|----------|
| OWASP LLM Top 10 2025 | LLM01:2025 Prompt Injection (indirect) | **DIRECT** | Official LLM01 page; RAG-repository document example |
| OWASP LLM Top 10 2025 | LLM08 Vector/Embedding Weaknesses | **RELATED** | Not the first lab (no embeddings in the proof) |
| OWASP LLM Top 10 2025 | LLM04 Data and Model Poisoning | **RELATED** | Training/embedding-data lifecycle ≠ runtime retrieve |
| OWASP Agentic 2026 | ASI06 Memory & Context Poisoning | **RELATED** | Official PDF lists RAG stores; this lab is single-run retrieve, not INV-003 memory |
| OWASP Agentic 2026 | ASI02 Tool Misuse | **RELATED** | Only if follow-on executes |
| MITRE ATLAS | AML.T0070 RAG Poisoning | **UNMAPPED / REQUIRES REVALIDATION** | atlas.mitre.org technique URL HTTP 404 on 2026-09-16 |
| MITRE ATLAS | AML.T0020 Poison Training Data | **UNMAPPED** (do not force) | Training-data technique, not retrieved-context runtime |
| NIST AI 600-1 | Indirect prompt injection | **RELATED** | Risk profile language, July 2024 |
| Cisco AI Defense | Inspect/taxonomy | **RELATED** | Complementary classifier; not this control |
| Microsoft MSRC 2025-07 | Indirect PI + permissions | **RELATED** | Defense-in-depth narrative matches REQUEST ≠ GRANT | |
