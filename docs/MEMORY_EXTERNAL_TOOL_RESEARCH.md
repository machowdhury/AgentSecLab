# Agent memory — external tool research

**Status:** Phase 11A DESIGN / RESEARCH. **No integration.**  
**Research date:** 2026-09-17.  
**Evidence class:** **DOCUMENTED**.

Parents: `docs/MEMORY_PREDECESSOR_ANALYSIS.md`, `docs/AGENTSEC_BUILD_VS_INTEGRATE.md`, `docs/RAG_EXTERNAL_TOOL_RESEARCH.md`.

The unique AgentSec slice is: **persisted bytes must not become authority**, with **cross-run** write/recall evidence. Most memory-security tools classify or filter **text** at write/read. Complementary, not a replacement for CTRL-MCP-001.

---

## Classification key

| Label | Meaning |
|-------|---------|
| ATTACK GENERATION | Produces payloads / probes |
| EVALUATION | Scores whether a model/agent obeyed |
| CONTENT ANALYSIS | Classifies memory text |
| MEMORY SECURITY | Write/read guards, integrity, policy on the store |
| RUNTIME EVIDENCE | Independent findings to import |
| HUNT ASSIST | Prioritize investigation |
| NOT RELEVANT | Wrong problem for 11A |

---

## Tools and projects

| Project | Class | 11A decision |
|---------|-------|----------------|
| **AgentSec fixture store + CTRL-MEMORY-CONTEXT-001 + CTRL-MCP-001** | MEMORY SECURITY + RUNTIME EVIDENCE | **BUILD** |
| **Cross-run Splunk reconstruction** | HUNT ASSIST (later) | **BUILD** (after telemetry) |
| **OWASP Agent Memory Guard** (owasp.org / GitHub OWASP incubator, Apache-2.0) | MEMORY SECURITY | **INTEGRATE later** — middleware, not grant engine. Policy `block` ≠ AgentSec DENY unless tested as a pre-op caller. |
| **A-MemGuard** (arXiv 2510.02373, ICML 2026) | MEMORY SECURITY / EVALUATION | **REFERENCE** / research overlay |
| **AgentPoison** | ATTACK GENERATION | **REFERENCE** — do not import optimizer |
| **MPBench** (arXiv 2606.04329) | EVALUATION | **REFERENCE** |
| **garak** | ATTACK GENERATION / EVALUATION | **INTEGRATE later** — model probes, not authz |
| **Promptfoo** | EVALUATION | **INTEGRATE later** |
| **PyRIT** | ATTACK GENERATION | **INTEGRATE later** |
| **NeMo Guardrails** | CONTENT ANALYSIS | **REFERENCE** — rails ≠ GRANT |
| **Cisco AI Defense inspect** | CONTENT ANALYSIS / RUNTIME EVIDENCE | **REFERENCE** — FAIL ≠ DENY |
| **Foundation-Sec / Foundation8** | HUNT ASSIST | **REFERENCE** — not authorization |
| **Cisco mcp-scanner** | NOT RELEVANT | Catalog chapter closed |
| **Snyk Agent Scan** | NOT RELEVANT | Not started; not memory |
| **LangGraph / LangChain / AutoGen / CrewAI** | NOT RELEVANT as kernel | Optional adapter later |
| **Chroma / FAISS / Qdrant** | NOT RELEVANT | No vector DB in first lab |

---

## BUILD vs INTEGRATE

**BUILD (required for the eventual lab):** deterministic memory fixture, write/recall evidence, cross-run correlation keys, trust-boundary teaching, overlay, composition with CTRL-MCP-001, hash/preview, tests, later Splunk questions, later workshop.

**INTEGRATE later:** OWASP Agent Memory Guard or similar as **independent** write/read findings; garak/Promptfoo/PyRIT for “did the model store/obey?”; inspect APIs.

**Do not BUILD:** a production memory classifier, a second authorization engine, full-memory Splunk indexing, multi-tenant isolation product, ML granter.

Prefer **not** to rebuild OWASP Agent Memory Guard inside AgentSec. If a later overlay wants write-time screening, **call it** and label output independent evidence — SCANNER/GUARD FINDING ≠ AUTHZ.
