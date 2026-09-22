# AgentSec curriculum information architecture (Home)

**Status:** DESIGN ONLY (Phase 15A). **Do not change nav, views, or Home XML from this file.**  
Preserve the current professional visual direction (`docs/AGENTSEC_UI_DESIGN_SYSTEM.md`, `docs/AGENTSEC_UI_INFORMATION_ARCHITECTURE.md`).

Studio remains a **syllabus**, not a web app. Do not create dozens of top-level menu items.

---

## Problem

Home is a **workshop directory** grouped as Attack Labs / Context Security / Agent Authority / Supply Chain. That matches shipping views, not a beginner→architect journey. Identity has **no view**. PI-001 and MCP-001 are the only 14E-complete loops, but they sit beside MCP-006 as if all Attack Labs were the same kind of lesson.

---

## Proposed academy model (future)

Keep **one Home**. Use a short **Start here** path, then **collections** (not 12 top-level items).

Suggested collections (five, matching current visual weight):

1. **Start here** — Level 0: what AgentSec is, platform roles, how to get a `run.id`, Splunk ≠ enforcement.  
2. **Trust & tools** — PI-001, MCP-001, then 003, 004 (Level 1–2). Badge LIVE where Attack Service exists.  
3. **Ecosystem & context** — MCP-005, catalog, scanner, RAG, memory (Level 3–5).  
4. **Authority & intent** — MCP-006, identity (coming), goal (Level 6–7).  
5. **Investigate & prove** — Search workbench, detection reasoning, future capstone.

Reference / framework mappings live as a **footer or Reference row**, not a sixth competing product area.

---

## Learner journey on Home (copy, not XML)

```text
START HERE
  → Trusting input (PI-001) LIVE
  → Tool authority (MCP-001) LIVE
  → Scope & resource (003, 004)   [REPLAY until Wave 1]
  → Data is not authority (005, catalog, RAG, memory)
  → Who may act, toward what goal (006, identity, goal)
  → Capstone (not built)
```

Each card should eventually show **mode** (LIVE / REPLAY / DESIGN) and **competency stage**, not phase numbers (Phase 6D, Phase 13E).

---

## PortSwigger-style principles (conceptual, not visual clone)

- Clear lesson and security property
- Small focused lab
- Explicit launch or honest REPLAY
- Observable result (`run.id`)
- Guided investigation in Search
- Solution when needed (Path B progression)
- Explanation and next concept

Do not turn Dashboard Studio into a marketing SPA. Do not copy another academy’s chrome.

---

## Framework mapping (learning aid, not runtime)

Classify existing mappings; do not invent MITRE IDs; do not drive PDP design from frameworks.

| Framework | Stance |
|-----------|--------|
| OWASP LLM Top 10 | RELATED / DIRECT where labs already cite (e.g. LLM01-class input, LLM06-class RAG) — **REQUIRES REVALIDATION** per lab page |
| OWASP Agentic Security Initiative | RELATED — AgentSec is a teaching range, not an ASI implementation |
| MITRE ATLAS | REQUIRES REVALIDATION — do not mint technique IDs in 15A |
| NIST AI RMF / AI 600-1 | RELATED at Govern/Map/Measure/Manage language; UNMAPPED as a lab-by-lab control catalog |

Unmapped is allowed. Forced mapping is not.

---

## External incidents (REFERENCE only)

| Material | Use |
|----------|-----|
| EchoLeak / indirect prompt injection research | REFERENCE on RAG — AgentSec did not reproduce the incident |
| PoisonedRAG | REFERENCE — retrieval poisoning pattern |
| Agent memory research | REFERENCE on LAB-MEMORY-001 |
| MCP ecosystem / catalog poisoning papers | REFERENCE on catalog + scanner |
| Confused-deputy classics | REFERENCE on MCP-006 |

Never treat a citation as proof AgentSec replayed the breach. Do not recreate dangerous real-world incidents for realism.

---

## What 15A must not change

`data.json` nav, `ws_agentsec_home.xml`, collection labels in production. Identity remains absent from nav until a workshop exists (Wave 4).
