# AgentSec next-build gap matrix (Phase 16C)

**Status:** DESIGN backlog. **Do not implement from this file.**  
**Do not start Phase 16D from this file.**

Priority: **P0** blocks coherent learning. **P1** major learning improvement. **P2** useful. **P3** future research.

Runtime/schema/Splunk/UI columns answer whether a later phase would need those surfaces — not authorization to change them now.

| Priority | Gap | Learner impact | Security value | Current evidence | Required work | Runtime? | Schema? | Splunk? | UI? | Effort | Recommended phase |
|----------|-----|----------------|----------------|------------------|---------------|----------|---------|---------|-----|--------|-------------------|
| P0 | Home copy is false (identity “not published”; capstone omitted) | Learners miss two LIVE labs + graduation exercise | High (truth in syllabus) | OBSERVED `ws_agentsec_home.xml` | Rewrite Home groups; LIVE/REPLAY labels; Start here | No | No | View XML | Yes | S | 16D polish if requested |
| P0 | Nav places capstone before Goal/Identity | Graduation appears mid-path | High (pedagogy) | OBSERVED `default.xml` | Reorder collections | No | No | Nav XML | Yes | S | 16D |
| P1 | No Level 0 orientation (LLM/agent/MCP/RAG/memory/PDP/Splunk role) | Beginner cannot start honestly | Medium | Home is lifecycle list only | Design+build orientation on Home | No | No | View | Yes | M | 16D |
| P1 | No LIVE vs REPLAY badges on Home/nav | REPLAY labs look equivalent to LIVE | High (honesty) | OBSERVED | Labels + Attack Service links only on LIVE | No | No | Nav/Home | Yes | S | 16D |
| P1 | Path B visible without disclosure on LIVE INVESTIGATE | Path A skipped | Medium | OBSERVED Studio markdown | Pedagogical disclosure; still not an authz gate | No | No | Studio | Yes | M | 16D |
| P1 | REPLAY labs lack `investigations.json` Path A | Cannot “try first” on 003–scanner | Medium | OBSERVED | Add Path A/B metadata or honest HUNT banner | No | No | Optional Studio | Yes | M | 16D |
| P1 | Assessment not in product | No graduate check | Medium | DESIGN `AGENTSEC_ASSESSMENT_MODEL.md` | Per-lab PROVE prompts only; no leaderboard | No | No | Optional | Optional | M | 16D or later |
| P2 | MCP-003/004 Attack Service LIVE | Grant anatomy stays REPLAY | Medium | 15A/16A already said REPLAY is enough | 14E-style ExperimentContext | Yes | No | Handoff | Yes | L | Later wave; not required for academy coherence |
| P2 | Manifest `level` fields inconsistent | Docs/IA confusion | Low | OBSERVED JSON | Align metadata with curriculum map | No | No | No | No | S | 16D |
| P2 | Memory Q-MEMORY needs two `run.id`s | Easy Path A miss | Medium | DOCUMENTED 15C/16B | Stronger starter_guidance already present; Attack Service handoff ORs ids | No | No | No | Low | S | optional 16D copy |
| P2 | Capstone retrieve→write is hash-only | Correlation honesty | Medium | DOCUMENTED 16B | Keep honest; no schema bump | No | **No** (do not bump) | No | No | — | not a phase |
| P3 | Real A2A / OAuth / SPIFFE | Not a beginner academy blocker | High if ever built | NOT IMPLEMENTED | Separate research | Yes | Likely | Yes | Yes | XL | research track |
| P3 | HITL | Not required to explain current labs | Medium | Enum only | Do not fake a checkbox | Yes | Maybe | Yes | Yes | L | future |
| P3 | MLTK / behavioral | After deterministic fluency | Low now | DETECT FUTURE panels | ML must not be PDP | No | No | Yes | Yes | L | future |
| P3 | Catalog rug-pull / `list_changed` | Supply-chain depth | Medium | Research | Not academy P0 | Yes | Maybe | Yes | Yes | L | research |
| P3 | DET-MCP-CATALOG candidate | 8D justified later | Low | DOCUMENTED candidate | Evidence-driven only | No | No | Yes | Yes | M | future detection |
| P3 | Progress persistence | Nice-to-have | Low | NOT IMPLEMENTED | Do not fake LEARNED from tab open | Maybe | No | No | Yes | M | future |
| P3 | Tool-output poisoning LIVE | MCP-005 is REPLAY | Medium | PARTIALLY TAUGHT | Optional later LIVE | Yes | No | Handoff | Yes | L | future |

### Explicit non-goals

Do not add: another security domain lab, DET-CAPSTONE, schema 1.10.0, `/a2a`, vector DB, LangChain, Kubernetes, leaderboards, or “more dashboards.”

---

## 16C determination

**OPTION B** — academy packaging P0/P1 should be the next *named* implementation **only after an explicit request**. Until then, STOP.

Constraint from Option C: **do not expand domains** until Home/nav/orientation tell the truth about what already exists.
