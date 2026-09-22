# Phase 16D P0/P1 implementation matrix

**Authority:** `docs/AGENTSEC_NEXT_BUILD_GAP_MATRIX.md` and `docs/PHASE16C_AGENTSEC_ACADEMY_AUDIT.md` (16C findings).  
**This file records 16D decisions.** It does not rewrite 16C.

Schema target: **1.9.0 UNCHANGED**. Learning metadata is not policy.

Priority: only **P0** and **P1** were implementation candidates. **P2/P3 remain backlog.**

| Gap ID | Priority | 16C finding | Learner impact | Required change | Files/components | Runtime? | Splunk? | Studio? | Attack Service? | Docs? | Test requirement | Implementation decision |
|--------|----------|-------------|----------------|-----------------|------------------|----------|---------|---------|-----------------|-------|------------------|-------------------------|
| GAP-16C-P0-HOME | P0 | Home copy is false (identity “not published”; capstone omitted) | Learners miss two LIVE labs + graduation | Rewrite Home as academy landing; LIVE/REPLAY labels; Start here | `scripts/build_agentsec_home_dashboard.py`, `learning/home/dashboard.definition.json`, `ws_agentsec_home.xml` | No | View XML | Yes | No | Yes | Home has identity + capstone; no “not published” | **DONE** — START/ORIENT/PATH/SPLUNK tabs |
| GAP-16C-P0-NAV | P0 | Nav places capstone before Goal/Identity | Graduation appears mid-path | Reorder collections to curriculum order | `splunk_app/.../nav/default.xml`, `learning/academy/curriculum.json` | No | Nav XML | Indirect | No | Yes | Foundations → Context Security → Agent Intent → Capstone; capstone after Goal/Identity | **DONE** |
| GAP-16C-P1-L0 | P1 | No Level 0 orientation | Beginner cannot start honestly | Orientation on Home (LLM/agent/MCP/RAG/memory/PDP/Splunk role) | Home builder ORIENT + START | No | View | Yes | Link to Home | Yes | Glossary + inequalities + four roles | **DONE** — not a new workshop |
| GAP-16C-P1-LIVE-REPLAY | P1 | No LIVE vs REPLAY badges on Home/nav | REPLAY labs look equivalent to LIVE | Labels on Home PATH; Attack Service links only on LIVE | Home PATH lab lists; Attack Service lab switch stays LIVE-only | No | Home | Yes | LIVE-only (unchanged allowlist) | Yes | Each curriculum lab labeled LIVE or REPLAY | **DONE** — nav stays human titles (no suffix clutter) |
| GAP-16C-P1-PATH-B | P1 | Path B visible without disclosure on LIVE INVESTIGATE | Path A skipped | Pedagogical disclosure; still not an authz gate | LIVE workshop builders; `academy.py` constants | No | Studio markdown | Yes | No | Yes | Path A default language; Path B “answer key, not policy” | **DONE** — not a product gate |
| GAP-16C-P1-REPLAY-PATHA | P1 | REPLAY labs lack investigations.json Path A | Cannot try first on 003–scanner | Honest HUNT banner (16C allowed this alternative) | REPLAY builders HUNT markdown | No | Studio | Yes | No | Yes | “REPLAY workshop” + Path A Search + Path B bound tables | **DONE** — no six new investigations.json files |
| GAP-16C-P1-ASSESS | P1 | Assessment not in product | No graduate check | Per-lab PROVE + Home CHECK; no leaderboard | Home SPLUNK CHECK; existing PROVE knowledge checks | No | Optional Studio | Yes | No | Yes | Claims classified SUPPORTED/CORROBORATED/NOT PROVEN/INCORRECT | **DONE** — no scoring backend |

## P2 items considered and deferred

| Gap | Why not in 16D | Exception? |
|-----|----------------|------------|
| MCP-003/004 Attack Service LIVE | 16C: REPLAY is enough for academy coherence | No |
| Manifest `level` fields inconsistent | Docs/IA only; curriculum.json is the learner source of truth | No — would not complete a P0/P1 |
| Memory Q-MEMORY two run.ids copy | Starter guidance already present; Attack Service already shows WRITE vs RECALL | No extra product surface |
| Capstone retrieve→write hash-only | Honesty already documented in 16B; no schema bump | No |

## P3 items not started

Real A2A / OAuth / SPIFFE, HITL, MLTK, catalog rug-pull, DET-MCP-CATALOG, progress persistence, tool-output poisoning LIVE.

## Non-goals verified

No new attack domain. No DET-*. No MLTK. No vector DB. No LangChain. No real A2A. No OAuth/OIDC/JWT/SPIFFE. No schema bump. No authorization mutation. Attack Service allowlist still the seven LIVE labs.
