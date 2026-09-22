# AgentSec curriculum map (Phase 16C)

**Status:** DESIGN (16C). **16D product:** Home START/ORIENT/PATH/SPLUNK and nav Foundations → Context Security → Agent Intent → Capstone implement this map. **17A:** Mastery Check is a standalone nav view after Capstone, not a new collection or L6. See `docs/PHASE17A_LEARNER_MASTERY_VALIDATION.md`.  
**Does not rewrite** historical 15A `docs/AGENTSEC_CURRICULUM_LEVELS.md` or 16A `docs/AGENTSEC_LEARNING_LEVELS.md`. Those remain dated snapshots (16A still says capstone DESIGNED).  
**16C line:** Do not implement nav/Home from this file. 16D was a later named phase.

All workshop XML currently lives under `learning/level_1/`. Levels below are **pedagogy**, not filesystem.

Do not preserve historical phase order merely because that is how the product was built. MCP-001 belongs before RAG/Memory because those labs’ tool PDP is CTRL-MCP-001.

---

## Recommended learner path

```text
LEVEL 0  Orientation          DESIGN (missing in product)
LEVEL 1  Input + tool PDP     LIVE PI → LIVE MCP-001
         Grant anatomy        REPLAY MCP-003 → MCP-004
LEVEL 2  Context              LIVE RAG → LIVE Memory
         INV-002 variants     REPLAY MCP-005 → catalog → scanner
LEVEL 3  Intent + identity    LIVE Goal → LIVE Identity
         Deputy contrast      REPLAY MCP-006
LEVEL 4  Investigation craft  woven through Path A (not a separate lab)
LEVEL 5  Integrated purple    LIVE capstone
```

---

## LEVEL 0 — Orientation

**Status in product:** **16D IMPLEMENTED** on Home (START/ORIENT). 16C snapshot: NOT IMPLEMENTED. Home was a workshop directory with stale copy. DESIGN the content here; do not build it in 16C.

**Prior knowledge:** Basic cybersecurity (authz vs authn, logs, least privilege). Almost no agentic AI.

**Learning objectives:** Define LLM, agent, tool call, MCP, RAG, memory, trust boundary, PDP, telemetry. State what Splunk does and does not do here. Distinguish ATTACK vs RETEST, LIVE vs REPLAY, authoritative vs corroborative evidence.

**Labs:** DESIGNED Home “Start here” + glossary. Not a new attack.

**Skills:** Open Home, Attack Service, Search. Copy nothing yet.

**Time:** 30–45 minutes (when built).

**Exit competency:** FOUNDATIONAL. Can answer the beginner questions in `docs/PHASE16C_AGENTSEC_ACADEMY_AUDIT.md` / graduate profile without launching.

---

## LEVEL 1 — Input and authority foundations

**Prior:** Level 0 (today: informal; learner currently jumps into PI LEARN).

**Objectives:** Untrusted input can influence an agent. A tool request is not a grant. Predict → launch → Path A → RETEST equivalent bytes.

**Labs (LIVE required):**

1. LAB-PI-001 — Direct Prompt Injection (CTRL-INPUT-001).
2. LAB-MCP-001 — Tool Authorization (CTRL-MCP-001).

**Labs (REPLAY, do not skip forever):** LAB-MCP-003, LAB-MCP-004.

**Skills:** `run.id`, `sequence`, `control.decision`, execution events, fingerprint equality.

**Time:** LIVE pair 2.5–3 hours; REPLAY 003/004 +1.5–2 hours.

**Exit:** PRACTITIONER. Names two PDPs. Does not claim Splunk enforced.

---

## LEVEL 2 — Context is data

**Prior:** Level 1 LIVE. MCP-003/004 REPLAY strongly recommended before claiming “I understand grants.”

**Objectives:** Retrieved content and stored memory may influence a later request. They do not mint grants. OBSERVE ≠ ALLOW.

**Labs (LIVE):** LAB-RAG-CONTEXT then LAB-MEMORY-001 (write then later recall).

**Labs (REPLAY):** LAB-MCP-005, LAB-MCP-CATALOG, LAB-SCANNER-RUNTIME-EVIDENCE.

**Skills:** Provenance ≠ trust; hashes; two `run.id`s; scanner sourcetype ≠ `otel:agentic:json`.

**Time:** LIVE 3–3.5 hours; REPLAY +2–2.5 hours.

**Exit:** INVESTIGATOR on context planes. Still not a fused chain.

---

## LEVEL 3 — Intent and identity

**Prior:** Level 2 LIVE.

**Objectives:** Authorized tool ≠ authorized goal. Identity/delegation claims ≠ authentication/authorization. MCP-006 confused deputy is **not** the same lab as identity claims.

**Labs (LIVE):** Goal Integrity then Identity / Delegation.

**Labs (REPLAY):** LAB-MCP-006 (required so the learner does not collapse deputy into identity).

**Time:** LIVE 2.5–3 hours; MCP-006 +45–60 minutes.

**Exit:** INVESTIGATOR who can rule a domain **out**.

---

## LEVEL 4 — Investigation and detection craft

**Not a separate workshop.** It is Path A across Levels 1–3 plus DETECT tabs.

**Objectives:** Hunt vs detection. Evidence quality. False conclusions. DET-MCP-001 only where DENY-then-start applies. 0 rows ≠ SAFE. No MLTK required.

**Exit:** Can investigate one LIVE pair without Path B.

---

## LEVEL 5 — Integrated purple team

**Prior:** Levels 1–3 LIVE. REPLAY class-A workshops (003/004/005/006/catalog/scanner) recommended.

**Lab:** LAB-AGENTSEC-CAPSTONE-001 (LIVE, implemented 16B).

**Objectives:** Symptom-first reconstruction across retrieve → persist → recall → MCP. Rule out Goal and Identity. Classify proof.

**Time:** 2.5–4 hours.

**Exit:** ADVANCED / PURPLE TEAM for this range. Not production agent-security engineering.

---

## What not to do

- Do not put the capstone in the nav before Goal/Identity (16C OBSERVED defect; **16D remediated**).
- Do not teach RAG before MCP-001.
- Do not require MCP-003 LIVE migration before a learner may attempt the capstone; require the **concept** (REPLAY is enough).
- Do not add a progress database or leaderboard.
- Do not treat Mastery Check as a sixth nav collection or as industry certification (17A).
