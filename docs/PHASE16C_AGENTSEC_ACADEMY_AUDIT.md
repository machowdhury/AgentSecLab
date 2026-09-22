# Phase 16C — AgentSec Academy audit

**Status:** DESIGN / AUDIT / RESEARCH / VALIDATION ONLY (2026-09-20).  
**Schema:** **1.9.0 unchanged.** Runtime authorization **UNCHANGED.** No new attack, detector, launcher, Studio rewrite, or schema bump in this phase.  
**Do not start Phase 16D from this file.**

This phase answers: after seven LIVE labs and an integrated LIVE capstone, does the repository function as a coherent hands-on Agentic Security Academy — and what remains before it is a complete learning experience?

Evidence classes follow `50-research-integrity.mdc`. Historical 14E–16B reports are **DOCUMENTED**; current tree, manifests, views, and launch catalog are **OBSERVED**; official Splunk pairs cited from those reports are **MEASURED** in their original files, not re-measured here.

---

## Operating principle (preserved)

AgentSec is a learning-by-doing range, not a demo gallery, CTF, detector factory, or SOC product.

Loop: LEARN → trust boundary → PREDICT → LAUNCH → OBSERVE → Path A Search → optional Path B → security decision → DEFEND the actual PDP → RETEST equivalent input → COMPARE → PROVE → connect domains.

Roles: Studio = syllabus. Attack Service = closed launcher. Runtime = enforcement. Search = notebook. Splunk = evidence. Learning metadata ≠ policy. Splunk ≠ enforcement.

---

## 1. Predecessor verification

| Phase | Lab/domain | Design | Runtime | LIVE ATTACK | LIVE RETEST | Splunk | Path A | Path B | Studio | Attack Service | Detection | Schema | Limitations |
|-------|------------|--------|---------|-------------|-------------|--------|--------|--------|--------|----------------|-----------|--------|-------------|
| 14E | PI-001 + MCP-001 reusable loop | DOCUMENTED | MEASURED | MEASURED | MEASURED | MEASURED | OBSERVED | OBSERVED | OBSERVED | OBSERVED | DET-MCP-001 reuse only | 1.9.0 | PI regex; LLM nondeterminism on ALLOW |
| 15A | Curriculum architecture | DESIGNED | NOT IMPLEMENTED (by design) | n/a | n/a | n/a | DESIGNED | DESIGNED | DESIGNED | DESIGNED | NONE JUSTIFIED | 1.9.0 | Recommended 15B as MCP-003; named 15B executed RAG |
| 15B | LAB-RAG-CONTEXT | DOCUMENTED | MEASURED | MEASURED | MEASURED | MEASURED | OBSERVED | OBSERVED | OBSERVED | OBSERVED | NO DET-RAG | 1.9.0 | Fixture retriever, not vector DB |
| 15C | LAB-MEMORY-001 | DOCUMENTED | MEASURED | MEASURED | MEASURED | MEASURED | OBSERVED | OBSERVED | OBSERVED | OBSERVED | NO DET-MEMORY | 1.9.0 | Two-run; serialized memory.id |
| 15D | LAB-AGENT-GOAL-INTEGRITY-001 | DOCUMENTED | MEASURED | MEASURED | MEASURED | MEASURED | OBSERVED | OBSERVED | OBSERVED | OBSERVED | NO DET-GOAL | 1.9.0 | RETEST is GOAL DENY, not MCP DENY |
| 15E | LAB-AGENT-DELEGATION-001 | DOCUMENTED | MEASURED | MEASURED | MEASURED | MEASURED | OBSERVED | OBSERVED | OBSERVED | OBSERVED | NO DET-A2A | 1.9.0 | Claims lab; WHO AUTHENTICATED = NOT PROVEN |
| 16A | Curriculum + capstone contract | DESIGNED | NOT IMPLEMENTED (by 16A design) | n/a | n/a | n/a | DESIGNED | DESIGNED | DESIGNED | DESIGNED | NO DET-CAPSTONE | 1.9.0 | Capstone DESIGNED; 16B built it |
| 16B | LAB-AGENTSEC-CAPSTONE-001 | DOCUMENTED | MEASURED | MEASURED | MEASURED | MEASURED | OBSERVED | OBSERVED | OBSERVED | OBSERVED | NO DET-CAPSTONE | 1.9.0 | Three-run; hash join retrieve→write; attack.id RAG-001 |

### Discrepancies (document before any later change)

1. **15A inventory is stale (DOCUMENTED vs OBSERVED).** `docs/AGENTSEC_EXISTING_LAB_INVENTORY.md` still says Attack Service is `{LAB-PI-001, LAB-MCP-001}` only. Current `known_lab_ids()` is seven labs including RAG, Memory, Goal, Identity, Capstone. Preserve the 15A file as a dated snapshot; use `docs/AGENTSEC_LIVE_LAB_MATRIX.md` as current.
2. **16A learning levels still say capstone DESIGNED, not built.** Historical 16A snapshot. 16B implemented it. Canonical progression: `docs/AGENTSEC_CURRICULUM_MAP.md`.
3. **Home is false (OBSERVED).** `ws_agentsec_home` still says “Identity / delegation workshop is not published yet” and omits the capstone. Nav already publishes both.
4. **Nav order inverts pedagogy (OBSERVED).** Capstone sits between Context Security and Agent Authority. Goal/Identity appear after the graduation exercise.
5. **Folder `learning/level_1/` holds every workshop (OBSERVED).** Manifest `level` fields disagree (MCP-001=`1`, RAG=`4`, Memory=`1`, Goal/Identity=`5`, capstone=`capstone`, PI omitted).
6. **Capstone telemetry `attack.id` is RAG-001 (MEASURED in 16B).** Schema 1.9.0 has no CAPSTONE-001 enum. Honest, not a silent schema bump.
7. **Retrieve→write has no dedicated schema field (DOCUMENTED 16B).** Correlation is `content.hash` equality plus `memory.source_run_id`.

Do not rewrite those historical files to pretend they were always current.

---

## 2. Does AgentSec function as an academy?

**Partially yes, not yet as a single coherent product.**

SUPPORTED today:

- Seven closed LIVE Attack Service labs with BASELINE / ATTACK / RETEST.
- Integrated LIVE capstone that requires RAG + memory + MCP reasoning and asks the learner to rule out Goal and Identity.
- Path A/B metadata on every LIVE lab.
- One professional Studio syllabus per published workshop.
- One operational detector pattern (DET-MCP-001), used honestly (silence ≠ SAFE).
- Security inequalities taught repeatedly: DATA ≠ AUTHORITY, REQUEST ≠ GRANT, OBSERVE ≠ ALLOW, ALLOW ≠ EXECUTION, SPLUNK ≠ ENFORCEMENT.

NOT YET a complete academy:

- Home does not tell a beginner where to start, what is LIVE vs REPLAY, or that Identity and the capstone exist.
- No Level 0 orientation that defines LLM / agent / MCP / RAG / memory / PDP / Splunk’s role.
- Grant-anatomy labs (MCP-003/004/005/006/catalog/scanner) are REPLAY workshops without Path A/B manifests.
- Path B lives in the same Studio tab as Path A, so solution SPL is one scroll away.
- No assessment or graduate checklist in product — only docs.

Verdict for this phase: **coherent core loop exists; academy packaging is the remaining P0/P1 work.** See recommended next phase.

---

## 3. Security semantics gate

Curriculum and Studio copy **must not** teach, and current LIVE manifests **do not** teach as true:

| Forbidden claim | Current teaching |
|-----------------|------------------|
| Splunk blocked the attack | Splunk ≠ enforcement |
| DENY string alone proves non-execution | Handler / LLM count is authoritative |
| Missing telemetry proves prevention | Incomplete copy ≠ prevention |
| OBSERVE means authorization | OBSERVE ≠ ALLOW |
| ALLOW proves execution | ALLOW ≠ EXECUTION |
| Stored memory is trusted | STORED ≠ TRUSTED |
| RAG provenance is trust | PROVENANCE ≠ TRUST |
| Caller agent id proves authentication | IDENTITY CLAIM ≠ AUTHENTICATION |
| Delegation claim grants authority | DELEGATION CLAIM ≠ AUTHORIZATION |
| Authorized tool means authorized goal | AUTHORIZED TOOL ≠ AUTHORIZED GOAL |
| BASELINE means SAFE | BASELINE ≠ SAFE |
| RETEST means universally secure | One RETEST ≠ universal security |
| ATTACK success means universal vulnerability | Labeled lab overlay only |
| Framework mapping proves security | Mappings are secondary / RELATED |
| Detector silence means SAFE | 0 rows ≠ SAFE |

---

## 4. Beginner readiness

A learner with basic cybersecurity and almost no agentic AI **cannot** currently answer these from product Home before Lab 1:

| Question | Product answer today |
|----------|----------------------|
| What is an LLM / agent / tool call / MCP / RAG / memory? | NOT IMPLEMENTED on Home. LEARN tabs assume the terms. |
| What is a trust boundary / PDP? | Implicit in first LEARN tab, not pre-lab. |
| What Splunk does / does not do | PARTIAL — Home says Splunk does not grant; weak on “not enforcement of RETEST.” |
| ATTACK vs RETEST / LIVE vs REPLAY | NOT on Home. LIVE labs teach it after launch. |
| Authoritative vs corroborative | NOT on Home. PROVE tabs teach it later. |

**DESIGN (do not implement in 16C):** a Level 0 Home/orientation panel. Placement: `ws_agentsec_home` first screen + Attack Service landing. Content in `docs/AGENTSEC_CURRICULUM_MAP.md` Level 0.

---

## 5. Path A / Path B quality

LIVE labs (`investigations.json`): each row has security_question, starter_guidance, hint_1, hint_2, solution_spl_id, expected_result_shape, does_not_prove. Path A is constructible. Path B is an answer key.

**Too much Path B too early (MEDIUM):** Studio INVESTIGATE stacks Hint 1 / Hint 2 / solution SPL in one tab. A determined learner can skip Path A. Capstone is the worst case (16 investigations). Do not hide SPL behind authorization; **do** DESIGN a “reveal solution” disclosure later.

**Path A scaffolding:** PI and MCP-001 are sufficient. Memory Q-MEMORY must bind **write and recall** — easy to miss (HIGH for that lab, already documented in 15C/16B). Capstone retrieve→write is hash equality with no field — Path A must say so (it does in CAP-I5).

REPLAY MCP-003–scanner: **Path A/B NOT IMPLEMENTED** as investigation metadata. HUNT tabs bind canonical SPL (Path B without a try-first prompt). P1 to add investigations.json **or** an honest “REPLAY syllabus — solution searches are on the HUNT tab” banner. Do not implement in 16C.

---

## 6. Attack → telemetry → investigation → defense loop

LIVE manifests include WHY, attacker influence, boundary, predict, expected evidence, which control, what RETEST keeps constant. Studio has LEARN / ATTACK / INVESTIGATE / DEFEND / RETEST / COMPARE / PROVE.

Missing or weak (flag, do not fix here):

| Step | Gap |
|------|-----|
| What should I do next (other lab)? | Home / nav have no Start-here path |
| Connect to another domain | Capstone LEARNING CONNECTION exists in 16B Studio; earlier labs point forward weakly |
| Evidence READY vs HTTP 200 | Attack Service teaches it; Home does not |
| Goal RETEST ≠ MCP DENY | Taught in-lab; easy to mis-generalize from MCP-001 |

REPLAY workshops have ATTACK/RETEST **specimen dropdowns**, not learner-launched RETEST. Loop is incomplete for those labs by design.

---

## 7. Capstone quality

16B capstone **does** require prior labs: RAG OBSERVE, memory WRITE/RECALL, MCP request/grant/execution, cross-run correlation, ATTACK vs RETEST, proof classes, ruling out Goal and Identity.

It is not three unrelated replay panels. Official triples are MEASURED in 16B docs.

Absent **by contract** (not defects): Goal failure, Identity failure, real A2A, HITL, DET-CAPSTONE, dedicated retrieve→write field.

Pedagogy remaining: Home/nav do not present it as graduation; it appears mid-nav.

---

## 8. Purple-team metrics (education only)

| Metric | Class | Note |
|--------|-------|------|
| Attack Success Rate (handler 1 on labeled ATTACK) | USEFUL FOR EDUCATION | Lab overlay, not production ASR |
| Retest Success Rate (handler 0 on equivalent bytes) | USEFUL FOR EDUCATION | One pair ≠ universal |
| Time to Evidence (EVIDENCE READY) | FUTURE | Do not treat learner latency as TTDR |
| Time to Investigate / Explain | FUTURE / MISLEADING if used as SOC KPI | Slow can mean careful |
| Hunt Completion | FUTURE | No progress store; do not fake it |
| Evidence Completeness (local vs dc(_raw)) | USEFUL FOR EDUCATION | Already MEASURED in LIVE reports |
| TTDR | MISLEADING | Learner time ≠ detection time |
| Production MTTD / MTTR | OUT OF SCOPE | |

No new telemetry in 16C. Do not implement dashboards of these metrics.

---

## 9. Framework coverage

Do not invent IDs. Secondary to the lesson.

| Mapping | Class |
|---------|-------|
| OWASP LLM01 prompt injection (PI, RAG influence) | RELATED |
| OWASP ASI01 goal hijack | RELATED (Goal lab); not capstone |
| OWASP ASI02 tool misuse | RELATED (MCP-001) |
| OWASP ASI03 identity/privilege | RELATED (Identity, MCP-006) |
| OWASP ASI04 supply chain | RELATED (catalog/scanner) |
| OWASP ASI06 memory/context | RELATED (Memory, capstone persistence) |
| MITRE ATLAS AML.T0054 on ATK-002 | REQUIRES REVALIDATION (8A already flagged) |
| Other ATLAS technique stamps | UNMAPPED / REQUIRES REVALIDATION |
| NIST AI RMF / AI 600-1 | RELATED (measure evidence, not a control) |
| “Certified mapping” | NOT PROVEN — never claim |

---

## 10. Detection engineering

Inventory: **DET-MCP-001** (disabled saved search) + SIMULATED positive-control SPL. Hunts Q-* as listed in 15A tests. Rejected: DET-RAG, DET-MEMORY, DET-GOAL, DET-A2A, DET-CAPSTONE, DET-SCANNER, DET-MCP-005.

| Behavior | Runtime | Hunt | Detector |
|----------|---------|------|----------|
| DENY then handler start | Prevented by control if coded; DET if violated | Q-MCP-AFTER-DENY | DET-MCP-001 |
| Fail-open ALLOW overlay | Observable, not this detector | Domain Q-* | NONE JUSTIFIED |
| RAG/memory OBSERVE | Classification | Q-RAG / Q-MEMORY | NONE JUSTIFIED |
| Goal DENY / MCP ALLOW | Dual plane | Q-GOAL + Q-MCP | NONE JUSTIFIED |
| Catalog description poison | Observable | Q-MCP-CATALOG-AUTHORITY | Candidate later (8D); not created |

ML may prioritize investigation later. ML must not grant or deny. No MLTK in 16C.

---

## 11. UI / information architecture

Established system: `docs/AGENTSEC_DESIGN_SYSTEM.md`. Do **not** redesign in 16C.

| Finding | Severity | Evidence |
|---------|----------|----------|
| Home omits Identity + capstone; says identity unpublished | **BLOCKER** (academy truth) | `ws_agentsec_home.xml` |
| Capstone nav group before Agent Authority | **HIGH** | `default.xml` |
| No Start-here / LIVE vs REPLAY badges | **HIGH** | Home + nav |
| Path B visible without disclosure | **MEDIUM** | INVESTIGATE tabs |
| 1024 PROVE label clip (capstone) | **MEDIUM** | 16B UI review |
| Dense Attack Service launcher | **MEDIUM** | 16B UI review |
| All labs under `learning/level_1/` | **LOW** | filesystem vs curriculum |
| Manifest `level` integers disagree | **LOW** | JSON fields |

Phase 16C does not fix these. Unresolved BLOCKER/HIGH here are **product-academy** defects, not a 16B UI regression of the capstone workshop itself.

PortSwigger principle (pedagogy only, no branding): learner should always know where they are, what they are learning, why, what to do next, what to observe, how to investigate, how to know they were correct, what comes next. Home currently fails “where / next.” LIVE labs mostly succeed in-tab.

---

## 12. Content duplication

| Statement | Action |
|-----------|--------|
| OBSERVE ≠ ALLOW | KEEP REPEATED in every OBSERVE lab |
| SPLUNK ≠ ENFORCEMENT | KEEP REPEATED |
| ALLOW ≠ EXECUTION | KEEP REPEATED |
| untrusted ≠ malicious | KEEP REPEATED |
| HEC ≠ searchable evidence | CENTRALIZE on Home + Attack Service; SHORTEN in later labs |
| What is RAG/memory/MCP | CENTRALIZE in Level 0; LAB-SPECIFIC depth stays |
| Overlay is lab-only fail-open | KEEP REPEATED (easy to miss) |
| 10-step LEARN→PROVE list | CENTRALIZE on Home; SHORTEN per lab |

Do not remove repetition that prevents false conclusions.

---

## 13. Missing domains

| Candidate | Class |
|-----------|-------|
| Tool output poisoning | PARTIALLY TAUGHT (MCP-005 REPLAY) |
| Multi-agent trust / real A2A | FUTURE / OUT OF SCOPE for 16C–16D polish |
| Authenticated agent identity | FUTURE (D) |
| Secrets / credential use | OUT OF SCOPE |
| HITL | FUTURE |
| Agent supply chain / catalog rug-pull | FUTURE (research track) |
| MCP server provenance | PARTIALLY TAUGHT (catalog + scanner) |
| Code execution / sandbox escape | OUT OF SCOPE |
| Data exfiltration | OUT OF SCOPE |
| Excessive agency | PARTIALLY TAUGHT (Goal + ungranted tool) |
| Agent lifecycle | FUTURE |
| Model/tool dependency | FUTURE |
| MLTK / behavioral analytics | FUTURE — not justified by 16C |
| MCP-003/004 Attack Service LIVE | P2 useful, not required for academy coherence |

---

## 14. Recommended next phase

**OPTION B:** P0/P1 educational gaps require a later Phase 16D **only if explicitly requested**, and that phase must be academy packaging — not another attack domain.

Option C (navigation remediation before expansion) is a **constraint on 16D**, not a reason to rebuild the capstone. Capstone runtime PASSed in 16B.

Option A (release/assessment only) is premature while Home misstates published labs.

**16C STOP.** Do not implement the gap matrix from this file.
