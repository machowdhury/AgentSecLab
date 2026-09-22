# Phase 16A — Curriculum integration, coverage analysis, and capstone architecture

**Date:** 2026-09-20  
**Mode:** DESIGN / RESEARCH / CURRICULUM ARCHITECTURE ONLY  
**Schema:** **1.9.0** unchanged. Runtime authorization **UNCHANGED**.  
**Do not start Phase 16B from this file.** Do not implement the capstone, a new launcher, detectors, MLTK, real A2A, OAuth/OIDC/JWT/SPIFFE, or additional lab migrations.

Predecessor: Phase 15E PASS (`docs/PHASE15E_IDENTITY_DELEGATION_LIVE_LEARNING_LOOP.md`). Locked platform roles remain:

| Role | Function |
|------|----------|
| Dashboard Studio | Syllabus / lesson / guided notebook |
| Splunk Search | Learner investigation workbench |
| Attack Service | Closed experiment launcher (not a PDP) |
| AgentSec runtime | Enforcement |
| Splunk | Evidence, **not** enforcement |
| Learning metadata | Teaching metadata, **not** policy |

## Primary question

If a learner completes AgentSec as currently implemented, what do they actually understand about agentic security, what can they actually do, what remains missing, and how should the existing labs become one curriculum plus a later capstone?

## Answer (design)

AgentSec is a **localhost purple-team learning range**: closed LIVE experiments, runtime enforcement, Splunk reconstruction. It is not a production AI-security product.

A learner who finishes the **six LIVE domains** can reconstruct source → trust boundary → influence → request → coded authority → control decision → execution → Splunk proof, and can name what evidence cannot prove. They have **not** completed dimensional MCP grant anatomy as LIVE (003/004), confused-deputy LIVE, catalog/scanner LIVE, HITL, real A2A, or a multi-hop capstone.

The curriculum therefore:

1. Teaches one refined reasoning chain (`docs/AGENTSEC_SECURITY_REASONING_MODEL.md`).
2. Places each lab at the trust boundary it actually owns (`docs/AGENTSEC_CURRICULUM_COVERAGE_MATRIX.md`).
3. Classifies gaps instead of inventing labs (`docs/AGENTSEC_CURRICULUM_GAP_ANALYSIS.md`).
4. Designs **LAB-AGENTSEC-CAPSTONE-001** without building it (`docs/AGENTSEC_CAPSTONE_ARCHITECTURE.md`).

## Predecessor verification (repository, not summaries)

Inspected: `src/agentsec/launch_catalog.py` `known_lab_ids()`, `src/agentsec/experiment_context.py` LAB_* constants, six `lab-manifest.json` + `investigations.json`, nav views, `docs/IMPLEMENTATION_STATUS.md`, PHASE14E / 15A–15E files, DET-*.spl, schema `1.9.0`.

### Current LIVE Attack Service labs (OBSERVED)

`known_lab_ids()` = `{LAB-PI-001, LAB-MCP-001, LAB-RAG-CONTEXT, LAB-MEMORY-001, LAB-AGENT-GOAL-INTEGRITY-001, LAB-AGENT-DELEGATION-001}`.

Each has ExperimentContext BASELINE/ATTACK/RETEST, closed `/api/launch`, Path A/B `investigations.json`, Studio view, LIVE Splunk pair recorded in the matching PHASE14D/14E/15B–15E validation doc.

### Discrepancies vs Phase 15A (DOCUMENTED, not silently rewritten)

| 15A claim (2026-09-19) | Repository now (2026-09-20) |
|------------------------|-----------------------------|
| Attack Service LIVE = PI + MCP-001 only | Six LIVE labs |
| RAG/Memory/Goal Attack Service NOT IMPLEMENTED | 15B–15D LIVE VALIDATED |
| Identity: **no Studio view**, launcher NOT IMPLEMENTED | `ws_lab_agent_delegation` + `identity_delegate` LIVE (15E) |
| `lab-manifest.json` only under PI and MCP-001 | Six manifests |
| Next wave: MCP-003 then MCP-004 | Named 15B executed RAG instead (already noted in 15A hub) |
| Learning architecture Level 1 = all MCP workshops COMPLETE as one level | LIVE loop and REPLAY workshops are different completion kinds |

15A documents remain **historical design snapshots**. Current-state teaching order is this file + `docs/AGENTSEC_LEARNING_LEVELS.md` (16A section).

### What 15A got right (preserve)

Platform roles. REQUEST ≠ GRANT. OBSERVE ≠ ALLOW. Splunk ≠ enforcement. Path A/B. Learning metadata ≠ policy. DET-MCP-001 as the only operational detector pattern. Capstone must not name the failing domain. MCP-003/004 still lack Attack Service (true then and now).

## Six LIVE security domains

| Lab | Security question (from lab-manifest) | Classifier | Tool PDP | LIVE pair class |
|-----|----------------------------------------|------------|----------|-----------------|
| LAB-PI-001 | Untrusted loan input vs CTRL-INPUT-001 before LLM | — | CTRL-INPUT-001 is the input PDP | 14D MEASURED |
| LAB-MCP-001 | Tool request vs CTRL-MCP-001 before handler | — | CTRL-MCP-001 | 14E MEASURED |
| LAB-RAG-CONTEXT | Can retrieved content mint a grant? | CTRL-RAG-CONTEXT-001 OBSERVE | CTRL-MCP-001 | 15B MEASURED |
| LAB-MEMORY-001 | Can persisted memory mint a grant on a later run? | CTRL-MEMORY-CONTEXT-001 OBSERVE | CTRL-MCP-001 | 15C MEASURED |
| LAB-AGENT-GOAL-INTEGRITY-001 | Can untrusted instruction redefine a granted tool’s task? | CTRL-GOAL-INTEGRITY-001 | CTRL-MCP-001 still ALLOWs lookup_policy | 15D MEASURED |
| LAB-AGENT-DELEGATION-001 | Can a delegation claim mint authority neither agent has? | CTRL-IDENTITY-001 OBSERVE | CTRL-MCP-001 | 15E MEASURED |

## Companion documents

| Document | Question it answers |
|----------|---------------------|
| `docs/AGENTSEC_SECURITY_REASONING_MODEL.md` | Shared chain + inequalities (15A + 16A refinement) |
| `docs/AGENTSEC_CURRICULUM_COVERAGE_MATRIX.md` | Per-lab capabilities without invented LIVE |
| `docs/AGENTSEC_CONCEPT_COVERAGE.md` | What is taught vs classified gap |
| `docs/AGENTSEC_CURRICULUM_GAP_ANALYSIS.md` | A–E prioritized gaps |
| `docs/AGENTSEC_LEARNING_LEVELS.md` | Current LIVE path vs historical 15A levels |
| `docs/AGENTSEC_SPLUNK_SKILL_PROGRESSION.md` | Search difficulty (updated for LIVE RAG/memory/goal/identity) |
| `docs/AGENTSEC_DETECTION_ENGINEERING_CURRICULUM.md` | CONTEXT → HUNT → DETECTION → FUTURE |
| `docs/AGENTSEC_FINAL_COMPETENCY_MODEL.md` | Measurable graduate bar |
| `docs/AGENTSEC_CAPSTONE_ARCHITECTURE.md` | Smallest honest capstone (not built) |
| `docs/AGENTSEC_CAPSTONE_ATTACK_STORY.md` | BASELINE / ATTACK / RETEST narrative |
| `docs/AGENTSEC_CAPSTONE_INVESTIGATION_DESIGN.md` | 16 Path A/B questions |
| `docs/AGENTSEC_CAPSTONE_EVIDENCE_MODEL.md` | Planes and authority of evidence |
| `docs/learning-notes/agentsec-end-to-end-security-reasoning.md` | Learner-facing explanation |

## What 16A does not do

No new runtime routes. No new ExperimentDefinition rows. No Studio XML. No detectors. No schema bump. No PI/MCP/RAG/Memory/Goal/Identity semantic change. No capstone runtime. No A2A transport. No MLTK.

## Phase 16B (recommendation only — do not start here)

**Exactly one next implementation:** LAB-AGENTSEC-CAPSTONE-001 as a **closed sequenced reuse** of existing RAG retrieve → memory write/recall → CTRL-MCP-001, with Path A/B. Prefer that over migrating MCP-003/004 LIVE first: grant anatomy already has REPLAY workshops; the missing graduate proof is **cross-domain reasoning**.

## Framework coverage (16A)

Verified mappings only (`docs/FRAMEWORK_MAPPING_MODEL.md`). Do not invent MITRE technique IDs. Mapping ≠ certification.

| Topic | Framework | Class | Evidence |
|-------|-----------|-------|----------|
| ATK-002 | MITRE ATLAS `AML.T0054` | DIRECT | `technique_id_for("ATK-002")` |
| MCP-002/003/004 | ATLAS `AML.T0050` | DIRECT | `technique_id_for` |
| Direct PI | OWASP LLM injection (LLM01-style) | RELATED | Educational; FRAMEWORK_MAPPING_MODEL |
| RAG / memory / result / catalog | OWASP LLM indirect / data-as-instruction | RELATED | INV-002 labs; no new ATLAS id in emitters |
| Goal expansion | OWASP agentic excessive agency / goal hijack | RELATED | Goal lab; UNMAPPED as ATLAS in `technique_id_for` |
| Identity claims | OWASP agentic identity / confused-deputy *pattern* | RELATED | 15E; MCP-006 is the deputy lab. Real A2A UNMAPPED |
| NIST AI RMF GOVERN/MAP/MEASURE/MANAGE | Educational tags | RELATED | Not a compliance claim |
| NIST 800-171 / 800-53 | — | NOT APPLICABLE / REQUIRES REVALIDATION | No published per-control attestation in 16A |
| RAG-001, MEMORY-001, GOAL-001, A2A-001 | ATLAS | UNMAPPED | `technique_id_for` returns None |

## Product / educational positioning

AgentSec is a **combination**: vulnerable-agent range + agent-security workshop + Splunk investigation workshop + purple-team loop on **closed localhost experiments**. It is not a production AI-security product, not multi-tenant, and not an “industry unique” claim.

What differentiates it educationally (repository-backed): Attack Service is not a PDP; Studio is a syllabus; Search is the notebook; runtime counts are authoritative; ATTACK/RETEST keep equivalent adversarial bytes; DET-MCP-001 is the only operational detector pattern; OBSERVE classifiers are taught as non-PDPs.

## UX / progress (design only)

See `docs/AGENTSEC_LEARNING_LEVELS.md`. No Home XML change. No fake completion store.

**Do not start Phase 16B from this file.**
