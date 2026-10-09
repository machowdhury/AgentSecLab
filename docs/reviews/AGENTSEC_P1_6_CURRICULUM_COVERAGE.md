# AGENTSEC P1.6 — Curriculum coverage

**Evidence class:** DOCUMENTED from `learning/academy/curriculum.json` and lab trees, plus OBSERVED Academy routes on 2026-10-09.

P1.6 did not manufacture new runnable labs. Missing instructional material for **LAB-MCP-001** was completed via the Academy nine-step workshop plus the October 15 demonstration package.

---

## How to read this audit

A lab is **complete for teaching** only if the listed instructional elements exist in learner-facing material (Academy, lab README / workshop.md, or the Oct 15 demo docs). Presence in an internal Phase report is not enough.

Runnable means:

| Label | Meaning |
|-------|---------|
| Academy | Dedicated nine-step Flask workshop |
| Attack Service LIVE | Closed `/api/launch` allowlist |
| Splunk Studio | Dashboard view `ws_lab_*` |
| Replay-only | Committed packs / Studio; no new runtime launch |
| Live-capable | Runtime can mint a new `run.id` |
| Conceptual / reference-only | Teaching text or simulated tables; not a live control experiment |

---

## Classification summary (Gate D labels)

Labels, one or more per lab: **Academy-integrated** · **Runnable outside Academy** · **REPLAY-only** · **LIVE-capable** · **Reference-only** · **Incomplete**.

"LIVE-capable" means the lab is on the closed launch allowlist. In P1.6 only LAB-MCP-001 LIVE was re-run and reconciled with Splunk (MEASURED). The other LIVE-capable labs are DOCUMENTED, not re-measured. On this host Ollama is unreachable and `llama3.2:1b` is absent, so any LIVE path that calls the model is DEGRADED. Per-lab model dependence was not re-measured in P1.6.

| Lab / item | Labels | Evidence class (P1.6) |
|------------|--------|------------------------|
| L0 Orientation | Academy-integrated (Foundations) · Reference-only | OBSERVED (route 200) |
| LAB-PI-001 | Runnable outside Academy · LIVE-capable | DOCUMENTED |
| **LAB-MCP-001** | **Academy-integrated · Runnable outside Academy · LIVE-capable** (+ committed REPLAY packs) | **MEASURED** (rehearsal + 7/7 reconcile) |
| LAB-MCP-003 | Runnable outside Academy (Studio) · REPLAY-only | DOCUMENTED |
| LAB-MCP-004 | Runnable outside Academy (Studio) · REPLAY-only | DOCUMENTED |
| LAB-RAG-CONTEXT | Runnable outside Academy · LIVE-capable | DOCUMENTED |
| LAB-MEMORY-001 | Runnable outside Academy · LIVE-capable | DOCUMENTED |
| LAB-MCP-005 | Runnable outside Academy (Studio) · REPLAY-only | DOCUMENTED; publication restriction kept |
| LAB-MCP-CATALOG | Runnable outside Academy (Studio) · REPLAY-only | DOCUMENTED |
| LAB-SCANNER-RUNTIME-EVIDENCE | Runnable outside Academy (Studio) · REPLAY-only | DOCUMENTED |
| LAB-EXTERNAL-EVALUATION-GARAK | Runnable outside Academy (Studio) · REPLAY-only | DOCUMENTED |
| LAB-AGENT-GOAL-INTEGRITY-001 | Runnable outside Academy · LIVE-capable | DOCUMENTED |
| LAB-AGENT-DELEGATION-001 | Runnable outside Academy · LIVE-capable | DOCUMENTED |
| LAB-MCP-006 | Runnable outside Academy (Studio) · REPLAY-only | DOCUMENTED |
| L4 Investigation craft | Reference-only · Incomplete (no packaged workshop) | DOCUMENTED |
| LAB-AGENTSEC-CAPSTONE-001 | Runnable outside Academy · LIVE-capable | DOCUMENTED |
| LAB-BLUE-TEAM-INCIDENT-001 | Runnable outside Academy (Studio) · REPLAY-only | DOCUMENTED |
| LAB-THREAT-MODELING-001 | Runnable outside Academy (Studio) · REPLAY-only | DOCUMENTED |
| LAB-PRIVACY-DATA-GOVERNANCE-001 | Runnable outside Academy (Studio) · REPLAY-only | DOCUMENTED |
| LAB-MULTI-STAGE-INCIDENT-001 | Runnable outside Academy (Studio) · REPLAY-only | DOCUMENTED |
| LAB-ADVANCED-CAPSTONE-MASTERY-001 | Runnable outside Academy (Studio) · REPLAY-only | DOCUMENTED |
| Checkpoints (12, below) | Reference-only (SIMULATED / REPLAYED / DOCUMENTED Studio material) | DOCUMENTED |

Every lab except LAB-MCP-001 is **Incomplete with respect to the Academy** (no nine-step workshop). That is a Phase 2 gap, not an Oct 15 blocker.

---

## Instructional-element checklist (LAB-MCP-001)

Target for October 15: complete beginner-friendly package.

| Element | Where it lives | Status |
|---------|----------------|--------|
| Learning objectives | Academy Start; `learning/level_1/LAB-MCP-001/README.md` | Present |
| Required background | Lab README prerequisite knowledge; Academy Foundations | Present |
| Architecture explanation | Academy Start story + lab README diagram | Present |
| Attack mechanism | Academy ATTACK scenario (server-owned MCP-002) | Present |
| Trust boundary | Academy lab boundaries; CTRL-MCP-001 before handler | Present |
| Prerequisites | Curriculum L0 → L1; Foundations page | Present |
| Step-by-step instructions | Academy START → EXPLAIN (9 steps) | Present |
| Expected observations | Evidence notebook + compare table | Present (after the learner looks) |
| Investigation questions | Academy notebook (5 questions) + `knowledge-check.md` | Present |
| Defense discussion | Academy DEFEND table | Present |
| Retest procedure | Academy RETEST (LIVE or REPLAY pair) | Present |
| Knowledge checks | `knowledge-check.md` (13 Q&A); Academy notebook | Present |
| Facilitator guidance | `docs/INSTRUCTOR_GUIDE.md`; `docs/demo/AGENTSEC_OCT15_FACILITATOR_GUIDE.md` | Present |
| Evidence references | Committed REPLAY IDs; P1.6 LIVE pair `82423ce2-…` / `2c4e5738-…` (and earlier `de60a91c-…` / `b8c432ff-…`) in the RC report | Present |

**October 15 beginner package:** open `http://127.0.0.1:5001/academy`, then Foundations, Path, LAB-MCP-001. Facilitators use the Oct 15 script. Do not start on Splunk Studio for a mixed audience.

---

## Labs in `curriculum.json` `levels[]`

### L0 Orientation

| Lab | Mode | Runnable | Instructional completeness | Notes |
|-----|------|----------|----------------------------|-------|
| (no lab id) | Conceptual | Academy Foundations + L0 Studio home | Partial (orientation, not a control lab) | Curriculum `labs: []` |

### L1 Input and tool authority

| Lab | Mode | Academy | Attack Service | Studio | Completeness | Oct 15 |
|-----|------|---------|----------------|--------|--------------|--------|
| LAB-PI-001 Direct Prompt Injection | LIVE | Path link only | LIVE | `ws_lab_pi_001` | Strong in lab tree / learning-notes; not the nine-step Academy | Out of 15–20 min path |
| **LAB-MCP-001 Tool Authorization** | LIVE | **Yes** | LIVE | `ws_lab_mcp_001` | **Complete beginner package** | **Primary** |
| LAB-MCP-003 Scope Escalation | REPLAY | No | No | `ws_lab_mcp_003` | Workshop + learning-notes | Reference |
| LAB-MCP-004 Parameter / Resource | REPLAY | No | No | `ws_lab_mcp_004` | Workshop + learning-notes | Reference |

### L2 Context and evidence are data

| Lab | Mode | Runnable | Completeness | Notes |
|-----|------|----------|--------------|-------|
| LAB-RAG-CONTEXT | LIVE | Attack Service + Studio | Strong lab tree | INV-002 teaching; not Academy nine-step |
| LAB-MEMORY-001 | LIVE | Attack Service + Studio | Strong lab tree | |
| LAB-MCP-005 Tool Result Trust | REPLAY | Studio | Strong; **do not publish detections** | MCP-005 restriction preserved |
| LAB-MCP-CATALOG | REPLAY | Studio | Workshop notes | |
| LAB-SCANNER-RUNTIME-EVIDENCE | REPLAY | Studio + committed scanner packs | Finding plane ≠ runtime PDP | |
| LAB-EXTERNAL-EVALUATION-GARAK | REPLAY | Studio + ExternalEvidence 1.0.0 packs | Adapter + pack; garak is not CTRL-MCP-001 | |

### L3 Intent and identity

| Lab | Mode | Runnable | Completeness |
|-----|------|----------|--------------|
| LAB-AGENT-GOAL-INTEGRITY-001 | LIVE | Attack Service + Studio | Strong lab tree |
| LAB-AGENT-DELEGATION-001 | LIVE | Attack Service + Studio | Strong lab tree |
| LAB-MCP-006 Confused Deputy | REPLAY | Studio | Workshop notes |

### L4 Investigation craft

No separate lab. Woven through Path A. Completeness: practice guidance, not a packaged workshop.

### L5–L10

| Lab | Mode | Runnable | Completeness |
|-----|------|----------|--------------|
| LAB-AGENTSEC-CAPSTONE-001 | LIVE | Attack Service + Studio | Integrated LIVE capstone |
| LAB-BLUE-TEAM-INCIDENT-001 | REPLAY | Studio | Replay incident |
| LAB-THREAT-MODELING-001 | REPLAY | Studio | Architecture exercise |
| LAB-PRIVACY-DATA-GOVERNANCE-001 | REPLAY | Studio | Privacy investigation |
| LAB-MULTI-STAGE-INCIDENT-001 | REPLAY | Studio | Integrated incident |
| LAB-ADVANCED-CAPSTONE-MASTERY-001 | REPLAY | Studio | Mastery capstone |

---

## Checkpoints (not in `levels[]`)

These appear in `curriculum.json` `checkpoints` and on the Academy path as “Not tracked here” / Studio views.

| Id | Evidence class in curriculum | Runnable | Completeness |
|----|------------------------------|----------|--------------|
| SPLUNK-DEFENDER-BRIDGE | REPLAY | Studio | Present as bridge, not an 8th LIVE lab |
| DETECTION-ENGINEERING | REPLAY | Studio | Teach detections; DET-MCP-001 stays disabled |
| AGENT-IDENTITY-NHI | REPLAY | Studio | Workshop |
| A2A-AUTH-DELEGATION | SIMULATED / REPLAYED | Studio | **No real A2A protocol** |
| HITL-APPROVAL | SIMULATED / REPLAYED | Studio | **Not production HITL** |
| CREDENTIAL-LIFETIME | SIMULATED / REPLAYED | Studio | |
| RAG-PURPOSE | SIMULATED / REPLAYED | Studio | |
| RECALL-ISOLATION | SIMULATED / REPLAYED | Studio | |
| ASSET-INVENTORY | DOCUMENTED | Studio | |
| COMPONENT-PROVENANCE | DOCUMENTED / SIMULATED | Studio | |
| CODE-AGENT-BOUNDS | SIMULATED / REPLAYED | Studio | |
| CHANGE-BOUNDS | SIMULATED / REPLAYED | Studio | |

Do not present checkpoints as LIVE runtime experiments.

---

## Launch allowlist (LIVE-capable)

Seven labs, 21 allowlist rows (BASELINE / ATTACK / RETEST × live) from `EXPERIMENT_DEFINITIONS`:

1. LAB-PI-001
2. LAB-MCP-001
3. LAB-RAG-CONTEXT
4. LAB-MEMORY-001
5. LAB-AGENT-GOAL-INTEGRITY-001
6. LAB-AGENT-DELEGATION-001
7. LAB-AGENTSEC-CAPSTONE-001

Academy dedicated workshop: **LAB-MCP-001 only**.

---

## Gaps (honest, not expanded in P1.6)

- Other LIVE labs lack the Academy nine-step UX. They remain Attack Service + Studio.
- Checkpoints with SIMULATED / DOCUMENTED classes must not be described as measured live incidents.
- LAB-MCP-001 README still mentions schema 1.1.0 for historical packs. Runtime LIVE is 1.9.0. Facilitators must say both.
- Knowledge-check.md is Phase 3B/3C voice; Academy notebook is the beginner surface.

No new scenarios were added.
