# AgentSec capstone design

**Status:** DESIGN ONLY (Phase 15A). **Do not build this runtime, Studio view, or launcher.**

**Phase 16A:** Smallest honest architecture, attack story, 16 investigations, and evidence planes are in `docs/AGENTSEC_CAPSTONE_ARCHITECTURE.md`, `docs/AGENTSEC_CAPSTONE_ATTACK_STORY.md`, `docs/AGENTSEC_CAPSTONE_INVESTIGATION_DESIGN.md`, and `docs/AGENTSEC_CAPSTONE_EVIDENCE_MODEL.md`. This 15A file keeps the original intent (symptom-first, mixed workflow, no domain in the title).

The capstone must **not** tell the learner “this is a RAG attack” (or any other domain label).

---

## Purpose

Demonstrate **ARCHITECT + PURPLE TEAM** competency: a realistic agent workflow with several possible trust boundaries. The learner reconstructs what happened and recommends the control plane, with proof and limitations.

---

## Prerequisites (must exist first)

- Level 1–2 complete (PI-001, MCP-001; ideally 003/004).
- At least one INV-002 lab (005, catalog, or RAG) as LIVE or honest REPLAY.
- Memory **or** a DESIGN EXERCISE on persistence.
- Goal integrity as workshop or DESIGN EXERCISE.
- Identity may remain DESIGN EXERCISE if Studio is still missing.
- Splunk skill: advanced Path A (cross-event correlation).
- DET-MCP-001 understood as the **only** operational detector pattern, not a template to clone.

Do not implement the capstone as Wave 1.

---

## Learning objectives

The learner will:

1. Understand a posted architecture (user → orchestrator → RAG → memory → agent → MCP → optional deputy → tool result → goal → execution → telemetry).
2. Launch **or** inspect a closed experiment (LIVE if a frozen multi-hop definition exists; otherwise REPLAY labeled REPLAY).
3. Find `run.id` (or the write/recall pair).
4. Reconstruct sequence from Search, not only Studio.
5. Identify source, trust boundary, influence/request/claim.
6. Identify authorization decision(s) and whether execution started.
7. Classify evidence (authoritative vs corroborative; LIVE vs REPLAY).
8. Decide hunt vs detection vs rejected signal — without inventing DET-*.
9. Recommend the correct control plane (which PDP, which classifier is OBSERVE-only).
10. Retest if LIVE exists, with equivalent adversarial input.
11. State what can and cannot be proved (HEC, coverage, one pair ≠ universal resistance, Splunk ≠ enforcement).

---

## Potential chain (narrative, not a build ticket)

```text
User
 → Orchestrator
 → RAG retrieve
 → Memory recall
 → Agent
 → MCP tool request
 → Delegated deputy (optional)
 → Tool result
 → Goal / task check
 → Execution
 → Telemetry → Splunk
```

Failure may be at **any** boundary. The scenario packet names the workflow, not the vulnerability class.

---

## Modes

| Mode | When justified |
|------|----------------|
| LIVE | Only if a server-owned multi-hop definition can freeze all untrusted bytes and profiles |
| REPLAY | Default honest mode for a mixed pack |
| DESIGN EXERCISE | Architecture reasoning without execution |
| REFERENCE | External incident analogy after the learner has a hypothesis |

Never label REPLAY as LIVE.

---

## What the capstone must not do

- New schema fields “for the capstone.”
- New DET-* because the story is dramatic.
- ML as authorization.
- Live A2A transport.
- Recreating a real breach payload for realism.
- Telling the learner the domain in the title (`ws_lab_rag_capstone` would already spoil it).

---

## Definition of done (future phase)

A learner who has not been told the domain can still: mark boundaries, reconstruct with SPL, name the PDP, compare ATTACK/RETEST or explain why RETEST is N/A, and write a short SOC + engineering readout that never claims Splunk enforced policy.
