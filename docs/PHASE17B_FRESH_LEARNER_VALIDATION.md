# Phase 17B — Fresh learner usability and instructional validation

**Status:** IMPLEMENTED 2026-09-21. Schema **1.9.0** unchanged. Runtime authorization **UNCHANGED**.  
**Predecessor:** Phase 17A PASS (Mastery Check).  
**STOP:** Do not start Phase 17C from this file. No new attack, detector, schema bump, MLTK, persistence backend, certification, real A2A, or OAuth/OIDC/SPIFFE.

This phase is **not** a new attack domain. It asks: can a person who did not build AgentSec learn agentic security from the product without repository knowledge?

---

## Product result

Copy-only instructional fixes on existing Academy surfaces.

- WHY / PREDICT before LIVE ATTACK on Goal Integrity and Capstone (PI and MCP-001 already had this).
- REPLAY LEARN headers no longer say LIVE EVIDENCE.
- REPLAY Path B explains YOU SHOULD SEE / THAT MEANS / IT DOES NOT MEAN / NEXT.
- Empty Search is taught as wait-for-EVIDENCE-READY, not DENY.
- Memory CTA is Launch ATTACK (LIVE); hunt authorization on the RECALL run.id.
- Capstone PROVE next action is Mastery Check.
- Home START skip for learners who already know agents/tools/RAG.
- Home ORIENT introduces overlay, fingerprint, and source_run_id.
- Mastery FOUNDATIONAL NONE cards do not require Splunk Search.
- Learner copy no longer points at `src/agentsec`, `knowledge-check.md`, `artifacts/<run-id>/`, or pytest as a next step.

REPLAY labs were **not** migrated to LIVE.

---

## Evidence classes (this phase)

- **DOCUMENTED:** friction log, instructional matrix, learner journey, troubleshooting.
- **MEASURED:** offline pytest (repository consistency).
- **OBSERVED:** Playwright of Home, six LIVE labs, Capstone, Mastery Check, Attack Service after restage (`docs/screenshots/agentsec-academy-17b/pass17b_validation.json`, defects `[]`).
- **Not claimed:** pytest proves learner comprehension; new LIVE attack pairs.

---

## Security semantics preserved

UNTRUSTED DATA != MALICIOUS DATA. PROVENANCE != TRUST. IDENTITY CLAIM != AUTHENTICATION. REQUEST != GRANT. OBSERVE != ALLOW. ALLOW != EXECUTION. MISSING EVENT != PREVENTION. SPLUNK != ENFORCEMENT. REPLAY != LIVE. Learning metadata != policy. AUTHORIZED TOOL != AUTHORIZED GOAL.

CTRL-* , `coded_policy()`, Attack Service allowlist, DET-MCP-001, and existing Q-* semantics were not modified.

---

## Related docs

- `docs/AGENTSEC_FRESH_LEARNER_FRICTION_LOG.md`
- `docs/AGENTSEC_INSTRUCTIONAL_QUALITY_MATRIX.md`
- `docs/AGENTSEC_LEARNER_JOURNEY.md`
- `docs/AGENTSEC_SPLUNK_NOTEBOOK_EXPERIENCE.md`
- `docs/AGENTSEC_ATTACK_LEARNING_EXPERIENCE.md`
- `docs/AGENTSEC_LIVE_REPLAY_LEARNER_GUIDE.md`
- `docs/AGENTSEC_TROUBLESHOOTING_FOR_LEARNERS.md`
- `docs/learning-notes/learning-agentic-security-with-agentsec.md`
- `docs/reviews/ui-review-agentsec-academy-17b-2026-09-21.md`
