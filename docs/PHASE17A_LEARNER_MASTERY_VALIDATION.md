# Phase 17A — Learner mastery validation

**Status:** IMPLEMENTED 2026-09-21. Schema **1.9.0** unchanged. Runtime authorization **UNCHANGED**.  
**Predecessor:** Phase 16D PASS (AgentSec Academy packaging).  
**STOP:** Do not start Phase 17B from this file. No new attack, detector, schema bump, MLTK, persistence backend, or certification.

This phase is **not** a new attack domain. It asks: can a learner who did not build AgentSec demonstrate agentic-security reasoning?

---

## Product result

A dedicated Studio view `ws_agentsec_mastery` (**Mastery Check**) plus `learning/academy/assessments.json`.

- Learning metadata only (`not_authorization: true`).
- Not copied into the Attack Service image.
- Cannot choose profile, grants, tools, or scopes.
- No progress persistence. No PII. No score percentage. Not a certificate.
- Path A first; Path B is an optional answer key. Studio 10.2 cannot hide Path B.
- REPLAY specimens remain labeled REPLAY. Capstone prefers LIVE; official historical recall ids are a labeled REPLAY fallback.
- Home gains a secondary Mastery Check link. Nav collections still end at Capstone.

---

## Challenges

| Id | Level | Mode | Skill |
|----|-------|------|-------|
| Who enforces, who observes? | FOUNDATIONAL | NONE | — |
| Rewrite the indefensible sentence | FOUNDATIONAL | NONE | S8 |
| Find this run without being told the mode | PRACTITIONER | REPLAY | S1 |
| Decision versus execution | PRACTITIONER | REPLAY | S5 |
| Same request, different defense | INVESTIGATOR | REPLAY | S7 |
| MCP ALLOW, but was the goal authorized? | ADVANCED | REPLAY | S4 |
| Identity OBSERVE is not authentication | ADVANCED | REPLAY | S8 |
| Empty mcp.started is not prevention | ADVANCED | REPLAY | S5 |
| Do not collapse every incident into prompt injection | ADVANCED | NONE | S8 |
| Lending assistant mastery readout | PURPLE TEAM | LIVE preferred | S7 |

Hunts reused: Q-RUN-EVENTS, Q-CONTROL-DECISION, Q-MCP-AUTHZ, Q-MCP-EXECUTED, Q-GOAL-INTEGRITY-AUTHORITY, Q-AGENT-DELEGATION-AUTHORITY. No new Q-*. No DET-ASSESSMENT / DET-CAPSTONE / DET-LEARNER.

---

## Evidence classes (this phase)

- **DOCUMENTED:** assessments.json, Studio markdown, knowledge-check rewrites.
- **MEASURED:** offline pytest (repository consistency).
- **OBSERVED:** Playwright of Home + Mastery Check + one lab + Attack Service after restage.
- **Not claimed:** live Splunk hunt results from pytest; new LIVE attack pairs.

---

## Security semantics preserved

UNTRUSTED DATA != MALICIOUS DATA. PROVENANCE != TRUST. IDENTITY CLAIM != AUTHENTICATION. REQUEST != GRANT. OBSERVE != ALLOW. ALLOW != EXECUTION. MISSING EVENT != PREVENTION. SPLUNK != ENFORCEMENT. REPLAY != LIVE. Learning metadata != policy.

CTRL-* , `coded_policy()`, Attack Service allowlist, DET-MCP-001, and existing Q-* semantics were not modified.

---

## Related docs

- `docs/AGENTSEC_ASSESSMENT_MODEL.md`
- `docs/AGENTSEC_MASTERY_RUBRIC.md`
- `docs/AGENTSEC_CAPSTONE_ASSESSMENT.md`
- `docs/AGENTSEC_SPLUNK_INVESTIGATION_ASSESSMENT.md`
- `docs/AGENTSEC_SECURITY_REASONING_ASSESSMENT.md`
- `docs/PHASE17A_FRESH_LEARNER_WALKTHROUGH.md`
- `docs/PHASE17A_ADVANCED_LEARNER_WALKTHROUGH.md`
- `docs/PHASE17A_UI_UX_VALIDATION.md`
- `docs/learning-notes/agentsec-mastery-and-assessment.md`
