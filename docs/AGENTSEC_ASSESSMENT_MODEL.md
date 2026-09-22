# AgentSec assessment model

**Status (17A):** IMPLEMENTED as `learning/academy/assessments.json` + `ws_agentsec_mastery`. Learning metadata is not policy. No scoring percentage. No leaderboard. No persistence backend. Not a certificate. Schema **1.9.0**.  
**16C body below** remains the DESIGN snapshot. Do not treat the 16C “not in product yet” rows as current.

Contract fields actually used: `assessment_id`, `title`, `competency_level`, `splunk_skill`, `lab_id`, `evidence_mode`, `run_ids`, `security_question`, `task`, `starter_context`, `hint_1`, `hint_2`, `solution_spl_id`, `related_hunt`, `related_control`, `related_invariant`, claim lists, attacker/server/observability ownership, `next_assessment`.

Path A is the default. Path B is an optional answer key. Studio 10.2 cannot hide Path B.

Progress words if a learner self-marks: NOT ATTEMPTED / IN PROGRESS / DEMONSTRATED / NEEDS REVIEW. Nothing is stored.

See `docs/PHASE17A_LEARNER_MASTERY_VALIDATION.md`.

---

# AgentSec assessment model (Phase 16C historical DESIGN)

**Status:** DESIGN only (16C). No scoring code. No leaderboard. No gamification store.  
**Do not implement from this file.** 17A implemented the model in a later named phase.

Assessment is evidence reasoning, not trivia (“what is CTRL-MCP-001’s id?”).

---

## Dimensions (unweighted until a later product decision)

1. **Security reasoning** — inequalities, trust boundary, PDP vs classifier.
2. **Splunk investigation** — Path A, fields, honest empty-result semantics.
3. **Evidence interpretation** — SUPPORTED / CORROBORATED / NOT PROVEN / INCORRECT.
4. **Control understanding** — who decided, before which operation.
5. **ATTACK / RETEST reasoning** — equivalent input, what changed, what did not.

Do not score speed. Time-to-investigate is not TTDR.

---

## Item types

| Type | Example |
|------|---------|
| Prediction | Before launch: will CONTEXT OBSERVE or ALLOW? Will the handler start? |
| Hands-on SPL | Given a `run.id`, reconstruct sequence in Search |
| Evidence interpretation | Classify “Splunk prevented the attack” |
| ATTACK/RETEST compare | Same hash? Different decision? |
| What can you prove? | Handler 1 vs missing `mcp.started` |
| Control identification | Which component made the authorization decision? |
| False-conclusion identification | “Identity must have failed because a tool ran” |

---

## Per-lab checks (LIVE)

Each LIVE lab already has prediction + Path A questions + PROVE classifications. Treat those as the **per-lab check**. Pass = learner produces a written or oral readout that:

- names the PDP
- does not credit Splunk as enforcement
- cites handler/LLM count for execution
- states one limitation from the lab manifest

Do not auto-grade Studio clicks.

---

## Per-level checks

| Level | Check |
|-------|-------|
| 0 | Define agent vs LLM; Splunk ≠ PDP (DESIGN; not in product yet) |
| 1 | LIVE PI + MCP-001 Path A; REQUEST ≠ GRANT; hop-0 DENY ≠ “Splunk blocked” |
| 2 | RAG or Memory: OBSERVE + MCP decision + hash; two ids for Memory |
| 3 | Goal: MCP ALLOW on RETEST is expected. Identity: WHO AUTHENTICATED = NOT PROVEN |
| 5 | Capstone CAP-I12/I13/I16 |

---

## Capstone assessment

Use CAP-I16 plus:

- Three `run.id`s identified
- Retrieve→write explained as hash equality (no invented field)
- Recall `source_run_id` = write `run.id`
- CTRL-MCP-001 named as tool PDP
- Goal/Identity “not required to explain” without claiming those domains never fail
- ATTACK handler 1 / RETEST handler 0
- One RETEST ≠ universal RAG/memory resistance

---

## What not to assess

- Memorized OWASP/ATLAS ids
- Production detector enablement
- Typing speed
- Whether the learner opened Path B (Path B is optional)
