# Agent goal integrity runtime

Runtime companion to `docs/learning-notes/agent-goal-integrity-101.md`.

## WHAT IS IT?

The smallest deterministic lab that shows a **granted** tool used for an **unauthorized objective**.

## WHY DOES IT EXIST?

If the attack only requested `lookup_customer_tier`, learners would think “MCP DENY saved us.” This lab keeps MCP ALLOW on both ATTACK and RETEST.

## HOW DOES IT WORK?

See `docs/GOAL_INTEGRITY_RUNTIME_CONTRACT.md`. Fingerprints exclude run.id and profile so ATTACK and RETEST compare equal.

## WHERE DOES IT SIT IN AGENTSEC?

After identity/delegation (12C). Splunk hunt is Phase 13C (`docs/learning-notes/goal-integrity-splunk-investigation.md`). Workshop not started.

## TRUST BOUNDARY / ATTACKER / FAILURE

Instruction fixture vs orchestrator contract. Attacker owns the note. Failure is treating the note as the new job.

## TELEMETRY / SPLUNK / CONTROL / TEST

Schema 1.9.0. Splunk validated in 13C. Profile is the discriminator. `tests/security/test_goal_integrity.py`.

## What I should now be able to explain

1. Why the TaskContract fingerprint must omit run.id and profile.
2. Why `extract_full_policy` is not a new MCP tool name.
3. Why RETEST can DENY expansion and still ALLOW `lookup_policy`.
4. Why wrong-goal handler count is the execution proof, not MCP DENY.
5. Why the overlay is labeled and closed to one action.
6. Why authority-like JSON keys are ERROR, not grants.
7. Why check/use passes a frozen ProposedTaskChange into follow-on MCP.
8. Why DET-MCP-001 stays silent and must stay unchanged.
9. Why `splunk.verified=false` on local packs.
10. Why this is not a prompt filter.
