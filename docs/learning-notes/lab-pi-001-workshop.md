# LAB-PI-001 workshop logic (Phase 2C.2)

## WHAT IS IT?

A guided Direct Prompt Injection lab: objectives, a ten-step flow, evidence gates, knowledge checks, and (Phase 2C.3) one Dashboard Studio view. It reuses four already-validated Splunk investigations. It is not a detection pack.

## WHY DOES IT EXIST?

Validated SPL sitting in `searches/` does not teach the lifecycle. Learners need to know **when** to run each question, what “good” looks like, and which layer is allowed to claim prevention.

## HOW DOES IT WORK?

Simple picture first:

BASELINE (benign, 4 ALLOW, 4 LLM) → ATTACK (same app, ATK-002, vulnerable fail-open, 4 LLM) → RETEST (same attack, defended, DENY before invoke, 0 LLM).

ALLOW is the decision. LLM execution is `llm.*`. Fail-open means the generate began, not that a loan was approved.

LEARN (concept) → BASELINE (benign hunt) → ATTACK (predict, then fire) → OBSERVE (`Q-RUN-EVENTS`) → HUNT (control + llm searches) → DETECT (contract question `Q-LLM-AFTER-DENY`, not a notable event) → DEFEND (CTRL-INPUT-001 placement) → RETEST (same payload; honest about `ATTACK` vs `RETEST` labels) → COMPARE (only Splunk-validated ids) → PROVE (four evidence blocks).

## WHERE DOES IT SIT IN AGENTSEC?

After Phase 2C.1 and 2C.2. Phase 2C.3 adds `ws_lab_pi_001`. Splunk remains the workbench; AcmeBank remains the enforcement point.

## WHAT IS THE TRUST BOUNDARY?

AcmeBank HTTP and the LLM call. The workshop files cannot ALLOW a loan.

## WHAT COULD AN ATTACKER CONTROL?

Still only `input` / `user_id`. Not workshop markdown, not search IDs, not profile.

## WHAT CAN GO WRONG?

Teaching DETECT as if DET-001 existed. Calling the 2C.1 defended run `RETEST`. Using the SIMULATED fixture as OBSERVED. Completing the lab from Splunk screenshots alone.

## WHAT TELEMETRY SHOULD EXIST?

Unchanged schema 1.0.0. No new event types.

## HOW WILL SPLUNK SHOW IT?

The same four VALIDATED searches. Studio JSON is later.

## WHAT CONTROL COULD CHANGE THE RESULT?

CTRL-INPUT-001 / security profile. Not this documentation.

## WHAT TEST PROVES THE LOGIC?

Pytest checks that the workshop files exist, name the four query IDs, forbid conceptual fields, and do not call the positive control OBSERVED. It does not re-execute Splunk.

## What I should now be able to explain

1. Why OBSERVE uses `Q-RUN-EVENTS` before HUNT.
2. Why DETECT in this phase is a contract hunt, not a saved detection.
3. Why COMPARE is BASELINE vs VULNERABLE ATTACK vs DEFENDED RETEST (benign 4 LLM → fail-open 4 LLM → DENY 0 LLM).
4. Why `78f05d1b-…` is DENY but still not a RETEST label.
5. Why G4 completeness is required before “no llm.*” language.
6. Why ALLOW rows and `llm.*` rows answer different questions.
7. Why the `makeresults` row is SIMULATED.
8. What four PROVE blocks are, in order.
9. Why Phase 2A ids `3367455f-…` / `9bdb542c-…` are not Splunk homework.
10. What would have justified a new SPL file (a missing lab question) — and why none was added.
