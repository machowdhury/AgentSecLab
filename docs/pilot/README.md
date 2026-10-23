# Five-participant pilot package

**Status: NOT CONDUCTED.** No participant has been recruited or observed. Every result field in this package is blank or says NOT CONDUCTED. Nothing here is a measured outcome.

| File | Use |
|---|---|
| `FACILITATOR_RUNBOOK.md` | One page: what the facilitator does, in order |
| `../PILOT_LAUNCH_CHECKLIST.md` | Pre-session readiness checklist, model warm-up and per-participant browser reset (run before EVERY session) |
| `SPLUNK_LOGIN_PROCEDURE.md` | Sign in to Splunk Web without exposing the credential |
| `OBSERVATION_LOG.md` | Per-participant timeline and every facilitator intervention |
| `SCORING_SHEET.md` | Task completion and security comprehension, with answer key |
| `FEEDBACK_QUESTIONNAIRE.md` | Post-session questions for the participant |
| `RESULTS_TEMPLATE.md` | Five-participant roll-up against the success criteria |

## Success criteria (fixed BEFORE any participant starts; do not edit after session 1)
These are **proposed pilot thresholds**, not measured outcomes. They decide whether to widen the pilot, not whether the Academy "works".

| # | Criterion | Pass threshold | Source |
|---|---|---|---|
| S1 | Core journey completed | at least 4 of 5 participants reach step 10 (Explain) having locked a prediction, run the attack and the retest, and the page shows both runs SPLUNK-VERIFIED | Observation log + page |
| S2 | Proposal / PDP / executed action | all 5 participants, after the mission and without the facilitator naming the answer, tell the three apart (scoring sheet Q1 to Q3 each scored 2) | Scoring sheet |
| S3 | Accessibility | no accessibility blocker (a participant cannot perform or perceive a required step) that stays unresolved without facilitator workaround; any blocker is reported even if worked around | Observation log, questionnaire |
| S4 | No fabricated or falsely verified evidence shown | 0 cases. Checked after each session by searching Splunk for both run ids shown on the page | Post-session evidence check |
| S5 | Every intervention recorded | every facilitator intervention has a log row (time, step, tier, reason); a session with an unlogged intervention is void for S1 and S2 | Observation log |

Decision rule: all five met = proceed to wider pilot. S4 or S3 failure = stop and fix before another session. Anything else = fix the named cause, re-run with new participants.
Also record, without a threshold: completion time per step, number and tier of interventions, hardened-run INCOMPLETE rate.

## Standing limits
Participants sit at the lab Mac (or share its screen); sessions run one at a time; do not restart the lab from the `develop` tree; the model must be installed (`docs/reviews/batch9/FINAL_READINESS.md` section 6).
