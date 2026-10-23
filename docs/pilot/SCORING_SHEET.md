# Scoring sheet (one per participant)

Status: NOT CONDUCTED. Score from what the participant does and says; do not coach before Part B.

## Part A: task completion (from the observation log)
Score each: **2** done independently (no tier 2 or 3 intervention), **1** done with help (tier 2 or 3), **0** not done.

| # | Task | Evidence | Score |
|---|---|---|---|
| T1 | Predicts before attacking (prediction locked in step 3) | page state / log | |
| T2 | Runs the planted application and sees the attacker text reach the underwriter queue | step 4 to 5 | |
| T3 | Finds the proposal, the policy decision and the executed handler events in Splunk (Investigate) | step 6 | |
| T4 | Verifies the attack run (Verify with Splunk shows SPLUNK-VERIFIED) | page badge | |
| T5 | Changes one control (Defend) | step 7 | |
| T6 | Retests; reads the outcome (blocked, and whether the loan review finished) | step 8 | |
| T7 | Compares before and after | step 9 | |
| T8 | Writes the Explain step in their own words | step 10 | |

Core journey complete (criterion S1) = T2, T4, T5, T6 and T8 each scored at least 1 and the retest also SPLUNK-VERIFIED. Independent = no score of 1 among T2 to T6.
Task completion: __ / 16. Core journey complete? yes / no. Independent? yes / no.

## Part B: security comprehension (ask AFTER the mission; ask aloud, write what they say)
Score **2** correct and specific, **1** partly right or right with a prompt, **0** wrong or no answer. A prompt of "say more" is allowed; naming the answer is not.

| # | Question | Answer key (correct = 2) | Score | What they said |
|---|---|---|---|---|
| Q1 | In the attack run, who or what *proposed* the action that wrote the attacker's note? | The model (Ollama llama3.2) proposed the `submit_for_underwriter_review` call with the planted note. Recorded as `agentsec.agent.action.proposed`. A proposal is only text. | | |
| Q2 | Who decided whether that proposal could run, and was that decision the same as the action happening? | The policy engine (the PDP, control CTRL-LOANDESK-001) decided ALLOW or DENY. Recorded as `agentsec.control.decision`. A decision is not an execution. | | |
| Q3 | What is the *executed action*, and where do you see it? | The tool handler actually writing to the underwriter queue; seen as the separate `agentsec.mcp.started` / `agentsec.mcp.completed` events in Splunk (not the model text, not the decision). | | |
| Q4 | The baseline decision was ALLOW. Does ALLOW mean the request was safe? | No: the policy allowed the tool but never checked the note's content. | | |
| Q5 | What does SPLUNK-VERIFIED prove, and what does it not? | Proves the events AcmeBank recorded are the events Splunk indexed. Does not prove the events are true. | | |
| Q6 | After the defence, the attack was blocked. Is the loan task done? | Not necessarily: blocked and business-task-completed are separate; the hardened run can end INCOMPLETE. | | |

Criterion S2 (this participant): Q1, Q2 and Q3 each scored 2 = **meets**; otherwise **does not meet**. Q4 to Q6 are reported, with no threshold.
Comprehension: __ / 12. Meets S2? yes / no.

Scorer: ______  Second scorer (optional, blind to the first): ______  Disagreements: ______
