# Comprehension prompts and scoring rubric

Ask each prompt aloud after the matching task. Record the answer verbatim. Two raters score independently from the
transcript, without seeing the participant's role or the other rater's score; disagreements are settled by a third read.

| Prompt (after) | 2 points | 1 point | 0 points |
|---|---|---|---|
| **C1** After T1: "What is the main idea of this lab?" | A valid, allowed action can still carry attacker content | Names model / policy / handler roles only | Anything else |
| **C2** After T6: "What is the difference between a proposal, a decision and an execution?" | Proposal is a request, decision is ALLOW/DENY, execution means code ran; a proposal is not an action | Names two of the three correctly | Fewer |
| **C3** After T10: "The retest did not finish the loan review. Did the defense fail?" | No: the attack was blocked; the unfinished review is a usability cost | Says it worked without the reason, or hedges correctly but vaguely | Says it failed, or cannot say |
| **C4** After T11: "Policy said ALLOW. Why was it still dangerous?" | Authorization checked the tool, scope and applicant, not the note's content | "Injection" with no mechanism | Anything else |
| **C5** After T7: "Does SPLUNK-VERIFIED prove the attack happened?" | It shows the events AcmeBank recorded are the ones Splunk indexed; not proof they are true | Says it proves indexing only, without the limit | Says it proves the attack or that the system is safe |

| **C6** After T11, last prompt: "Who decides whether the agent's action runs: the model, the policy, or Splunk? Could the model change that decision? Could Splunk?" | The **policy decision point** is separate code the model cannot edit; the model only proposes; Splunk records and neither allows nor denies; names that the handler runs only after ALLOW | Says the policy decides but not that the model cannot influence it, or confuses Splunk with enforcement | Says the model or Splunk decides, or that the prompt/instructions enforce it |

**Confidence:** before T9 ask "How sure are you the defense works, 1-5?"; after T10 ask again. Record both.
**Scoring output per participant:** C1 to C6 points (max 12). Headline measures: the count of 2s on C3 (blocked versus unfinished) and on C6 (independent enforcement boundary).
