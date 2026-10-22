# Loan Desk five-person pilot protocol

**Status: NOT CONDUCTED.** No participant has been recruited or observed. The results table in section 7 is empty on
purpose. Do not fill it from the automated walkthrough.

## 1. Question and limits
Can a first-time learner complete the Loan Desk mission unaided in 30–45 minutes and explain why the attack
succeeded under BASELINE and failed under HARDENED? Five people find the common blocking problems. They do not
estimate rates: report counts ("3 of 5"), never percentages or significance.

## 2. Participants (5)
- 2 security analysts or SOC engineers (Splunk-literate, new to agents).
- 2 developers or platform engineers (agents-literate or not, security-light).
- 1 participant who uses a keyboard only or a screen reader, if one can be recruited. If not, record "accessibility
  participant NOT RECRUITED" and say accessibility remains covered by automated checks only.
- None may have seen AgentSecLab or its authors' notes. Record role, Splunk familiarity (0–3) and agent familiarity (0–3).
- Volunteers, no personal data beyond role and the two familiarity scores. Participant ids P1–P5, never names.
- Do not time or judge the participant, only the product. Anyone may stop at any time.

## 3. Setup
Fresh browser profile, 1280×800 screen, one observer, screen and audio recorded only with consent. Lab started by the
facilitator; `ollama list` shows `llama3.2:latest`; `./scripts/loan_desk_verifier.sh status` is running. Use the task
script in `LEARNER_ACCEPTANCE.md` §1. Facilitator reads the task text and nothing else. Hints are allowed only after
3 silent minutes on one task, and each hint is logged as a hint, not a pass.

## 4. Measures, recorded per task by the observer
| Measure | How |
|---|---|
| Task completion | Pass, Pass-with-hint, Fail, Abandoned, using the pass rules in the acceptance table |
| Elapsed time | Stopwatch from task read-out to pass or abandonment, per task and total |
| Navigation errors | Count of: clicks on locked steps, wrong tab or page, Back-button use that lost state, asking where something is |
| Comprehension | T1, T5, T9, T10 free-text answers scored 0/1/2 against the rubric in §5, scored blind by two raters |
| Perceived difficulty | After each task: Single Ease Question, 1 (very hard) to 7 (very easy). After the session: free text "what was hardest?" |
| Accessibility | Whether every task was completable with the participant's own input method; each barrier logged with step and control |
| Confidence | "How sure are you the defense works?" 1–5 before and after the retest |
| Trust calibration | Asked: "Is the Splunk check proof the policy works?" Correct answer: it proves the events were indexed, nothing more |

## 5. Comprehension rubric
- T1 (idea): 2 = a valid, allowed action can still carry attacker content; 1 = names model/policy/handler roles only; 0 = other.
- T5 (proposed vs decided vs executed): 2 = names all three and says a proposal is not an execution; 1 = two; 0 = fewer.
- T9 (blocked vs unfinished): 2 = attack blocked, unfinished review is a usability cost; 1 = says blocked only; 0 = says the defense "failed" or "worked" with no reason.
- T10 (why dangerous though ALLOW): 2 = authorization checked the tool, scope and applicant, not the content; 1 = vague "injection"; 0 = other.

## 6. Success criteria (agree before running; do not move afterwards)
- At least 4 of 5 reach T10 within 45 minutes.
- Median total time within 30–45 minutes.
- No task blocks 2 or more participants (a blocker is a defect, not a participant failure).
- At least 4 of 5 score 2 on T9, the point the Batch 4 hardened-run copy exists to land.
- Mean SEQ ≥ 5 on every task; any task below 4 gets redesigned.
- The accessibility participant (if recruited) completes every task, or the barrier is logged as a P1 defect.

## 7. Results (empty until the pilot is run)
| P | Role | Splunk/Agent fam. | Tasks passed (of 11) | Hints | Total min | Nav errors | T1/T5/T9/T10 | Mean SEQ | A11y barriers |
|---|---|---|---|---|---|---|---|---|---|
| P1 | | | NOT CONDUCTED | | | | | | |
| P2 | | | NOT CONDUCTED | | | | | | |
| P3 | | | NOT CONDUCTED | | | | | | |
| P4 | | | NOT CONDUCTED | | | | | | |
| P5 | | | NOT CONDUCTED | | | | | | |

## 8. After the pilot
Rank every observed problem by (participants affected) × (blocked or slowed). Fix blockers, then rerun with 3 new
participants before claiming the experience is acceptable. Report the automated and human results in separate
sections, as in the acceptance document.
