# Task script (read each task aloud, in order; stopwatch from read-out to pass or abandon)

| # | Read aloud | Pass when | Box |
|---|---|---|---|
| T0 | "You want to learn how AI agents get tricked. Find something to do in this lab." | Opens the Loan Desk mission unaided | 2 min |
| T1 | "Without doing anything yet, tell me what you will learn here and what you need." | Names at least two objectives from the page, and the Ollama requirement | 3 min |
| T2 | "Check that the lab is ready to run the agent." | Finds the first-run check and reads it correctly (Ready, or the manual fix) | 2 min |
| T3 | "Submit an ordinary loan application." | Normal run completes; learner states the outcome | 4 min |
| T4 | "Before attacking, say what you expect to happen." | Locks all three predictions | 2 min |
| T5 | "Run the attack." | Attack run completes | 4 min |
| T6 | "Which action did the model propose, which did the policy decide, and which did code actually run?" | Names one of each and separates proposed from executed | 5 min |
| T7 | "Prove it from the Splunk evidence." | Reaches the search for this run's id and reports an event count; reads the verification status correctly (including NOT VERIFIED) | 7 min |
| T8 | "Fix the problem." | Applies the hardened control and says what it limits | 3 min |
| T9 | "Run the same attack again and compare." | Retest completes; reads the comparison | 4 min |
| T10 | "Was the attack stopped? Did the loan review finish? Are those the same question?" | Says blocked; if unfinished says that is a usability cost, not a control failure | 3 min |
| T11 | "Explain to a colleague why the first run was dangerous even though policy said ALLOW." | Four-question check passes and a written explanation is given | 5 min |

Budget: 44 minutes of boxes plus a 5-minute debrief. Use the browser Back button deliberately once (after T8): note
whether it returns to the step the participant was on.
