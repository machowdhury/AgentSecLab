# Batch 5, Priority 1: Loan Desk learner acceptance

**Status of human evidence: PILOT NOT CONDUCTED.** No learner has used the mission. Everything under "Automated results"
was produced by a Playwright script. A script cannot be confused, bored or misled, so none of it is a usability result.

## 1. Acceptance session (30–45 minutes, facilitated, one learner at a time)

Target learner: a security analyst or engineer who has not seen AgentSecLab. Docker already works on their machine.
The facilitator starts the lab beforehand (`./scripts/lab-up.sh`), confirms the host Ollama has `llama3.2:latest`, then
hands over the browser at `http://127.0.0.1:5001/academy`. The facilitator says nothing about the product, and answers
only "what would you do next?" and safety questions. Think-aloud is requested.

| # | Task (what the learner is told) | Lifecycle stage | Pass when | Time box |
|---|---|---|---|---|
| T0 | "You want to learn how agents get tricked. Find something to do." | Discover | Opens the Loan Desk mission without help | 2 min |
| T1 | "Say in your own words what you will learn." | Understand | States the idea (a valid action can carry attacker text) or any two of: model proposes / policy decides / handler runs | 3 min |
| T2 | "Submit an ordinary application." | Explore | Run finishes; learner can name the outcome | 4 min |
| T3 | "Before attacking, say what you expect." | Predict | Locks all three predictions | 2 min |
| T4 | "Run the attack." | Attack | Baseline run completes | 4 min |
| T5 | "Which step did the model propose, which did policy decide, which did code actually run?" | Observe | Names one of each, distinguishing proposed from executed | 5 min |
| T6 | "Prove it in Splunk." | Investigate | Reaches Splunk search with the run id and reports an event count; reads the verification status correctly | 7 min |
| T7 | "Fix it." | Defend | Applies the hardened control; says what it constrains | 3 min |
| T8 | "Run the same attack again." | Retest | Retest completes | 4 min |
| T9 | "What changed, and was the loan review finished?" | Compare | States the attack was blocked; if the review did not finish, says that is a usability cost, not a control failure | 4 min |
| T10 | "Explain to a colleague why the first run was dangerous even though policy said ALLOW." | Explain | Passes the four-question check and writes the explanation | 5 min |

Budget: 43 min of task boxes plus a 5-minute debrief. The 30–45-minute claim stands only if the median of five learners
lands inside it. The page's own reading load is 7.7 min (10 steps, 1,537 words at 200 wpm); the real model runs took
5–13 s each on a warm model. The rest is thinking, Splunk navigation and typing, which is the part nobody has measured.

## 2. Automated results (Playwright against the live Docker stack, 2026-10-22)

Script: `scripts/loan_desk_learner_walkthrough.py` (artifact: `learner_walkthrough.json`). Fixture-based journey tests,
which use a labelled test double, are in `tests/ui/test_loan_desk_mission_browser.py` and ran in the full suite.

| Check | Result | Note |
|---|---|---|
| Home → mission | 1 click ("Start the mission"); also in the nav | |
| Mission page states a duration | Yes | |
| Mission page lists learning objectives | **No** (only "What you will learn", one sentence). The Academy home card has them. | Gap |
| Mission page lists prerequisites | **No** | Gap |
| Steps with "What to do" and "Why it matters" | 10 of 10 | |
| Out-of-order step links blocked, with a reason | 4 of 4 | |
| Keyboard-only: Tab to Continue, Enter, focus lands in new step | Pass | |
| Prediction and unlocked state survive page reload | Pass | |
| Browser console errors / page errors / HTTP ≥ 400 during the full journey | 0 / 0 / 0 | |
| Attack panel shows proposals, policy decision, handler outcome, planted text reaching the queue | All shown | |
| Retest panel says BLOCKED, separates business outcome, shows reason `argument_not_allowed` | All shown | |
| Machine time, explore / attack / retest | 5.1 s / 8.1 s / 12.5 s cumulative | Not human time |
| Browser Back from the Compare step | Goes to `#understand`, not the previous step | Minor navigation defect |
| axe-core on all 10 steps | No serious or critical. Moderate: `region` on all steps, `heading-order` on 5, minor `empty-table-header` on 2 | The repo gate checks serious/critical only |
| Jargon (`posture`, `scope`, `handler`, `ALLOW`, `DENY`) | Used 29 times; none marked up with `<abbr>`/`<dfn>`; a glossary is not on the page | Whether the text defines them in prose is a pilot question |

Not tested by any script: comprehension, whether the prediction step is understood, whether the Splunk step is
findable by a newcomer, tone, cognitive load, screen-reader announcements (axe is not a screen reader), colour
perception, or whether 25–40 minutes is true.

## 3. Defects and gaps found in this pass (not fixed; Batch 5 forbids new features)

1. Mission page has no objectives list and no prerequisites. Required by the vision (§7 items 1 and "prerequisite knowledge").
2. Browser Back from Compare lands on Understand (step history is not pushed per step).
3. Undefined jargon; recommend a four-term glossary (`posture`, `scope`, `handler`, `ALLOW/DENY`).
4. axe `heading-order` on 5 steps and `empty-table-header` on 2.
5. **Terminal dependency:** the mission needs `ollama pull llama3.2:latest` on the host. The compose Ollama container only pulls `llama3.2:1b`, and is empty on this machine. A learner with only working Docker cannot complete the mission; the page says "model unavailable" and the fix is a terminal command. This contradicts the Batch 4 acceptance sentence "without terminal commands" for a fresh machine.
6. The verifier must be running (started by `lab-up.sh`); otherwise evidence stays NOT VERIFIED. Honest, but a learner cannot fix it from the browser.
7. `scripts/validate_phase14b_live_launch.py` sends a `profile` field that the launch contract now rejects (400). Stale validator; the live sweep in this batch used the contract's four fields.
