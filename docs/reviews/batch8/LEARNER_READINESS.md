# Learner-readiness assessment (Batch 8)

**The human pilot has NOT been conducted.** No participant has used the lab. Everything below is automated or operator-run evidence about the
*environment*; none of it is a usability result. Pilot package: `docs/reviews/batch6/pilot/`.

## Readiness against your six requirements
| Requirement | Evidence | Status |
|---|---|---|
| All required services ready | `python3 scripts/learner_ready.py` on the redeployed lab: **28 of 28** checks (Docker; five services healthy; Ollama and `llama3.2:latest` with its digest as AcmeBank sees them; Splunk Web; searchable index; every REPLAY specimen the labs offer; verifier process, fresh heartbeat, receipts mount read-only in both containers, no key reachable from a container; Academy, mission and Attack UI pages) | READY |
| All 31 original labs remain discoverable | 32 of 32 labs (31 original + Loan Desk) are reachable: 20 on the Academy path, 12 through the Splunk learning path and app navigation (all 32 are in the Splunk nav and learner-path script). All 32 Studio views render in Splunk Web (Gate A) | READY |
| Original LIVE and REPLAY behaviour preserved | Gate A: 0 regressions across 31 entries. Re-run in Batch 8 after the changes: all 21 live launches identical to the baseline (decisions and event order), 0 changed or removed learning files, the 8 restored labs verified per specimen in an isolated stack and live (193 searches, 0 errors; 24 view states, 0 errors). The 21 specimen launches on the deployed lab reproduce their earlier event counts | READY |
| The Loan Desk mission works end to end | real browser, real model (`llama3.2:latest`, digest `a80c4f17acd5`), on the **redeployed** lab: attack run `32def4b5-9b8a-48ff-b8e7-5d35dd7dcfd0` (34 of 34 events) and hardened retest `0bbf85ca-43ff-4f20-ba8c-b92af7edfbf3` (48 of 48), both SPLUNK-VERIFIED by the host verifier and reconciled independently; "Workflow complete" recorded. Screenshots `live_acceptance/` | READY |
| Learners can finish it without terminal interaction after operator preparation | the journey script drives only the browser. **Operator-only steps:** start the lab, pull the model, start the verifier if it stopped, sign in to Splunk Web once in the session browser profile, reset the profile between participants (`docs/OPERATOR_SETUP_CHECKLIST.md`). Every failure state a participant can reach has a plain-language message and an operator fix | READY **with operator conditions** (below) |
| Known limitations disclosed | `docs/OPERATOR_SETUP_CHECKLIST.md` section G and the lists below | DONE |

## Operator conditions that decide "no terminal"
1. **The model must already be installed.** The lab never downloads one; if it is absent the participant sees the first-run check with the exact command, but only an operator can run it.
2. **Splunk Web needs a login.** The investigation step opens Splunk; the lab admin session must be signed in beforehand in the browser profile used for the session (never typed in front of participants, never pasted into a page). This is the one item the earlier batches had not stated.
3. **The verifier is not supervised** (`docs/ops/VERIFIER_SUPERVISION.md`): if it dies the page says VERIFIER OFFLINE and an operator runs one command.
4. **Reset between participants** (new profile or the Reset control): progress lives in the browser.
5. AcmeBank keeps run history in memory: restarting it mid-session loses the on-page run (events stay in Splunk).

## What changed in this batch
- Original specimens of the eight REPLAY labs restored (`REPLAY_RESTORATION.md`).
- Four Attack UI serious contrast defects fixed (`ACCESSIBILITY_RESULTS.md`).
- `learner_ready.py`, the operator checklist and a verifier-supervision recommendation with a tested recovery table.
- A merge plan with scratch-clone simulations (`MERGE_PLAN.md`).
- The two images were redeployed (the contrast fix is a static file inside the Attack Service image): preflight 14 of 14, only those two containers recreated, Splunk, collector and Ollama untouched with identical ids and start times, volumes identical, rollback anchors tagged (`pre-batch7-*` = the previous images).

## Regression counts
| Measure | Count |
|---|---|
| Curriculum preservation, 31 entries | 24 PRESERVED, 7 ENHANCED, **0 REGRESSED**, **0 UNVERIFIED** (first Gate A report: 22 / 1 / 0 / 8) |
| Original learning files changed or removed | 0 of 31 labs (additions are specimen packs only) |
| Live launches differing from the baseline | 0 of 21 |
| Attack UI serious/critical axe violations | 0 (was 4) |
| Browser console errors / failed requests in the walks | 0 / 0 |
| Test suite | all passing (see the final report for the count) |

## Remaining blockers and risks (none blocks starting the pilot; the first three need your decision)
1. **Merge** into `develop` is pending your action; the plan is safe but the deployed lab still depends on `scripts/deploy_acmebank_attack.py` until the compose file is merged.
2. **Recruiting five participants**, including one keyboard-only or screen-reader user if possible, and a decision on who operates.
3. **Original September Splunk volume** (`0aa27f8fe380...`) is now the only complete copy of that index; back it up before any Docker cleanup.
4. The 25 to 40 minute estimate and every comprehension claim are unmeasured until the pilot runs.
5. Verifier supervision (recommendation: operator-run for the pilot), Windows/Linux hosts, first-ever Splunk boot timing on a cold image cache, and a restart of an existing Splunk with the Loan Desk view remain untested.
6. Pre-existing moderate axe `region` finding (skip link) on the 7 Attack UI lab pages.
7. Evidence for the LIVE labs' own specimen dropdowns (PI, RAG, MEMORY, GOAL, DELEGATION, CAPSTONE) still points at September runs that are not committed; recoverable from the same volume if you want them.
