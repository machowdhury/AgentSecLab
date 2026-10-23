# Pilot launch checklist (operator: run this before EVERY learner session)

**Pilot package (runbook, log, scoring, questionnaire, results, success criteria): `docs/pilot/README.md`. Splunk sign-in without exposing the credential: `docs/pilot/SPLUNK_LOGIN_PROCEDURE.md`.**

Run from the repository root on the lab machine. The participant touches only the browser, never a terminal.
Every step has a pass condition. **Any step that fails is a NO-GO: fix it with the pointer given, or stop the session.** Nothing here
downloads a model, weakens TLS, restarts Splunk, or deletes anything.
Allow 10 minutes. First-ever start of the lab (cold image cache) is a separate procedure: `docs/OPERATOR_SETUP_CHECKLIST.md` sections A and B.

| # | Step | Do | Pass condition | If it fails |
|---|---|---|---|---|
| 1 | Machine | Mac awake, on power, Docker Desktop running, sleep disabled for the session | `docker info` answers | start Docker Desktop and wait for it |
| 2 | Whole-lab check | `python3 scripts/learner_ready.py` | last line `READY for participants: 28/28 checks passed`. It covers the five services, the model, Splunk, **all 15 specimen labs' recorded runs searchable**, the verifier (process, heartbeat, read-only receipts mounts, no key reachable) and all 32 labs reachable | each FAIL line prints its own operator fix; do not continue on any FAIL |
| 3 | Model readiness | `ollama list` shows `llama3.2:latest` (digest `a80c4f17acd5`). **Warm it up within 5 minutes of hand-over:** `ollama run llama3.2:latest "Reply with OK"` then `ollama ps` shows it loaded. (Ollama unloads an idle model after about 5 minutes; without the warm-up the first participant's first run pays the load time.) | model listed and loaded | if absent, an operator pulls it (`ollama pull llama3.2:latest`); on a certificate error use your organisation's approved certificate process and **never** disable verification; if it cannot be fixed, the mission cannot run: cancel the session |
| 4 | Splunk login | In the **participant's browser profile**, open `http://127.0.0.1:8000/en-US/app/agentsec/ws_lab_loandesk_001`. Sign in once as the lab admin using `docs/pilot/SPLUNK_LOGIN_PROCEDURE.md` (clipboard only, never displayed, never in front of participants, never into a lab page) | the Loan Desk view loads with no login prompt | sign in; if the app is missing run `learner_ready.py` and read the Splunk section |
| 5 | Verifier health | `./scripts/loan_desk_verifier.sh status` | `running (pid N)` and `learner_ready.py` step 2 reported a fresh heartbeat | `./scripts/loan_desk_verifier.sh start`, then repeat step 2. Recovery table: `docs/ops/VERIFIER_SUPERVISION.md` |
| 6 | Browser profile reset | Close every Academy tab from the previous participant and open a **new tab**. Open `http://127.0.0.1:5001/academy/path` and press **Reset browser progress**. Leave the Splunk tab signed in | every progress label on the path page reads "Not started"; `http://127.0.0.1:5001/academy/missions/loan-desk` opens at **Understand** with no prediction selected | see "Why this reset works" below |
| 7 | Evidence check | `python3 scripts/learner_ready.py` already proved the recorded runs are searchable. Also confirm the mission page's first step shows "Model llama3.2:latest installed: Ready". The verifier has no standing status line on the page: it is covered by steps 2 and 5, and a participant would only see VERIFIER OFFLINE after pressing "Verify with Splunk" | the model line reads Ready | model line not Ready: step 3; anything verifier-related: step 5 |
| 8 | Hand over | Put the participant on the mission page. Read them the disclosures below. Start the screen recording only with their consent | | |

## Why the reset works (tested)
- The mission's answers and run ids live in the browser **tab** (`sessionStorage`): closing the tab discards them. The only thing that
  outlives a tab is the progress marker on the path page, which **Reset browser progress** clears. `scripts/pilot_reset_check.py`
  drives the real UI to prove it (locked prediction, close tab, new tab, reset): nothing of the participant remains and the mission reopens at Understand.
- Splunk's login is a separate site origin (port 8000), so the reset does not sign Splunk out.
- "Reset this mission" is inside the final step, which a participant who stopped early cannot reach (steps unlock in order). **Use step 6, not that button.**
- Nothing in the lab changes: no run, no evidence and no Splunk data is removed by a reset.

## Disclose to every participant before they start
1. A real small model (3B) drives the agent, so results vary; the hardened run sometimes does not finish the loan review.
2. SPLUNK-VERIFIED means the events AcmeBank recorded are the events Splunk indexed. It does not prove the events are true.
3. The recorded runs in older labs are labelled REPLAY: they show evidence captured in September, not a live run.
4. The 25 to 40 minute estimate is not measured yet; you are helping measure it.
5. Synthetic data only. Nothing here is production authentication.

## While the session runs (operator, not the participant)
| Page shows | Do |
|---|---|
| VERIFIER OFFLINE | step 5 |
| Model unavailable / First-run check "Not ready" | step 3, then **Check again** |
| SPLUNK MISMATCH right after a run | wait a minute and press Verify again (indexing delay) |
| "receipts directory is writable from this container" | stop the session; between participants run `python3 scripts/deploy_acmebank_attack.py deploy` |
| Hardened run ends INCOMPLETE | expected sometimes; the page explains it |
| Page stuck / error | note the time and the run id on the page; do not restart AcmeBank mid-session (it keeps run history in memory) |

## After the session
1. Write down the attack and retest run ids shown on the page (they stay in Splunk; `index=agentsec_telemetry "agentsec.run.id"="<id>"`).
2. Close the participant's tab. Do not stop the lab between sessions on the same day.
3. At the end of the day only: `./scripts/lab-down.sh` (stops the verifier too, never removes volumes).
4. Delete recordings per the consent terms.
