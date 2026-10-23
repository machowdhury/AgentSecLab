# Operator setup checklist (pilot and workshop sessions)

Participants use **only a browser**. Everything on this page is done by the **operator**, who may use a terminal, before participants arrive.
Nothing here downloads a model for you or weakens certificate checks, and the lab never will.

**Running a session? Use `docs/PILOT_LAUNCH_CHECKLIST.md`**: the single per-session checklist (model warm-up, Splunk login, verifier, reset, evidence). This page is the one-time machine setup it assumes.

## A. One-time machine preparation (operator, terminal)
| # | Step | Check |
|---|---|---|
| A1 | Docker Desktop installed and running, 8 GB or more RAM given to Docker (12 GB recommended: Splunk uses about 3 GB) and 15 GB free disk | `docker info` answers |
| A2 | Clone the repository; `cp .env.example .env`; leave the lab defaults; never commit `.env` | `.env` exists, mode 0600 |
| A3 | **Model.** Ollama runs on this machine (host mode). Set `OLLAMA_BASE_URL=http://host.docker.internal:11434` in `.env`. Pull the mission model yourself: `ollama pull llama3.2:latest` | `ollama list` shows `llama3.2:latest` |
| A3a | If the pull fails with a certificate error (`x509: certificate signed by unknown authority`), the machine is behind TLS inspection. Use your organisation's approved certificate process (for example its trust-store procedure). **Do not** turn off verification, set insecure flags or pull through an unapproved proxy. If you cannot fix it, stop: the mission cannot run without the model | |
| A4 | Docker Desktop, Ollama and the lab start with the machine awake; disable sleep for the session | |
| A5 | Splunk Web login for the session browser profile: participants need to reach Splunk Web for the investigation step. Sign in once, as the lab admin from `.env`, in the browser profile that participants will use (the lab credential is local-only; never type it into a terminal in front of participants or paste it into any page) | the Splunk page loads without a login prompt |

## B. Starting the lab (operator, terminal, 10 to 20 minutes the first time)
1. `./scripts/lab-up.sh`. It creates the certificate, starts the services, waits for READY, starts the host verifier and seeds the scanner/garak REPLAY specimens. The first Splunk boot can take 10 to 20 minutes.
2. `python3 scripts/learner_ready.py`. It must print **READY for participants** (28 checks). It is read-only; every FAIL prints the exact operator fix. It checks:
   - Docker and the five services healthy;
   - the model as AcmeBank sees it (Ollama reachable, `llama3.2:latest` installed, digest);
   - Splunk Web, a searchable index, and that every recorded (REPLAY) specimen the 15 specimen labs offer is searchable;
   - the host verifier (process, fresh heartbeat, receipts mount read-only in both containers, no key reachable from a container);
   - Academy access: home, the Loan Desk mission with its objectives, the Attack UI pages, and that all 32 labs (31 original + Loan Desk) are discoverable.
3. Do not continue while any check fails. Common fixes: model missing, `ollama pull llama3.2:latest`; verifier offline, `./scripts/loan_desk_verifier.sh start`; specimens missing, `python3 scripts/seed_envelope_specimens.py` and the HEC init (`docker compose ... up splunk_hec_init`); both are additive and safe to repeat.

## C. Before each participant (operator, browser)
1. Close the previous participant's Academy tab, open a **new tab**, and press **Reset browser progress** on `/academy/path` (tested by `scripts/pilot_reset_check.py`). Mission answers live in the tab and the progress marker in the browser, so without this the next participant can see the previous one's progress. Do not rely on "Reset this mission": it sits in the final step, which a participant who stopped early cannot reach.
2. Open `http://127.0.0.1:5001/academy` and confirm the "Loan Desk mission" card and a green model line ("Model llama3.2:latest via Ollama ...").
3. Keep these tabs ready for the facilitator only: `http://127.0.0.1:8000` (Splunk), `http://127.0.0.1:5001/labs/LAB-PI-001`.
4. Hand over the browser. The participant needs no terminal at any point.

## D. Where each mission step happens (all in the browser)
Understand, Explore, Predict, Attack, Observe: the Academy mission page. Investigate: the mission page plus Splunk Web (an "Open in Splunk" link per search) and the page's **Verify with Splunk** button (answered by the host verifier). Defend, Retest, Compare, Explain: the mission page.

## E. If something goes wrong during a session (operator fixes; participants wait)
| The page shows | Do |
|---|---|
| "Model unavailable" or the First-run check says Not ready | A3 / A3a, then press **Check again** |
| VERIFIER OFFLINE | `./scripts/loan_desk_verifier.sh start`; see `docs/ops/VERIFIER_SUPERVISION.md` |
| "receipts directory is writable from this container" | `python3 scripts/deploy_acmebank_attack.py deploy` (operator, between participants) |
| SPLUNK MISMATCH right after a run | events are still being indexed: wait a minute and press Verify again |
| A hardened run ends INCOMPLETE ("attack blocked, review not finished") | expected sometimes: the page explains it; it is a usability cost, not a control failure |
| An Attack UI lab page returns an error page | run `learner_ready.py`; a 500 means the Attack Service image is not the current one |

## F. After the session
To pause the lab: `./scripts/loan_desk_verifier.sh stop`, then `docker compose -f docker-compose.yml -f docker-compose.local.yml --profile local --env-file .env stop`. **Do not use `./scripts/lab-down.sh` from a checkout that predates the named-volume change if you want to keep the Splunk data:** it runs `down`, and the next `lab-up.sh` starts Splunk with new empty data volumes (see `docs/ops/SPLUNK_VOLUME_MIGRATION.md`). Delete recordings per the consent terms.

## G. Known limitations to tell participants up front
- A real small model (3B) drives the agent, so runs vary; the hardened run sometimes does not finish the review.
- "SPLUNK-VERIFIED" means the events AcmeBank recorded are the events Splunk indexed; it does not prove the events are true.
- Original REPLAY labs show recorded evidence from 2026-09 and are labelled REPLAY, not live runs.
- AcmeBank keeps run details in memory; restarting it loses the on-page run history (the events stay in Splunk).
- Estimated time (25 to 40 minutes) is an author estimate, not yet measured with learners.
- This is a learning lab with synthetic data; nothing here is production authentication.
