# AGENTSEC GUIDED-LEARNING EXTERNAL PILOT REMEDIATION

Evidence classes stay separate. A passing test is not a Splunk-hosted render. HEC health is not indexed evidence. A listed model is not generation quality.

Starting point: `develop` at `5706cbff625eea66919f5177ff47782b8f8c5233`. `main` and `origin/main` were `0178c70e20cfe0152648e2aafb8e607280625c40`. Schema, ExternalEvidence, DET-MCP-001, and CTRL-MCP-001 were not edited.

Independent pilot baseline: CONDITIONAL PASS — REMEDIATION REQUIRED BEFORE RELEASE.

## HIGH-1 Your Path

Root cause: `agentsec_learner_path.js` registered `DOMContentLoaded` and did nothing if that event had already fired. Splunk dashboard scripts can load after the document is ready, so the curriculum was never drawn. The reset control also shadowed the `reset` function with the button variable, so a click could not clear progress.

Fix: `mount()` runs immediately when `document.readyState` is not `"loading"`, and registers the listener otherwise. A second call sees `data-agentsec-mounted` and returns. The reset button calls the progress `reset` function.

Node tests cover both lifecycle orders, a second mount, a fresh learner, reload of stored progress, and reset. Headless Chrome loaded a local page that injected the script from a `DOMContentLoaded` handler. The dumped DOM contained `Direct Prompt Injection`, `NOT STARTED`, `agentsec-progress-tally`, and `Reset learning progress`. That page was not Splunk.

After `fe67ebb` was fast-forwarded on EC2, `./scripts/lab-up.sh --build --refresh-app --remote` exited 0. The Your Path script SHA-256 in the running Splunk app matched the checkout (`fb80a104fc20016380896e1b2a57e62bc6d0d6f962aff88fd623ee268c86f143`). An authenticated request to `http://127.0.0.1:8000/en-US/app/agentsec/learner_path` returned HTTP 200, 8100 bytes, with `agentsec_learner_path.js` referenced and `Page not found` absent. The curriculum strings were not in that HTML. They are drawn by the script in the browser. EC2 has no browser, so the Splunk-hosted paint was not measured.

Status: FIXED — INDEPENDENT RE-VERIFICATION REQUIRED for the Splunk-hosted paint.

## HIGH-2 Attack Service navigation

Root cause: every root-relative URL on a non-8000 page was rewritten to port 8000. `/` and `/labs/...` are Attack Service routes. `/en-US/...` is Academy and Search. The rewrite sent the lab switcher and NEXT LAB to Splunk, which has no such view.

Fix: only `/en-US/` paths move to port 8000 on the hostname already in the address bar. Attack Service paths stay relative. Loopback absolute URLs still take the page hostname and keep their port. No learner URL is hardcoded to a cloud address.

Python and the browser script were both tested for local `127.0.0.1`, a documentation hostname, and `203.0.113.10`.

On EC2 after the same refresh, `http://127.0.0.1:5001/` returned HTTP 200. The HTML contained `/labs/LAB-MCP-001` and `/en-US/app/agentsec/ws_agentsec_home`. It did not contain `:8000/labs/` or `127.0.0.1:8000`. The Attack Service copy of `agentsec-ui.js` matched the checkout SHA-256 `d5f2b804b53d424093c50650a761c79260799b5aec6d6ac9940959a9c9ee6dc7`. A browser click of the switcher on the public host was not measured.

Status: FIXED — INDEPENDENT RE-VERIFICATION REQUIRED for a browser click on the public host.

## HIGH-3 REPLAY evidence

`lab-up` and `--refresh-app` copy the app and start services. They do not post otel events. The example canonical id `51f70fb9-994e-4dd4-9b36-cac6fb1e8232` is in the RAG workshop. Its event body is not in the repository. `artifacts/` is gitignored and that pack is not in the workspace. Scanner packs under `docs/phase9b-evidence` are sourcetype `agentsec:scanner:finding`. They are not these run.ids.

EC2 Splunk Search, OBSERVED before this remediation was deployed:

`index=agentsec_telemetry earliest=0 "agentsec.run.id"="51f70fb9-994e-4dd4-9b36-cac6fb1e8232" | stats count`

CSV result: `count` `0`.

No reseed was added. Inventing the historical events would fabricate evidence. There is no supported recovery command that restores that run.id. Do not delete the Splunk volume. A fresh LIVE launch is a different id.

FIXTURE EXISTS: NO for the otel canonical pack. YES for the scanner packs, which are a different sourcetype.
SEED EXECUTED: NO.
INDEXED EVIDENCE PROVEN: NO. The search returned zero.

Status: ENVIRONMENT / DEPLOYMENT LIMITATION. NOT REMEDIATED as product logic.

## MEDIUM-4 Session history

`learnerRunState` labeled `completed_allowed` plus `WAITING_FOR_EVIDENCE` as `RUN IN PROGRESS` while the same row printed `launcher terminal=completed_allowed`.

A terminal launcher result is now `RUN COMPLETED` or `RUN DENIED`. The evidence field stays on its own line and is labeled not a Splunk verdict. `run_failed` is `RUN FAILED`. No terminal is `RUN IN PROGRESS`. Completion text says it is not proof the attack succeeded. Reload rehydration recomputes the label from the launcher record.

Status: FIXED — INDEPENDENT RE-VERIFICATION REQUIRED on a live ATTACK and RETEST history row.

## MEDIUM-5 Evidence readiness

The probe runs `docker exec` into `agentsec_splunk`. The Attack Service container does not have Docker. `docker_not_available` left `splunk_count` unset. A one-shot check (`timeout_seconds=0`) then set `evidence_timeout`, and the button painted `RUN TIMED OUT`. That is a probe that cannot execute, not a measured absence of events.

A probe error in `docker_not_available` now stops immediately, sets `EVIDENCE_CHECK_UNAVAILABLE`, and does not set `evidence_timeout`. A successful probe with count 0 is `WAITING_FOR_EVIDENCE` (`WAITING FOR INDEXING`). A wait that expires on count 0 is `CHECK TIMED OUT`. Count at least 1 is `EVIDENCE CONFIRMED` (`evidence_state=EVIDENCE_READY`). The Docker socket was not mounted. TLS verification was not disabled. No fresh ATTACK or RETEST was launched in this pass, so this was not compared with a new Splunk Search.

Status: FIXED — INDEPENDENT RE-VERIFICATION REQUIRED against a fresh run.id and Splunk Search.

## MEDIUM-6 Troubleshooting

`docs/TROUBLESHOOTING.md` now covers a blank Your Path, the expected list, reload, the reset button, a canonical REPLAY id with zero rows, and the four evidence-check words. It does not tell the learner to edit browser storage or to treat the old blank page as normal.

Status: FIXED in the docs. The Splunk page those words describe still needs the independent check in HIGH-1.

## LOW-7

TRUE BROWSER 200% ZOOM: NOT MEASURED. CSS zoom was not used as a substitute.

## LOW-8

SCREEN READER: NOT TESTED.

## Regression and boundaries

Guided navigation files were not edited. Schema `1.9.0`, ExternalEvidence `1.0.0`, DET-MCP-001 `disabled = 1`, and CTRL-MCP-001 were not in the diff.

Offline suite: `1100 passed, 3 deselected`, process exit 0, 8.55s. The same focused progress, session, navigation, and readiness tests were repeated five times, each process exit 0.

No `.env`, key, certificate, token, Docker socket, or privileged container was added.

## EC2 update after this commit

On the existing checkout, as `ubuntu`, without deleting volumes:

```sh
git fetch origin --tags --prune
git checkout develop
git merge --ff-only origin/develop
./scripts/precheck.sh --remote
./scripts/lab-up.sh --build --refresh-app --remote
```

There is no extra reseed step. `lab-ready` does not prove a canonical REPLAY id is searchable.
