# Evidence verification bridge (Loan Desk)

**Goal.** Let the learner press *Verify with Splunk* and get an honest answer, without enabling the management REST probe, exposing Splunk credentials, mounting the Docker socket, or adding a host endpoint.

## Flow
1. Browser -> Attack Service `POST /api/missions/loan-desk/runs/<id>/verify` (only for runs that service launched) -> AcmeBank `POST /api/v1/loan-desk/runs/<id>/verify`.
2. AcmeBank writes `artifacts/loan_desk/requests/<run_id>.json`, HMAC-signed with `artifacts/loan_desk/.bridge.key`, rate limited (1 per 10 s per run, 120 per hour).
3. The **host verifier** (`scripts/loan_desk_verifier.sh`, started by `lab-up.sh`, stopped by `lab-down.sh`) polls that directory every 2 s. For each request it checks: the MAC, file name = `run_id` = a lowercase UUID, age 0-600 s, nonce unseen, at most 30 searches a minute. It then fetches **that run's own events** from AcmeBank (run-ID binding: an unknown run is reported as `unknown_run`), and runs the fixed searches in `loan_desk/reconcile.py` through the existing `docker exec ... splunk search` mechanism (read-only; `earliest=-24h`; `-maxout 500`; run id validated as a UUID before substitution).
4. It writes `<run_id>.splunk.json`, signed, containing the request's nonce.
5. AcmeBank shows `SPLUNK_VERIFIED` only if: key present, result MAC valid, `run_id` matches, nonce equals the latest authentic request, `reconciled` is true, no error, and the local event count still matches. Otherwise one of NOT_VERIFIED, PENDING, VERIFIER_OFFLINE, TIMED_OUT, VERIFICATION_FAILED, INVALID_RECORD, SPLUNK_MISMATCH, STALE, each with its own text.

## Requirement check
| Requirement | How it is met |
|---|---|
| Browser never receives Splunk credentials | No Splunk credential exists outside the Splunk container. `SPLUNK_PASSWORD` is expanded by the shell inside `docker exec` and never read by Python (tested). Views and API responses never contain the key, nonce or MAC (tested). |
| Run-ID binding | Request is signed over `run_id`; file name, content and result must agree; the verifier verifies the run's own AcmeBank events; searches embed only a validated UUID. |
| Least privilege | Verifier runs as the host user with docker access (same as `lab-up.sh`); it can only run the fixed read-only searches; no write path to Splunk; no network listener. |
| Bounded queries | Fixed templates, 24 h window, row cap, 45 s budget per run, 30 searches/minute, request age cap. |
| Authentication | HMAC-SHA256 on requests, results and the heartbeat; unauthenticated or replayed files are ignored (tested: forged, wrong key, stale nonce, other run id). |
| Safe failure | Any exception, Splunk outage, missing key, offline verifier, unknown run or timeout produces an explicit non-verified state. Success requires `reconciled: true` and no error. |
| No new unauthenticated host endpoint / no Docker socket | File hand-off through the existing `./artifacts` bind mount only. `docker-compose.yml` is unchanged and contains no socket mount (tested). |

## Limits (honest)
- The key sits in the shared directory (mode 0644 so the container user can read it on a bind mount). It prevents forgery by anything that cannot read the directory (the model, tools, browsers). A process that can read and write `artifacts/` can forge a verification record. Anyone with that access already controls the lab's evidence files.
- Needs a host with `python3` and `docker`. Without them the page says NOT VERIFIED and why; the learner can still confirm with the Splunk searches.
- The learner-entered count in the mission is learner-reported, not verification.
- Not tested on Windows hosts.
