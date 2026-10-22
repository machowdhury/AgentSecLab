# Loan Desk mission: start, run, troubleshoot

## Start (the documented procedure)
1. `cp .env.example .env` (first time), then `./scripts/lab-up.sh`. It starts the stack, waits for READY, and starts the host-side evidence verifier. A host Ollama must have `llama3.2:latest` installed (`ollama pull llama3.2:latest`); AcmeBank reaches it through `OLLAMA_BASE_URL`.
2. Open the Academy at http://127.0.0.1:5001/academy and choose **Loan Desk Mission** (sidebar or home page). No further terminal commands are needed.
3. Work through the ten steps. At *Investigate* press **Verify with Splunk**.

Stop with `./scripts/lab-down.sh` (also stops the verifier; volumes are kept).

## What each evidence state means
| State | Meaning |
|---|---|
| NOT VERIFIED | Only local evidence exists. The text says why (no verifier, not requested, ...). |
| VERIFYING | The host verifier is running its fixed searches. |
| SPLUNK-VERIFIED | Authenticated result: every local event is indexed, per-event counts and sequences identical. |
| SPLUNK MISMATCH / STALE | Indexing incomplete (try again) / the run changed since the check. |
| VERIFIER OFFLINE / TIMED OUT / VERIFICATION FAILED | The check could not complete. This is never shown as success. |

## Troubleshooting
- "The Loan Desk is not reachable": AcmeBank is down; `./scripts/lab-ready.sh`.
- "Model unavailable": `ollama list` on the host must show `llama3.2:latest`.
- Verifier offline: `./scripts/loan_desk_verifier.sh status|start`; log at `artifacts/loan_desk/verifier.log`.
- Splunk view: `ws_lab_loandesk_001` (Foundations). Paste the run.id into *LIVE: your run.id*.
- Design and limits: `docs/reviews/batch4/VERIFICATION_BRIDGE.md`. Duplicate fields in Splunk: `docs/reviews/batch4/SEQUENCE_DUPLICATION.md`.
