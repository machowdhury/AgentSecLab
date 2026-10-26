# Loan Desk mission: start, run, troubleshoot

The mission has seven stages (Learn, Prepare, Attack, Investigate, Defend, Retest, Explain). They are separate from the six-step Workshop path and from the legacy L0–L10 curriculum; see [Getting started](GETTING_STARTED.md#three-numbering-schemes-do-not-mix-them-up). The Attack stage runs a live agent and is the only live part of the React Academy journey.

## Start (the documented procedure)
1. `cp .env.example .env` (first time), then `./scripts/lab-up.sh`. It starts the stack, waits for READY, and starts the host-side evidence verifier. A host Ollama must have `llama3.2:latest` installed (`ollama pull llama3.2:latest`); AcmeBank reaches it through `OLLAMA_BASE_URL`.
2. Open the React Academy at http://127.0.0.1:5001/learn and choose **Loan Desk Mission** (sidebar), or go straight to http://127.0.0.1:5001/learn/loan-desk. The original page is http://127.0.0.1:5001/academy. No further terminal commands are needed.
3. Work through the ten steps. At *Investigate* press **Verify with Splunk**.

Pause with `./scripts/lab-down.sh` (also stops the verifier; it stops containers and removes nothing).

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
- Verifier offline: `./scripts/loan_desk_verifier.sh status|start`; log at `~/.local/state/agentsec/loan_desk/verifier.log` (host-only; override with `AGENTSEC_VERIFIER_STATE_DIR`).
- Splunk view: `ws_lab_loandesk_001` (Foundations). Paste the run.id into *LIVE: your run.id*.
- Design and limits: `docs/reviews/batch4/VERIFICATION_BRIDGE.md`. Duplicate fields in Splunk: `docs/reviews/batch4/SEQUENCE_DUPLICATION.md`.
