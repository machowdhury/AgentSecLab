# Loan Desk mission: start, run, troubleshoot

The mission has seven stages (Learn, Prepare, Attack, Investigate, Defend, Retest, Explain). They are separate from the six-step Workshop path and from the legacy L0–L10 curriculum; see [Getting started](GETTING_STARTED.md#three-numbering-schemes-do-not-mix-them-up). The Attack stage runs a live agent and is the only live part of the React Academy journey.

## Start (the documented procedure)
1. `cp .env.example .env` (first time), then `./scripts/lab-up.sh`. It starts the stack, waits for READY, and starts the host-side evidence verifier. A host Ollama must have `llama3.2:latest` installed (`ollama pull llama3.2:latest`); AcmeBank reaches it through `OLLAMA_BASE_URL`.
2. Open the React Academy at http://127.0.0.1:5001/learn and choose **Loan Desk Mission** (sidebar), or go straight to http://127.0.0.1:5001/learn/loan-desk. The original page is http://127.0.0.1:5001/academy. No further terminal commands are needed.
3. Work through the ten steps. At *Investigate* press **Verify with Splunk**.

Pause with `./scripts/lab-down.sh` (also stops the verifier; it stops containers and removes nothing).

## Which model the Loan Desk uses, and why it is not the 1b model
The Loan Desk has its own model setting (`LOANDESK_MODEL`, default `llama3.2:latest`, the 3B build) separate from the AcmeBank labs (`OLLAMA_MODEL`, default `llama3.2:1b`). It does **not** reuse the 1b model because that model cannot reliably finish the Loan Desk's tool loop. Measured 2026-10-29 against a host Ollama with the repository's own whole-loop harness (`scripts/bench_agent_loop.py`, real inference, nothing downloaded): `llama3.2:1b` completed **0 of 5** benign runs (stops: step budget exhausted, invalid proposal limit; its tool arguments were rejected), while `llama3.2:latest` completed **4 of 4**. The earlier Batch 2 measurement had the 1b model at 9 of 10; small samples and a newer Ollama differ, and the 1b figure is not stable. You can still point the Loan Desk at another installed model with `LOANDESK_MODEL` (or `models.loan_desk` in the installer configuration); nothing is substituted silently, and a missing model is reported with its pull command.

What the installer does about it: with the **bundled** Ollama, `agentsec install --apply` now pulls both models (`scripts/ollama_init.sh` pulls `LOANDESK_MODEL` when it is set and different), so the plan's "Download on --apply" line is true. With a **host** Ollama the installer pulls nothing and lists no download: run `ollama pull llama3.2:latest` yourself (the Academy status shows the command). The legacy `lab-up.sh` flow never sets `LOANDESK_MODEL`, so it is unchanged. This adds about 2 GB to a clean bundled install. Not yet run on a clean host since the change.

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
- Design and limits: an unpublished internal record. Duplicate fields in Splunk: an unpublished internal record.
