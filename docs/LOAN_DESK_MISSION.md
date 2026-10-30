# Loan Desk mission: start, run, troubleshoot

The mission has seven stages (Learn, Prepare, Attack, Investigate, Defend, Retest, Explain). They are separate from the six-step Workshop path and from the legacy L0–L10 curriculum; see [Getting started](GETTING_STARTED.md#three-numbering-schemes-do-not-mix-them-up). The mission appears on the same stage rail as the other LIVE workshops (Prepare covers Predict and Baseline). The Attack stage runs a live agent against the local model.

## Start (the documented procedure)
1. Install and start the lab with the installer (`./agentsec ... install`, then `./agentsec status`; see the [installation guide](INSTALLATION_AND_DEPLOYMENT.md)). The installer pulls `llama3.2:latest` with the bundled Ollama; with a host Ollama run `ollama pull llama3.2:latest` yourself. AcmeBank reaches Ollama through `OLLAMA_BASE_URL`.
2. Open the React Academy at `https://localhost/learn` and choose **Loan Desk Mission** (sidebar), or go straight to `https://localhost/learn/loan-desk`. Sign in as `operator` to launch. No further terminal commands are needed.
3. Work through the ten steps. At **Investigate** you press **Run** on each notebook cell: the Attack Service runs an approved, fixed-template search against Splunk and the Academy shows the rows, a chart and a plain-language reading. If search access is not provisioned the notebook says so and fails closed; the host owner runs `./agentsec splunk-access` (check with `./agentsec splunk-access --check`). Splunk Web is an optional Advanced view, never a required step. The notebook was validated on one real Splunk 10.2.7 host (bundled Splunk, 2026-10-30); it was not validated against an external Splunk, Splunk Cloud or an organization certificate.

Pause with `./agentsec down` (it keeps your data). The legacy `lab-up.sh` flow (pause with `./scripts/lab-down.sh`, which stops containers and removes nothing; Loan Desk at http://127.0.0.1:5001/learn/loan-desk) is described in [the legacy multi-port flow](LEGACY_MULTI_PORT_FLOW.md) and is not the supported path.

## Which model the Loan Desk uses, and why it is not the 1b model
The Loan Desk has its own model setting (`LOANDESK_MODEL`, default `llama3.2:latest`, the 3B build) separate from the AcmeBank labs (`OLLAMA_MODEL`, default `llama3.2:1b`). It does **not** reuse the 1b model because that model cannot reliably finish the Loan Desk's tool loop. Measured 2026-10-29 against a host Ollama with the repository's own whole-loop harness (`scripts/bench_agent_loop.py`, real inference, nothing downloaded): `llama3.2:1b` completed **0 of 5** benign runs (stops: step budget exhausted, invalid proposal limit; its tool arguments were rejected), while `llama3.2:latest` completed **4 of 4**. The earlier Batch 2 measurement had the 1b model at 9 of 10; small samples and a newer Ollama differ, and the 1b figure is not stable. You can still point the Loan Desk at another installed model with `LOANDESK_MODEL` (or `models.loan_desk` in the installer configuration); nothing is substituted silently, and a missing model is reported with its pull command.

What the installer does about it: with the **bundled** Ollama, `agentsec install --apply` now pulls both models (`scripts/ollama_init.sh` pulls `LOANDESK_MODEL` when it is set and different), so the plan's "Download on --apply" line is true. With a **host** Ollama the installer pulls nothing and lists no download: run `ollama pull llama3.2:latest` yourself (the Academy status shows the command). The legacy `lab-up.sh` flow never sets `LOANDESK_MODEL`, so it is unchanged. This adds about 2 GB to a clean bundled install. Not yet run on a clean host since the change.

## What each evidence state means
| State | Meaning |
|---|---|
By default a Loan Desk run is **NOT VERIFIED**: the older host-side verifier below is legacy, off by default (`AGENTSEC_LEGACY_HOST_VERIFIER=1` enables it) and ignored behind the gateway, so no default run is Splunk-VERIFIED. The Investigate notebook shows rows as evidence of what Splunk returned; it does not turn a run into SPLUNK-VERIFIED.

| State | Meaning |
|---|---|
| NOT VERIFIED | Only local evidence exists. The text says why (no verifier, not requested, ...). |
| VERIFYING | The legacy host verifier is running its fixed searches. |
| SPLUNK-VERIFIED | Legacy verifier only: every local event is indexed, per-event counts and sequences identical. |
| SPLUNK MISMATCH / STALE | Indexing incomplete (try again) / the run changed since the check. |
| VERIFIER OFFLINE / TIMED OUT / VERIFICATION FAILED | The check could not complete. This is never shown as success. |

## Troubleshooting
- "The Loan Desk is not reachable": AcmeBank is down; run `./agentsec status`.
- "Model unavailable": `ollama list` on the host must show `llama3.2:latest`.
- Notebook says search access is not provisioned: `./agentsec splunk-access`, then `./agentsec splunk-access --check`.
- Legacy verifier only (not the supported path): `./scripts/loan_desk_verifier.sh status|start`; log at `~/.local/state/agentsec/loan_desk/verifier.log` (host-only; override with `AGENTSEC_VERIFIER_STATE_DIR`).
- Optional Advanced view: the Splunk dashboard `ws_lab_loandesk_001` (Foundations) on the host's loopback Splunk Web.
- Design and limits: an internal record (not published). Duplicate fields in Splunk: an internal record (not published).
