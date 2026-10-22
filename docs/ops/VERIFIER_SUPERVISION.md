# Host verifier supervision: recommendation and tested manual recovery

**Nothing in this document was installed.** No LaunchAgent, daemon, login item, cron entry or privileged helper exists or was created. The draft
`com.agentseclab.loan-desk-verifier.plist.draft` is a file in the repository, outside `~/Library/LaunchAgents`, and was only syntax-checked
(`plutil -lint`: OK). Installing it needs separate approval.

## What the verifier needs from a supervisor
It is a stdlib-only Python process that opens no port, runs as the user, writes only under `artifacts/loan_desk/receipts/` and a 0700 state
directory, and calls `docker exec` (so `docker` must be on its PATH). Since Batch 6 it is safe to restart at any time: an exclusive `flock` makes a
second instance exit, SIGTERM writes a `stopped` heartbeat, a crash leaves only a stale pidfile that the script ignores, and a bad request never kills it.

## Can a user-scoped service manager supervise it on this Mac? Yes, with caveats.
Checked read-only on this machine: `launchctl print gui/501` shows the user's `login` domain, so a per-user LaunchAgent is available; no AgentSec
agent is loaded; `~/Library/LaunchAgents` holds only Google updater files. A LaunchAgent would run as the logged-in user in that domain, with no root.

| Option | What it gives | Cost and risk |
|---|---|---|
| **A. Operator-run, no persistence (current).** `lab-up.sh` starts it; `lab-down.sh` stops it; `learner_ready.py` checks it; the manual recovery below fixes it | Zero new persistence; nothing runs when no session is planned | Does not survive a reboot, logout or crash; the operator must notice (the page shows VERIFIER OFFLINE and `learner_ready.py` fails) |
| **B. Per-user LaunchAgent (`gui/<uid>` domain)**, `KeepAlive: {SuccessfulExit: false}`, `ThrottleInterval 15`, `RunAtLoad` | Restarts after a crash and after login; no root; removable with one `launchctl bootout` | Persists until removed; starts at login even when no pilot is running; PATH must be set explicitly (below); launchd restarts a verifier whose Docker Desktop is not yet up, so it will answer `VERIFICATION_FAILED` until Docker is ready (safe, noisy) |
| C. LaunchDaemon (system domain) | Runs without login | **Rejected.** Needs root, runs outside the user's Docker context, wider blast radius, no benefit for a single-user lab |
| D. Wrapper loop in a terminal or tmux | No launchd | A visible terminal is exactly what operators forget; dies with the shell |

### Recommendation
1. **For the five-person pilot use option A.** The pilot is operator-led, sessions are scheduled, and `scripts/learner_ready.py` already checks the verifier before each participant. Nothing needs to persist between sessions.
2. **Revisit option B only if** the lab is left running for self-service use. If approved, install the draft with the three REPLACE values filled in, keep it per-user, and add `scripts/learner_ready.py` to the start-of-day routine.
3. Never option C.

### Details found while testing that matter for option B
- `docker` here is `~/.docker/bin/docker`, which is **not** on launchd's default PATH. The draft sets `PATH` to start with `REPLACE_HOME/.docker/bin`. Without it every verification would end in `VERIFICATION_FAILED` (it fails safe).
- Tested the exact command line the plist would run in a clean environment (`env -i` with only `HOME` and a PATH, scratch artifacts and state directories): the verifier started, wrote a fresh `running` heartbeat in 1.3 s, and on SIGTERM wrote `stopped` and exited cleanly.
- Homebrew's `python3` path is hard-coded in the plist; a Homebrew upgrade that changes it needs the plist edited.

## Manual recovery procedure (operator; every step below was exercised on the live lab or in scratch directories)
| Symptom (what the page or checker shows) | Cause | Fix | Evidence |
|---|---|---|---|
| Mission shows `VERIFIER OFFLINE`; `learner_ready.py` fails "host verifier process is running" | stopped, crashed, or machine rebooted | `./scripts/loan_desk_verifier.sh start`, then `python3 scripts/learner_ready.py` | Gate B: `kill -9`, status "not running", start, verification recovered |
| `loan_desk_verifier.sh status` says running but the heartbeat is stale | process hung | `./scripts/loan_desk_verifier.sh stop` then `start`. `stop` waits 10 s and never force-kills | Gate B stop/start; unit tests for the pid check |
| Pidfile points at another program (after a reboot) | stale pidfile | nothing to do: `status` and `stop` ignore it ("stale pidfile ignored") and never signal that pid | `tests/test_loan_desk_verifier_security.py` (unrelated `sleep` process survives) |
| Two verifiers started | double start | none needed: the second exits with "another verifier already holds the lock" | four concurrent starts leave one process |
| Page says "receipts directory is writable from this container" | containers recreated without the read-only mount | `python3 scripts/deploy_acmebank_attack.py deploy` (or merge the two mount lines) | Gate B compose and mounts |
| Verifier log shows `rejected request ...` | hostile or malformed request file | none: quarantined under `artifacts/loan_desk/rejected/` (50 max) | live adversarial run |
| Page says VERIFICATION_FAILED "FileNotFoundError" | `docker` not on the verifier's PATH (typical under launchd) | start the verifier from a shell that has `docker`, or fix `PATH` in the service definition | PATH finding above |
| Verification ends in `VERIFICATION_FAILED` (Splunk unreachable) or `SPLUNK MISMATCH` (events not yet indexed) | Splunk down, or the run was verified before indexing finished | confirm Splunk is healthy, wait a minute, press Verify again; the verifier waits up to 45 s per request for indexing before it reports | Batch 4 tests; `reconcile.wait_and_reconcile` |
Logs: `~/.local/state/agentsec/loan_desk/verifier.log`. State (key, lock, pid): `~/.local/state/agentsec/loan_desk/` (0700). To stop for the day: `./scripts/lab-down.sh` (also stops the verifier).
