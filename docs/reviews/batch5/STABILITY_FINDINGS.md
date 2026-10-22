# Batch 5, Priority 3: stability findings

Scope: investigate the remaining Batch 4 risks without changing infrastructure. Nothing here applied a `KV_MODE`
change, restarted Splunk, merged, or touched the develop working tree. All Splunk searches were read-only.
Scratch directories were used for every verifier experiment; the verifier running on this Mac (pid in the lab's
`artifacts/loan_desk/`) was not stopped or restarted.

## 1. KV_MODE compatibility (proposed change: `KV_MODE = none` for `otel:agentic:json`)

**Method.** Splunk configuration cannot be changed, so the change is emulated per search: run the search as-is, then
run it again with every field de-duplicated immediately after the base search (`| foreach * [eval <<FIELD>>=mvdedup(...)]`).
That is exactly what removing the duplicate search-time extraction does to the 37 fields that have two copies. It
over-corrects the 10 fields that have three copies to one copy, so the emulation is an approximation, not a proof.
Searches that begin with `makeresults` generate their own rows and are independent of extraction. Scripts:
`scripts/spl_compat_unbound.py`, `scripts/spl_compat_dashboards.py`. Results: `kvmode_unbound.json`, `kvmode_dashboards.json`.

**Results**

| Population | Count | Identical | Different | Not informative |
|---|---|---|---|---|
| Run-bound hunts (Batch 4, real run ids) | 92 executions | 92 | 0 | |
| **Unbound hunts** (`learning/level_1/*/searches`, no run placeholder) | **49** | 47 | **2** | 18 returned zero rows here, so "identical" proves nothing for them (29 informative) |
| **Dashboard panel searches** (393 across the lab views and Academy home) | 393 | 388 already wrap fields in `mvdedup`/`mvindex` (static) | | 24 carry a count/group/dc construct and were executed: 11 identical with rows, 12 zero rows, **1 different** |

**The three differences are the same lab:** `LAB-SPLUNK-DEFENDER-BRIDGE` (`Q-BRIDGE-DUPLICATES`, `Q-BRIDGE-FIELDS`, and
its dashboard panel `ds_dup`). That lab exists to show learners the duplicated values (`mvcount`, `dc`, `fieldsummary`).
Removing the duplicates would change the numbers its lesson tells the learner to expect. Every other search either
already de-duplicates or is unaffected. One false alarm was found and fixed in the harness: five searches that start
with `makeresults` (positive controls) looked different because the emulation prefix was inserted before the generator;
they generate their own rows and are independent of extraction.

**Limits of this evidence.** (1) Emulation, not the real config. (2) 369 of 393 panel searches were classified
statically (they already de-duplicate) and not executed. (3) Panel searches that depend on tokens were run with
the token set to the latest Loan Desk run id or `*`, which is not what a learner's token would be. (4) Saved searches,
alerts and accelerations were not examined. (5) Nothing tests the index-time side.

**Verdict: do not apply yet.** Searches are insensitive except in the lab that teaches the duplication; and the
emulation cannot test cold-start index-time behaviour, saved-search acceleration, or any dashboard that was not
executed. Applying it also changes the numbers a learner of LAB-SPLUNK-DEFENDER-BRIDGE is told to expect. The
earlier run-bound result (92 executions, 0 differences, Batch 4) still stands. Safe path if you decide to apply:
(a) scratch Splunk or a copy of `props.conf` on a disposable volume, (b) rerun both scripts against the real
config instead of the emulation, (c) update the two sensitive searches' lesson text in the same change.

## 2. Verification bridge: trust boundary and key permissions

**What the bridge guarantees (tested):** an unauthenticated, wrongly keyed, mismatched-run, expired or replayed
record is never shown as verified (`test_loan_desk_bridge.py`, plus the probes below). The browser and the containers
never hold a Splunk credential; Splunk searches run on the host through `docker exec` and are fixed read-only templates
bounded by a run UUID.

**Probes run in a scratch directory (not the live one):**

| Probe | Result |
|---|---|
| Result signed with the wrong key | `INVALID_RECORD`, never verified |
| Result signed with the **right** key for a run that never existed | **`SPLUNK_VERIFIED`** |
| Signed request with `requested_at="abc"`, `null`, or missing `nonce` | `process_once` raises (ValueError/TypeError/KeyError) |
| Request path is a symlink to a validly signed file elsewhere | Followed and answered |
| 50 MB binary file as a request | Ignored in 0.0 s (read fails closed) |

**Findings**

- **B5-T1 (Medium, by design, must be stated plainly).** The signing key lives in the shared `artifacts/loan_desk/`
  mount, mode `0644`, owned by the container user (uid 1000), and the AcmeBank container both reads it and can write
  there. Anything that can run code inside AcmeBank or Attack Service can write a signed `SPLUNK_VERIFIED` for any run
  id. The bridge therefore protects against **learners, browsers, the model and its tools**, not against **code execution
  in a lab container**. In this lab a compromised AcmeBank is also the thing being verified, so the verification is
  honest evidence of "Splunk holds the events AcmeBank reported", not evidence that AcmeBank is uncompromised.
  Verified directly: `docker exec agentsec_acmebank` shows the key `644 1000` at `/app/artifacts/loan_desk/.bridge.key`.
- **B5-T2 (Medium, availability).** A signed request with a malformed field crashes the verifier loop (see B5-V1).
  Only a key holder can create one, so this is the same trust boundary, but the failure is silent and permanent
  (heartbeat goes stale; the page then says the verifier is offline, which is true but unhelpful).
- **B5-T3 (Low).** Symlinked request files are followed. Only someone with write access to `artifacts/` can plant one.
- **B5-T4 (Low).** The key is `0644` on a macOS host, so any local user who can traverse the repository path can read
  it. On a shared workstation use `0600` and a group, or run the lab on a single-user machine. Container reads depend on
  the 0644 mode because the bind-mounted uid must match; a Linux host with different uids needs a deliberate choice.
- **B5-T5 (Low).** The verifier's in-memory `seen` nonce map grows without bound for the life of the process.
- Residual (documented in Batch 4, unchanged): the key is a shared secret. A stronger design signs results with a
  host-only key and gives AcmeBank the public half (asymmetric), so a compromised container could check but not forge.
  That is a design change, so it is a recommendation, not a fix, in this batch.

## 3. Background verifier lifecycle

Tested with `scripts/loan_desk_verifier.sh` against a scratch `AGENTSEC_ARTIFACTS_HOST_DIR`.

| Scenario | Result |
|---|---|
| `start`, `status`, `stop` | Works. Heartbeat file written within 2 s |
| `start` twice | Second reports "already running"; one process |
| `SIGTERM` | Exits immediately; no handler needed (writes are replace-based so no half files) |
| `kill -9`, then `status`, then `start` | `status` reports not running; restart works; stale pidfile does not block it |
| Concurrent `start & start` | **Two verifiers launched**; both write `verifier.json.tmp`; one dies with `FileNotFoundError` on `os.replace` and leaves a traceback in the log |
| Pidfile holds the pid of an unrelated live process | `status` says **running**; `stop` **kills that unrelated process** |
| Survives login-shell exit | Yes (`nohup`). Does **not** survive reboot, sleep-induced network change, or `docker` restart; nothing supervises it |
| `lab-down.sh` | Calls `stop`; with a verifier started outside `lab-up.sh` it still stops by pidfile |
| Runs on the host's stock Python | Imports and runs on macOS `/usr/bin/python3` 3.9.6 and Homebrew 3.15 using only the standard library |

**Findings**
- **B5-V1 (Medium).** Any unexpected exception in `process_once` or `heartbeat` ends the loop; there is no per-request
  `try/except`, no restart, no logging beyond the traceback. Fails safe (page shows verifier offline) but never recovers.
- **B5-V2 (Low).** Symlink request followed (see B5-T3).
- **B5-V3 (Low, real).** Two writers share one `.tmp` name (also true of the heartbeat vs. a second verifier); the crash
  above was reproduced, not hypothetical.
- **B5-V4 (Medium, safety).** `stop` and `alive` trust the pidfile and `kill -0`, so after a reboot or a crash the
  pid may belong to an unrelated user process and `lab-down.sh` will terminate it. Reproduced with a `sleep` victim.
  Mitigation when fixing: verify the process command line contains `loan_desk_verifier.py` before signalling.
- **B5-V5 (Low).** Starting requires `docker` on PATH (otherwise prints "stays NOT VERIFIED" and exits 0, which is honest).

All of B5-V1…V4 are pinned as strict xfail tests in `tests/test_loan_desk_stability_probes.py` (6 cases): the suite
stays green, and each case fails loudly the day the defect is fixed, which is the cue to delete its marker.

## 4. Cold-start procedure review

What was checked: `scripts/lab-up.sh`, `lab-down.sh`, `docker-compose.yml`, `ollama_init.sh`, `.env.example`, the
Loan Desk docs, and the running stack. **What was not done:** a cold start. Splunk was not restarted and
`lab-up.sh` was not executed in this batch, so everything below is from reading, except where noted.

| # | Risk | Evidence | Effect |
|---|---|---|---|
| C1 | **Host Ollama with `llama3.2:latest` is required** and must be pulled with a terminal command. The compose Ollama container only pulls `OLLAMA_MODEL` (default `llama3.2:1b`) and its model list is empty on this machine. | `ollama_init.sh` line 5; `docker exec agentsec_ollama ollama list` is empty; `docs/LOAN_DESK_MISSION.md` line 4 | Fresh learner reaches the mission and gets "model unavailable". Contradicts "no terminal commands" for first-time setup |
| C2 | Host Ollama is reached via `host.docker.internal`, which `docker-compose.local.yml` maps to the host gateway. The base `docker-compose.yml` has no such mapping. | `.env.example` line 20 (commented out); `LOCAL_DOCKER_LAB.md` line 55 | Compose files must be combined as documented. Plain `docker compose up` with the base file alone cannot reach host Ollama on Linux |
| C3 | Verifier only starts after the readiness loop succeeds, or via the `--no-wait` path. If readiness never passes (80 × 15 s), no verifier starts and evidence stays NOT VERIFIED. | `lab-up.sh` lines ~175–203 | Honest, but a slow first Splunk boot (10–20 min) is covered; a failed one is not recoverable from the browser |
| C4 | Verifier does not restart after a reboot or a laptop sleep that kills it. Nothing re-runs `lab-up.sh`. | Section 3 | Mission shows `VERIFIER OFFLINE`; fix is a terminal command (`./scripts/loan_desk_verifier.sh start`) |
| C5 | **The branch's own `lab-up.sh` has not been run.** The stack on this Mac was brought up from the develop tree's (uncommitted) compose and scripts; Batch 4 rebuilt two images with `up -d --no-deps --no-build`. The branch's `lab-up.sh` and `lab-down.sh` changes (verifier start/stop) passed `sh -n` and a scratch-dir lifecycle test only. | `git diff` of the branch vs the develop tree's uncommitted `lab-up.sh`, `docker-compose.yml` | Real risk at merge time |
| C6 | **Merge conflict risk.** The develop tree has uncommitted edits to `lab-up.sh`, `docker-compose.yml`, `.env.example`, `docs/QUICKSTART.md` and others (HEC TLS work). The branch also edits `lab-up.sh`, `lab-down.sh`, `docs/QUICKSTART.md`. | `git status` in the develop tree vs `git diff d415c93` in the branch | Whoever merges must reconcile by hand |
| C7 | A fresh Splunk install gets the Loan Desk view automatically (`splunk_app_init` copies the app). The running Splunk got it by a manual additive copy and `_reload`; `--refresh-app` (restarts Splunk) was never run. | `BATCH4_NOTES.md` | The "view works after a restart" claim is untested; the cold-start path for views is unverified |
| C8 | `/usr/bin/python3` is the Xcode stub on some Macs and may open an installer prompt. Here `python3` resolves to Homebrew; the stub resolves to 3.9.6 and ran the verifier imports. | `which python3` | Low on this machine; mention in prerequisites for others |
| C9 | The verifier writes into the develop tree's git-ignored `artifacts/loan_desk/` (the lab's mounted directory). | `ls artifacts/loan_desk` | Clean for git, but this Mac now carries 14 entries from tests and acceptance runs there |
| C10 | Windows is untested (shell scripts, `kill`, pidfiles, `docker exec -u splunk`). | not run | Unsupported until tried |

**Recommended cold-start test (needs your approval, because it restarts Splunk):** on a disposable copy of the lab
(`COMPOSE_PROJECT_NAME=agentseclab_cold`, separate volumes, different host ports), run `lab-up.sh` from a clean clone of
the branch with an Ollama that has only `llama3.2:1b`, and record: time to READY, whether the mission page shows the
model-unavailable state, whether the verifier starts, whether the Loan Desk view loads. Then pull `llama3.2:latest`
and run the browser acceptance script. Resource cost: roughly one more Splunk (4+ GB RAM), a second set of images and
10–20 minutes.

## 5. Unresolved risks (ranked)

1. C1/C2 prevent a first-time learner on a fresh machine from completing the mission without terminal commands.
2. B5-V4: `lab-down.sh` can kill an unrelated process after a reboot.
3. B5-T1: lab containers can forge verification; the claim must stay "evidence the lab recorded", not "uncompromised".
4. C5/C6: the branch's startup path and the develop tree's uncommitted scripts have never been run together.
5. KV_MODE: two lessons in the duplicate-handling lab depend on current behaviour; 18 of 49 unbound hunts return no rows here, so their "identical" result is not evidence.
6. B5-V1/V3: a single bad record or a double start silently ends the verifier.
