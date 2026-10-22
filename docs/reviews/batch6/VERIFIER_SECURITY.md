# Batch 6, Priority 0: verification bridge v2

Replaces the Batch 4 design (`docs/reviews/batch4/VERIFICATION_BRIDGE.md`). Batch 5 showed that a lab container could
forge `SPLUNK_VERIFIED` because it held the signing key and could write the result file. This removes that path
without a new endpoint, a Splunk credential in any container, or a Docker socket.

## 1. What changed

| Concern (Batch 5 finding) | v1 | v2 |
|---|---|---|
| Who can write a result | any process in AcmeBank or Attack Service (shared rw mount) | only the host verifier. `artifacts/loan_desk/receipts/` is bind-mounted **read-only** into both containers (`docker-compose.yml`, two mounts) |
| Where the key lives | `artifacts/loan_desk/.bridge.key`, mode 0644, readable in the container | host-only state directory `~/.local/state/agentsec/loan_desk/` (0700), file `receipt.key` (0600). Not under `artifacts/`, not mounted anywhere |
| How AcmeBank decides a receipt is real | HMAC with the shared key | filesystem boundary. AcmeBank also **refuses SPLUNK_VERIFIED when it can write to `receipts/`**, so a mis-mounted deployment fails safe (`NOT_VERIFIED`, "mount it read-only"). Requests are no longer signed (they are untrusted input and the verifier validates them) |
| Receipt at rest | HMAC, checkable only with the shared key | HMAC with the host key; `scripts/loan_desk_verifier.py --check <file>` audits one on the host |
| Malformed request | uncaught exception, loop dies | strict shape check; bad request quarantined to `rejected/` (bounded to 50) and logged; each request handled in its own `try`; loop-level `try` and no exit on error |
| Symlinks, FIFOs, huge files | followed / read | opened `O_NOFOLLOW|O_NONBLOCK`, `fstat` must be a regular file ≤ 4 KB |
| Temporary files | fixed `*.tmp` name shared by writers | `mkstemp` in the target directory, `fsync`, `os.replace`; unique per writer; cleaned on failure |
| Two verifiers | both ran, one crashed | exclusive `flock` on `verifier.lock`; the second exits 0. The pidfile is written by the process that holds the lock |
| `stop` with a stale pid | killed whatever owned the pid | pid is trusted only if `ps -o command=` contains `loan_desk_verifier.py`; otherwise "stale pidfile ignored"; waits up to 10 s, never escalates to SIGKILL |
| Shutdown | no handler | SIGTERM/SIGINT finish the current request, write a `stopped` heartbeat, remove the pidfile |
| Nonce memory | unbounded | `OrderedDict` capped at 1024 |
| Disposable testing | verifier always searched `agentsec_splunk` | `AGENTSEC_SPLUNK_CONTAINER` (validated name) selects the container |

Unchanged and still true: the verifier opens no port, takes no input except request files, runs only fixed read-only searches
bound to a validated run UUID (`reconcile.py`), at most 30 a minute, and never reads `SPLUNK_PASSWORD` into Python.

## 2. Receipt integrity versus evidence integrity

- **Receipt integrity** (now strong): this answer was written by the host verifier for this request (`nonce`, `request_digest`) and has not changed. Established by the read-only mount (online) and the HMAC with a key the lab never sees (at rest).
- **Evidence integrity** (not claimed): the events are true. A receipt says only "the events AcmeBank reported for this run are the events Splunk indexed". It carries `evidence_digest_local` and `evidence_digest_indexed` (hashes of the per-event-name counts on each side) and a `scope` string stating this. If AcmeBank were compromised it could emit false events and still earn a truthful receipt. If the collector or HEC path were compromised, Splunk could hold false events that match. Neither is detected, and the page's wording ("SPLUNK-VERIFIED ... does not prove the events are true") now appears in the glossary.

## 3. Residual risks

1. **Host trust.** Anything that can write to the repository's `artifacts/loan_desk/receipts/` on the host (the learner's own account) can forge a receipt, and anything that can read the host state directory can sign one. This is a single-user workstation lab; it is not a multi-user boundary.
2. **Docker Desktop mounts.** The read-only guarantee comes from the container runtime. A deployment that mounts `receipts/` writable is detected by AcmeBank and shown as `NOT_VERIFIED`, but the *verifier* cannot know how AcmeBank was started.
3. **Quarantine and log growth.** `rejected/` is capped; `verifier.log` is not rotated.
4. **Windows is unsupported** (`flock`, `ps`, shell scripts).
5. **Migration.** *(Done in Batch 7 Gate B; see `docs/reviews/batch7/DEPLOY_REPORT.md`.)* Until then the running lab used v1 images and the v1 `.bridge.key` layout (this batch deploys nothing to it). Moving to v2 means: recreate `acmebank` and `attack_service` with the new compose file, `loan_desk_verifier.sh stop` the old verifier (it has no process-name check, so stop it by its recorded pid yourself), `lab-up.sh` or `loan_desk_verifier.sh start`, then delete the old `.bridge.key`, `*.splunk.json`, `verifier.json` and `requests/` files in `artifacts/loan_desk/`. I did none of this.

## 4. Tests (all pass)

`tests/test_loan_desk_bridge.py` (15 functions) and `tests/test_loan_desk_verifier_security.py` (19 functions, 26 cases with parametrization), 41 cases in all, cover: receipts bound to the current request and nonce;
replayed, mismatched, unsigned and wrong-run receipts never verify; malformed requests (type, NaN, bool, extra field,
bad nonce) quarantined while a good request is still served; symlink, FIFO, 5 MB and 100 KB-of-braces requests ignored in seconds;
one failing fetch does not stop other requests; bounded nonce memory; unique-temp atomic writes, a failed write leaving the old
file, six concurrent writers never exposing a partial file; isolation enforced (writable receipts directory refuses verification;
a 0555 directory allows it and raises `PermissionError` on any write attempt); key outside the artifacts tree with modes 0600/0700;
a receipt audited with the right key, the wrong key, and after tampering; **process tests with the real shell script:** start,
status, stop, clean shutdown writing a `stopped` heartbeat, four concurrent starts leaving exactly one process and a correct pidfile,
`kill -9` followed by status and restart, **a stale pidfile naming an unrelated live process never signals it**, garbage pidfiles
(`""`, `abc`, `1; rm -rf /`, `-1`, `0`) harmless, crash recovery answering a request left pending, a replayed request not
answered twice, and compose mounting `receipts/` read-only exactly twice with the override variable never set.
The real-container proof (a container actually receiving `EROFS`) is in `COLD_START_RESULTS.md`.
