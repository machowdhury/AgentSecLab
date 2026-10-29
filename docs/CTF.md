# Advanced CTF (RC2 MVP)

A bounded, local-only challenge layer on the existing lab engines. **NOT MULTI-USER. NOT PUBLIC HOSTING. NOT PRODUCTION AUTHENTICATION.** One local participant.

Pages: `/ctf` (challenges), `/ctf/<id>` (attempt), `/ctf/scoreboard`. JSON API under `/api/ctf/` (health, challenges, attempts, scoreboard). Code: `src/agentsec/ctf/`.

## Model

| Piece | What it is |
|---|---|
| Registry | Static metadata per challenge: id, title, difficulty, points, technique, expected control boundary, objective, defensive outcome, simulated/real label, engine binding, hint policy. **No flag or answer exists anywhere**; a test scans the static assets and registry JSON for decisive markers. |
| Attempt | Server-minted `secrets.token_urlsafe(24)` id (192 bits) bound to the run id(s) the engine produces. States: `NEW -> RUNNING -> VERIFIED \| FAILED \| RESET`. Record: `<state dir>/attempts/<id>.json` (dir 0700, file 0600, atomic write, symlink refused, max 200 records, max 32 KB each; unredeemed VERIFIED, FAILED, RESET and zero-award records are pruned oldest-first when the store is full; the at most one scoring record per challenge is kept)|
| Verification | Only the server decides, from events it recorded while driving the engine itself (control decisions, executed handlers, queue state). A client sends scenario parameters (posture, a note, a tool name, a step) and nothing else; there is no field that accepts a flag, a run id to trust, or text to score. Runs not owned by the attempt, created before it, bound to another challenge or another attempt, or carrying foreign events are refused (403 `run_not_owned`). The verdict is final: verifying again never re-decides; on an unredeemed VERIFIED attempt it re-signs the same verdict with a fresh nonce and time (so a lapsed 15-minute window does not kill the attempt), and the old receipt stops working. Still one score per challenge; a redeemed attempt cannot be redeemed again. |
| Receipt | HMAC-SHA256 over canonical JSON (sorted keys): `typ, v, attempt_id, challenge_id, participant, run_ids, verdict, points, issued_at, key_id, nonce, evidence_sha256, splunk, mac`. Same sign/verify primitives as the Loan Desk verifier receipts, separate key (`ctf.key`, 0600, never logged or returned). Strict shape check before the MAC; constant-time compare; integer times and points; 15 minute redemption window. |
| Ledger | `ledger.jsonl` plus a MAC'd `ledger.head` (entry count + last chain hash) checked on every read, so truncation or rollback is detected and the scoreboard fails closed (total 0, clear error) and redemption is refused until repaired or reset. One line per scored challenge (later redemptions are history and are not appended); capped at 500 lines. Append-only, `flock`-serialised, hash-chained, each line MACed. Redeeming checks and appends under one lock, so a receipt or attempt can score once even across threads and processes. |
| Scoreboard | Rebuilt on every read from ledger lines whose own MAC/chain verify **and** whose embedded receipt verifies again. No counter exists to edit. A damaged line is dropped and flagged. |

**Ledger recovery (tested with real killed and concurrent processes, `tests/ctf/test_ctf_concurrency_and_recovery.py`):**
- A process killed after the ledger line is fsynced but before `ledger.head` is written leaves the head exactly one entry behind a fully valid chain (or absent, with exactly one entry). The next redemption heals it under the lock; retrying the same receipt completes (200, same `seq`) with no second spend. Until then the scoreboard fails closed (total 0).
- Fail closed, nothing appended, nothing repaired automatically: a partial or truncated JSON last line, a whole line removed (head ahead of the ledger), an edited or forged head, a head more than one behind, an unparseable head beside two or more entries. Redemption answers 503 `ledger_integrity_failed`; repair by restoring both files together, or reset the CTF (delete the state directory).
- A last line that lost only its final newline is complete and valid; the next append starts on its own line.
- Two or more service processes over one state directory: redeeming the same receipt simultaneously scores once. Every success carries the identical body; a request arriving after the attempt is marked redeemed gets 409 `already_redeemed`. A second receipt for the same challenge awards 0 (policy: one score per challenge). No 5xx, no partial state.

**Rollback limits, stated precisely.** NOT detected: deleting BOTH `ledger.jsonl` and `ledger.head` (the scoreboard looks like a fresh ledger and the score is silently lost; a new attempt can then score again), and restoring an OLDER matched pair of the two (that older state is accepted as genuine). Detected: removing or damaging only the ledger, or only the head, or any line. Detection relies on the head being newer than, or equal to, the ledger; nothing outside the state directory records the latest count. A local OS user who can read `ctf.key` can forge anything and is out of scope.

**Trust limit, stated plainly:** the signed scoreboard resists casual tampering only. The local OS user who can read `ctf.key` can forge receipts, ledger lines and the head. It is not a security boundary against that user.

**Scoring policy (best-of):** one score per (participant, challenge). The first redeemed, verified receipt counts at the registry points; later verified attempts are history and award 0. No time, speed or hint bonus or penalty; hints are free.

## Reset and retry

Reset sets the attempt to `RESET`, drops its recorded events from server memory, and makes its receipt unredeemable. Starting an attempt again (or pressing Start while one is open) resets the open one and mints a **new** id. Each Loan Desk run builds its own service and store, so one attempt's queue can never hold another's tickets. Points already redeemed stay (ledger history).

Limits (per server process, rolling hour): 20 starts, 60 scenario runs, 120 verifications, 20 resets, 60 redemptions (HTTP 429 with `Retry-After`). Attempt lifetime 60 minutes. In-memory evidence keeps the newest 40 attempts; after a restart an unverified attempt answers 410 `evidence_unavailable` and must be reset.

## Local-only gating

Every `/ctf` and `/api/ctf` request needs a loopback peer **and** a loopback `Host` (this also blocks DNS rebinding). A non-loopback client is refused (403) unless ALL of these hold: `AGENTSEC_CTF_ALLOW_GATEWAY=1`; a shared secret of at least 16 characters configured in `AGENTSEC_CTF_GATEWAY_SECRET` (or `..._FILE`) and presented as `X-AgentSec-Gateway-Secret` (constant-time compare); and the identity header `X-Remote-User`. `X-Remote-User` alone never suffices. The secret is stripped of whitespace; a `_FILE` secret is refused if group/world-readable and re-read only when its mtime or size changes. This is not user authentication: the participant stays the single `local-participant`. POSTs also pass the Attack Service request guard (cross-origin `Origin`/`Sec-Fetch-Site` rejected), require `application/json`, a 4 KB body cap and duplicate-key rejection. Errors are generic; ids must match strict regexes and never become paths.

## Through the HTTPS gateway (opt-in, off by default)

`scripts/gateway.sh init` creates a random 32-byte gateway-owned secret (hex, 0600, in `.gateway/`, which is git-ignored) but leaves the CTF **off**. `scripts/gateway.sh ctf-enable` (idempotent; keeps an existing secret; rotate by deleting `.gateway/ctf-gateway-secret` and `.gateway/ctf-secret.conf`, then enable again) turns it on, `ctf-disable` turns it off; `scripts/gateway.sh up` applies it. Enabled, `docker-compose.gateway-ctf.yml` hands the secret file to the Attack Service (`AGENTSEC_CTF_GATEWAY_SECRET_FILE`, plus `AGENTSEC_CTF_ALLOW_GATEWAY=1`), and the gateway attaches it as `X-AgentSec-Gateway-Secret` **only** on the CTF locations; it blanks every client copy of that header everywhere else. Pages: `/attack-service/ctf`, `/attack-service/ctf/scoreboard`, `/attack-service/ctf/<id>` (GET/HEAD). API: `/api/ctf/...` (reads GET; the five POSTs need the operator login, the same-origin check and the shared attack quota of 6 POSTs per minute). Requires `AGENTSEC_ATTACK_TIER=enabled`. Disabled, the routes return 404 and the Attack Service has no secret and no opt-in, so the CTF stays loopback-only.

What the secret protects: it proves to the CTF that a request came through the gateway (which authenticated the user) and not from another container or host on the Docker network that merely sets `X-Remote-User`. It is not a user credential, not per-user identity (everyone is `local-participant`), and not a defence against anyone who can read `.gateway/` or the container environment. Limits: the CTF is a **single-participant** teaching tool; the gateway path is **NOT public multi-user hosting** and the scoreboard is shared by everyone who can log in. The nginx behaviour is modelled in tests, not run (see docs/GATEWAY.md).

## The challenges

| id | Level | Pts | Engine (existing) | Simulated | Success is read from |
|---|---|---|---|---|---|
| `note-smuggler` | Intermediate | 200 | `LoanDeskService`, policy `CTRL-LOANDESK-001` | Agent is a scripted stand-in (`test_double`), not an LLM | baseline run, ALLOWED+executed `submit_for_underwriter_review`, a queue ticket with free text copied from the learner's note. Hardened denies free text, so no success. |
| `poisoned-catalog` | Advanced | 300 | `run_mcp_invoke`, `MCP-CATALOG-001` | In-process catalog snapshot, **NOT an MCP server**; no rug-pull | `CTRL-MCP-METADATA-001` OBSERVE, tool ALLOWED+executed, follow-on `lookup_customer_tier` ALLOWED on metadata-derived authority and executed. Hardened observes but `CTRL-MCP-001` denies the follow-on. |
| `confused-deputy-relay` | Advanced | 300 | `run_identity_delegation` then `run_mcp_006_invoke` | Delegation model, **NOT A2A**; two server-sequenced runs, not one chain | claim run: `CTRL-IDENTITY-001` OBSERVE + claim-derived ALLOW executed; relay run: `CTRL-DELEGATION-001` ALLOW on ambient deputy authority and the restricted tool executed under the compliance agent for a credit-agent caller. Defended mode denies. |

## Splunk

Each attempt and receipt shows its `agentsec.run.id`s and the existing server-built starter search (`search_handoff.starter_spl`, passed through `spl_policy.check`; never built from input). The Splunk Search link is omitted when `AGENTSEC_GATEWAY_MODE=1`. Status is always **NOT VERIFIED in Splunk**: the CTF holds its events in memory and does not export them, and nothing here confirms indexing. A receipt proves this server's verdict, not that events are true.

## What the simulations do and do not show

- **Note Smuggler success reflects a simulation rule, not model behaviour.** The scripted agent only copies text introduced by a fixed marker phrase (the on-request hint gives it), and queue-harm detection needs at least 24 characters of that copied text. A note without the marker, or a shorter copy, does not succeed. Participants must use the marker; the hint is the only place it is revealed.
- **Confused Deputy Relay is two independent engine checks** (identity claim, then MCP-006 deputy) sequenced by the server. The first run does not feed the second.
- Hardened-posture runs are for comparison and are **not scored**; only a baseline success earns points.

## Limitations

Single participant (not multi-user, not public hosting), in-memory evidence (lost on restart), no HA. A host user who can read the state directory can read the key. The scripted agent and in-process catalog/delegation are teaching simulations. Engines are unchanged; no new event types were added. Challenge parameters are the learner's only input, so a "solution" is a configuration, not a secret.

## How to reset everything

Per attempt: the Reset button or `POST /api/ctf/attempts/<id>/reset`. Whole CTF: stop the Attack Service and delete the state directory (`$AGENTSEC_CTF_STATE_DIR`; with the gateway overlay it is the host directory `.gateway/ctf-state` (0700, the installing user's), kept by `down` and `agentsec down` and removed only by deleting it yourself; otherwise default `~/.local/state/agentsec/ctf`). Deleting `ledger.jsonl` zeroes the scoreboard; deleting `ctf.key` invalidates every receipt.

**Rotating the gateway secret:** delete `.gateway/ctf-gateway-secret` and `.gateway/ctf-secret.conf`, run `scripts/gateway.sh ctf-enable`, then `scripts/gateway.sh down` and `up`, then `docker restart` the Attack Service container so it re-binds the new file (`up` does not recreate it). A plain `up` keeps serving the old secret, because both containers bind-mount single files. `ctf-enable` refuses a secret that is not 64 lowercase hex characters or any symlinked material. The learner role can read challenges, hints, the scoreboard and attempt records (including a verified attempt's receipt); every POST is operator-only. State is shared by learner and operator (single participant).
