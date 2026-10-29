# Splunk integration: bundled, external Enterprise, Splunk Cloud (v1.3.0, **unreleased**)

> The published v1.2.0 supports only the bundled Splunk container. The modes below are on the v1.3.0 development branch. See [Deployment modes at a glance](GATEWAY.md#deployment-modes-at-a-glance).

AgentSecLab no longer assumes where Splunk runs. `AGENTSEC_SPLUNK_MODE` selects how the application searches and verifies evidence. Default `BUNDLED` is unchanged. **Evidence verification inside the Attack Service** (it has no Docker): when `AGENTSEC_SPLUNK_REST_URL` and `AGENTSEC_SPLUNK_SEARCH_TOKEN_FILE` are both set, the strict-TLS REST client is used in any mode, including BUNDLED, and an invalid setting never falls back to Docker; with neither, the Docker probe runs and, without Docker, the state is **VERIFICATION UNAVAILABLE** (never zero rows, never verified). Learners see `VERIFIED` (Splunk returned events for the run id), `NOT VERIFIED` (none yet, or the token cannot see them) or `VERIFICATION UNAVAILABLE` (the check could not run). The bundled lab does not create the token or the CA for its own port 8089: unverified against a real Splunk after this change.

## What is verified, and how
| Capability | Verification |
|---|---|
| `BUNDLED`: unchanged docker-based search and probes | **Real Splunk** (the lab's own container, read-only query: the `agentsec_telemetry` index answered with 3,986 events via the unchanged backend) plus the existing test suite |
| `EXTERNAL_ENTERPRISE` and `CLOUD`: strict-TLS REST client, staged diagnosis, search/verifier/probe wiring | **Mock only** (a disposable HTTPS endpoint with a test CA). **Real Splunk Enterprise and Splunk Cloud: NOT VERIFIED** |
| HEC export from the collector to an external Splunk | **NOT VERIFIED** (configuration only; see below) |
| Installing the `agentsec` app and index on an external Splunk | **NOT VERIFIED** and not automated |
| Splunk Web behind the gateway | **NOT VERIFIED**, not implemented |

## Configuration (external modes)
```
AGENTSEC_SPLUNK_MODE=EXTERNAL_ENTERPRISE | CLOUD
AGENTSEC_SPLUNK_REST_URL=https://splunk.example.org:8089      # https only; no credentials, path or query
AGENTSEC_SPLUNK_CA_BUNDLE_FILE=/run/secrets/splunk-ca.pem     # optional: ADDS trust for a private CA; verification can never be turned off
AGENTSEC_SPLUNK_SEARCH_TOKEN_FILE=/run/secrets/splunk-token   # single-line, least-privilege, search-only token (never in env values, URLs or logs)
AGENTSEC_SPLUNK_INDEX=agentsec_telemetry
AGENTSEC_SPLUNK_TIMEOUT_SEC=30                                # 1-120
AGENTSEC_SPLUNK_HEC_URL / AGENTSEC_SPLUNK_HEC_TOKEN_FILE      # validated only; the collector exports with SPLUNK_HEC_ENDPOINT and its CA mount
```
Check it: `PYTHONPATH=src python -m agentsec.splunk_client validate`, then `... check [--run-id <id>]`. This CA bundle is independent of the gateway's own certificate (`AGENTSEC_TLS_*`).

## Staged results (each judged separately; one PASS never implies the next)
`CONNECTIVITY` (verified TLS handshake) · `AUTHENTICATION` (token accepted) · `AUTHORIZATION` (token may run searches) · `SEARCH` (a trivial search returned a parsable result) · `TELEMETRY` (**NOT VERIFIED** unless `--run-id` finds indexed events for that run). A search-only token that may not read server info still passes, because server info is not required. Invalid external configuration fails closed: nothing falls back to docker.

## Security properties (tested against the mock)
Certificate and hostname verification always on (wrong CA, wrong hostname, expired certificate all fail as `tls_verification_failed`); redirects are never followed, so a token cannot reach another host; tokens travel only in the `Authorization` header and never appear in findings, errors, reprs or the CLI output; responses are size-capped and searches have a wall-clock limit; only application-built SPL that passes a **constrained read-only policy** is sent (learners still send only a template id). The policy (`agentsec.spl_policy`) is an allowlist for the application's fixed dialect, not a general SPL sanitizer: ASCII only, no macros, comments or subsearches (backtick, `[`, `]`), every `|` starts a stage (even inside quotes), the first stage is a plain search or `| makeresults`, and every later stage must start with `eval`, `fillnull`, `head`, `rename`, `sort`, `stats`, `table` or `where`; `index=` is allowed only in the base search. Anything else (including `delete`, `outputlookup`, `collect`, `rest`, `script`, `outputtelemetry`, `webhook`, and any command not listed) is refused before any request, on the REST path and on the bundled docker path (which runs with the container's admin credential). Every accepted or refused search writes a hash-only audit line (`agentsec.splunk.audit`: backend, SHA-256 prefix, length, stages; never the text or a secret); Splunk's own `_audit` index records what runs under the token. The credential remains the real control: use a search-only token limited to the telemetry index. Per-search time and size are limited client-side (wall-clock deadline, 2 MiB response cap, row cap); server-side `max_time`/`max_count` are not sent because they are **NOT VERIFIED** against a real Splunk; the REST client is used only server-side (verifier, readiness) and is not reachable from the learner interface.

## What the Academy status reports (reachable, authenticated, operational)
The status endpoint probes only the **configured** Splunk endpoint, never a guessed address (`host.docker.internal`, a bare loopback port): `AGENTSEC_SPLUNK_INTERNAL_URL` if set, then, in `BUNDLED` mode, the lab's own container on the compose network and the configured `AGENTSEC_SPLUNK_WEB_URL`. In `BUNDLED` mode **Splunk Web (reachability)** can only say that the web UI answered; it states that this is not a login, a search or indexing, and **Splunk indexing** stays `NOT CHECKED` (the page does not authenticate to Splunk). In `EXTERNAL_ENTERPRISE` and `CLOUD` modes a **Splunk REST (configured endpoint)** check runs the staged client (cached 30 s): `AVAILABLE` only when connectivity, authentication, authorization and a trivial search all passed; `DEGRADED` when the endpoint is reachable but a later stage failed; `UNAVAILABLE` when it is unreachable, fails TLS verification or the configuration is invalid (nothing falls back to the bundled container). The top-bar chip turns green only on those results, and its tooltip repeats the limit. Real external Splunk remains **NOT VERIFIED** (mock-tested).

## Real-Splunk verification record (the lab's bundled Splunk 10.2, 2026-10-26, read-only)
**Result: partially verified. The authenticated stages through the new client are BLOCKED.**

*Why searches "reported zero".* Data: 3,986 events in `agentsec_telemetry`, `_time` from 1789158299 to 1792784280 (the newest is about 3.1 days old). Splunk's own job record for `search index=agentsec_telemetry earliest=-30d | stats count` shows `dispatchState=DONE`, `eventCount=scanCount=3545`, `resultCount=1`, bounds 2026-09-26T22:46:44Z to 2026-10-26T22:46:44Z, run time 0.07 s, result `count=3545`.

| Endpoint | Exact SPL (plus API time parameter) | Result |
|---|---|---|
| REST `/services/search/v2/jobs/export` | `search index=agentsec_telemetry \| stats count` (none) | 3986 |
| same | same + `earliest_time=0` | 3986 |
| same | `search index=... earliest=-24h \| stats count` + `earliest_time=0` | **0** (inline bound wins; the data is older than 24 h) |
| same | `search index=... earliest=-30d \| stats count` + `earliest_time=0` | 3545 |
| same | `\| eventcount summarize=false index=agentsec_telemetry` | 3986 |
| CLI `splunk search` | `index=agentsec_telemetry earliest=0 \| stats count` | 3986 |
| CLI `splunk search` | `index=agentsec_telemetry earliest=-30d \| stats count` | 3545 |
| CLI `splunk search` | **`search index=agentsec_telemetry earliest=0 \| stats count`** | **0** |

Explanation: (1) the CLI prepends `search` itself, so a leading word `search` becomes a literal term and matches nothing; the REST endpoints require the leading `search`. The application's searches start with `index=...`, so the docker backend is correct, but a caller that passes a leading `search` to it silently gets 0. (2) Every application template carries `earliest=-24h`, which correctly returns 0 for data older than a day; that is not a defect. (3) An inline `earliest` overrides the client's default `earliest_time=0`, so the client never widens a template's own window. The bundled docker backend uses the Splunk CLI, whose hostname validation is disabled by default (`cliVerifyServerName`); only the REST client verifies hostnames.

*Strict TLS against real Splunk (isolated, read-only probe container on the lab's private Docker network: no capabilities, read-only filesystem, no volumes except read-only source and CA, removed afterwards; no search, no ingest, no configuration change).* Splunk's default management certificate is `CN=SplunkServerDefaultCert` with **no subject alternative name**, issued by the publicly distributed default `SplunkCommonCA`. The client therefore fails closed: `tls_verification_failed` with the system trust store, with Splunk's default CA bundle, and via the other DNS alias. A closed port is `connect_failed`; an unroutable address is `timeout`, bounded at the configured 3.0 s (measured 3.00 s). A dummy token never left the client because the handshake failed first. **Do not trust `SplunkCommonCA`**: it is the same default CA on every Splunk install.

*BLOCKED against real Splunk:* authentication, authorization, search execution and result parsing **through the client**, because (a) the default certificate can never pass hostname verification, so strict TLS cannot succeed without installing a certificate that has a matching SAN (a Splunk configuration change), and (b) no least-privilege search token exists, and creating one changes Splunk. Splunk's own job lifecycle and CSV result format were checked above with administrator access through `splunk _internal call`, not through the client.

*Smallest safe prerequisite to unblock:* a Splunk (disposable or the lab's, with your approval) whose management port presents a certificate with a SAN for the hostname the client uses, signed by a CA you control and give to the client as `AGENTSEC_SPLUNK_CA_BUNDLE_FILE`, plus a role limited to the `search` capability on `agentsec_telemetry` and a token for it. Alternatively a separate disposable Splunk on a host with enough memory.

## REST verification against the bundled Splunk: what it took, verified on a disposable host (2026-10-29)
Record: reviews/rc2/FINAL_TWO_CHECKS_ACCEPTANCE.md. With the steps below, a live workshop run reached **VERIFIED** (22 of 22 events, matching an independent Splunk search), and NOT VERIFIED and VERIFICATION UNAVAILABLE were each produced against the same real Splunk. Four things stood between the lab and that result:
1. **Application defect (fixed): the settings never reached the Attack Service container.** The installer wrote `AGENTSEC_SPLUNK_REST_URL`, the CA file and the token file into `.env`, but Compose did not pass them on and the files were not mounted. The installer override now passes them and bind-mounts the token and CA read-only at `/run/secrets/agentsec_splunk_token` and `/run/secrets/agentsec_splunk_ca` (external modes, or the bundled Splunk when `splunk.rest_url` and `splunk.token_file` are both set). A second defect found on the way: re-running `agentsec install` over a running install was refused because the collector's published port **range** (`4317-4318`) was not parsed; ranges now count port by port.
2. **Splunk's KV store did not start on a Linux kernel 6.19 or newer.** Authentication tokens live in the KV store, so on such a host the token call answers "KVStore is not ready. Token auth system will not work." The cause is in `mongod.log`: `MongoDB cannot start: Linux kernel versions 6.19 and newer has a known incompatibility with this version of MongoDB (SERVER-121912)`. The default Ubuntu 24.04 AWS image now ships kernel 7.0. On the test host, booting the Ubuntu 24.04 GA kernel (6.8.0-1050-aws) fixed it at once. The lab itself runs without the KV store; only token creation and anything else that needs it is affected. The verification code never uses the KV store.
3. **The management certificate must match the name the client uses.** Splunk's default is `CN=SplunkServerDefaultCert` with no subject alternative name, so strict verification fails with "Hostname mismatch, certificate is not valid for 'splunk'" (original evidence kept in the record). The disposable host used a throwaway CA and a certificate with `DNS:splunk, DNS:agentsec_splunk, DNS:localhost`, installed with `[sslConfig] serverCert` and `sslRootCAPath` in `server.conf`. **The certificate must allow both `serverAuth` and `clientAuth`:** the KV store uses it for mutual TLS, and a server-only certificate left the KV store `failed` with "unsuitable certificate purpose". Splunk must also be told which CA to trust (`sslRootCAPath`), or the KV store cannot connect.
4. **A token and a search-only role.** A role limited to `agentsec_telemetry` plus a Splunk authentication token for a user with that role; the token went into a 0600 file mounted read-only into the container. The container's user must be able to read it (the installing user when `gateway.ctf` is on, otherwise UID 1000), or the state stays VERIFICATION UNAVAILABLE.
What a learner sees: with none of this configured, VERIFICATION UNAVAILABLE and the search to run by hand. A Splunk that answers with zero rows, or is not answering yet (retried until the timeout), shows NOT VERIFIED, never VERIFIED. The application still does not accept a session key or a password instead of a token: a deliberate least-privilege choice.

## Where the code assumed a local Splunk (inventory)
| Place | Before | Now |
|---|---|---|
| `loan_desk/search.py` notebook searches; `loan_desk/verifier.py` | `docker exec ... splunk search` | `default_backend()`: docker when BUNDLED, strict REST when external |
| `loan_desk/reconcile.py` | docker exec | shared client when external |
| `evidence_readiness.py` launch probe | docker exec (REST only via legacy `AGENTSEC_SPLUNK_PROBE_*`) | shared client when external; legacy REST probe kept |
| `gateway-ready.sh` | loopback Splunk Web check | staged client report when external |
| `lab-ready.sh`, `lab-up.sh`, `lab-preflight.sh`, `learner_ready.py`, `splunk_hec_init.sh`, access scripts, `capture_*` scripts | bundled container, `docker exec`, `curl -k` against its loopback management port | **unchanged by design**: they provision or screenshot the bundled instance |
| Academy "Splunk" links | `AGENTSEC_SPLUNK_WEB_URL` (default `http://agentsec_splunk:8000`) | unchanged; set it for an external Splunk Web |

## Splunk Cloud: what the Splunk documentation says (checked 2026-10-26)
REST management endpoint `https://<deployment>.splunkcloud.com:8089`; access must be enabled for your source addresses (Admin Config Service `search-api` IP allow list, or a support case); free trials cannot use the REST API; authentication tokens are available (native, LDAP, SAML); the Search resource group is supported and REST access is limited to the search tier. **Not checked here:** the Cloud HEC endpoint and token details, private-app installation rules, and what a given stack's roles allow. No Cloud compatibility is claimed until a real stack passes the `check` command.

## Preparing an external Splunk (operator tasks, not automated)
Create the `agentsec_telemetry` index, an HEC token bound to it, a role with only the `search` capability and access to that index, and a token for that role; install the `agentsec` app/dashboards yourself if you want them. Never use an administrator token.

## Moving from bundled to external
Nothing is moved or rewritten: the bundled volumes stay as they are, new evidence goes to the external index, and historical bundled events stay in the bundled Splunk. Evidence from the two sources is not merged or re-dated. Switch back by unsetting `AGENTSEC_SPLUNK_MODE`.

## Not in this milestone
Real-Splunk external tests; HEC through the collector to an external endpoint; Splunk Web proxying; automatic app installation; SSO.
