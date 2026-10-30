# Splunk integration: bundled, external Enterprise, Splunk Cloud (RC2, **unreleased**)

> The published v1.2.0 supports only the bundled Splunk container. The modes below ship in the RC2 release candidate (unreleased; the text was written on the v1.3.0 development branch). See [Deployment modes at a glance](GATEWAY.md#deployment-modes-at-a-glance).

> **How learners use Splunk in RC2.** Learners never open Splunk. The Academy's Investigate notebook and Security Assurance page ask the Attack Service to run approved, fixed-template searches and show the rows, a chart and a plain-language reading. Splunk Web and the five dashboards are optional Advanced views on the host's loopback, never a required step. The installer provisions a least-privilege, search-only Splunk identity (`./agentsec splunk-access`; check with `./agentsec splunk-access --check`); the Attack Service reaches Splunk's management API (`https://splunk:8089`) with strict TLS from a read-only mount. If it is not provisioned, the notebook says so and fails closed, with no silent fallback. The older host-side verifier that reads Docker is legacy, off by default (`AGENTSEC_LEGACY_HOST_VERIFIER=1` enables it) and ignored behind the gateway. This behaviour was validated on one real Splunk 10.2.7 host (bundled Splunk, 2026-10-30); it was not validated against an external Splunk, Splunk Cloud or an organization certificate.

AgentSecLab no longer assumes where Splunk runs. `AGENTSEC_SPLUNK_MODE` selects how the application searches and verifies evidence. Default `BUNDLED` is unchanged. **Evidence verification inside the Attack Service** (it has no Docker): when `AGENTSEC_SPLUNK_REST_URL` and `AGENTSEC_SPLUNK_SEARCH_TOKEN_FILE` are both set, the strict-TLS REST client is used in any mode, including BUNDLED, and an invalid setting never falls back to Docker; with neither, the Docker probe runs and, without Docker, the state is **VERIFICATION UNAVAILABLE** (never zero rows, never verified). Learners see `VERIFIED` (Splunk returned events for the run id), `NOT VERIFIED` (none yet, or the token cannot see them) or `VERIFICATION UNAVAILABLE` (the check could not run). In RC2 the installer provisions the search-only identity and CA for the bundled Splunk's port 8089 (see the note above); that provisioning was validated on one real Splunk 10.2.7 host (bundled Splunk, 2026-10-30); it was not validated against an external Splunk, Splunk Cloud or an organization certificate.

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

---

## Reference: the installer's bundled Splunk, search access, kernel and known issues

Moved from the installation guide.

### Kernel 6.19 or newer and the bundled Splunk

**Kernel warning for the bundled Splunk (important).** The current Ubuntu 24.04 AWS image ships Linux kernel 7.0. Splunk's bundled MongoDB refuses to start on Linux kernels **6.19 and newer**, which disables Splunk's KV store and with it Splunk authentication tokens (section 7.4). The lab itself still runs. If you need tokens, boot Ubuntu's own 6.8 kernel (TESTED on the acceptance host):
```bash
sudo apt-get install -y linux-image-6.8.0-1050-aws linux-modules-6.8.0-1050-aws
echo 'GRUB_DEFAULT="gnulinux-advanced-'"$(findmnt -no UUID /)"'>gnulinux-6.8.0-1050-aws-advanced-'"$(findmnt -no UUID /)"'"' | sudo tee /etc/default/grub.d/99-kernel-pin.cfg
sudo update-grub && sudo reboot
uname -r       # 6.8.0-1050-aws; the stack restarts by itself (restart: unless-stopped)
```
The commands are those used on the acceptance host (acceptance logs, not published). A reboot cancels any scheduled `shutdown`; schedule it again. Package versions change: check `apt-cache search '^linux-image-6.8.0-.*-aws$'` for the current 6.8 build.

#### Bundled Splunk and HEC (TESTED)
The bundled Splunk Enterprise (10.2.7 in the acceptance run; the installer checks the image digest recorded in `deploy/images.lock.json`, while a bare `docker compose up` uses the `splunk/splunk:10.2` tag) runs in the `local` Compose profile. Telemetry flows from AcmeBank to the OpenTelemetry collector, which sends it to Splunk's HTTP Event Collector over TLS inside the Docker network (`https://agentsec_splunk:8088/...`, a generated token `SPLUNK_HEC_TOKEN`, index `agentsec_telemetry`, sourcetype `otel:agentic:json`). `scripts/hec-certs.sh` creates the HEC certificate on first install (`AGENTSEC_HEC_TLS_MODE=LOCAL_SELF_SIGNED`). The two init jobs create the index, the HEC input and the Splunk app and load the recorded sample runs.

Check that a live run arrived (TESTED, from the repository's acceptance record): launch a run in the Academy, copy its run id, and, as the operator, in Splunk Search (an optional Advanced view; learners use the Academy's Investigate notebook instead) run `index=agentsec_telemetry "agentsec.run.id"="<run id>" | stats count`. The count equals the run's local event count. Telemetry can take seconds to minutes to appear.

#### Evidence verification states
The Academy labels each live run with one of three words: **VERIFIED** (Splunk returned the run's events), **NOT VERIFIED** (Splunk answered and found nothing yet, or was not answering) and **VERIFICATION UNAVAILABLE** (the check could not run: no Splunk REST settings, a certificate that does not match, a refused token). **VERIFIED is optional and off by default**; without the settings in 6.3 a launch card reads VERIFICATION UNAVAILABLE, because the Attack Service has no Docker access.

**Search access for the Academy notebook (RC2).** The Investigate notebook and Security Assurance do not depend on VERIFIED. The installer provisions a least-privilege, search-only Splunk identity for them: run `./agentsec splunk-access` (check it with `./agentsec splunk-access --check`). The Attack Service then reaches Splunk's management API (`https://splunk:8089`) with strict TLS, reading the credential and CA from a read-only mount (`.splunk-access/`). Where it is not provisioned the notebook says so and fails closed; there is no silent fallback. The older host-side verifier that reads Docker is legacy, off by default (`AGENTSEC_LEGACY_HOST_VERIFIER=1` enables it) and ignored behind the gateway, so no installer deployment reports a Splunk-VERIFIED Loan Desk run by default. **Validated (RC2 acceptance run, 2026-10-30) on one real Splunk Enterprise 10.2.7 host with the bundled Splunk, the Ubuntu 24.04 and kernel 6.8 setup above; not validated against an external Splunk, Splunk Cloud or an organization-issued certificate.** Rotating the credential with `--force` does not revoke the previous token: see [Troubleshooting](TROUBLESHOOTING.md#rotating-the-search-credential-and-the-old-token).

#### Turning on REST verification (VERIFIED) for the bundled Splunk (TESTED once, on a disposable host)
VERIFIED needs all of the following, none of which the lab creates for you. The complete evidence is in [Splunk integration](SPLUNK_INTEGRATION.md).
1. A Splunk **management certificate** whose names include the host name the client uses (`splunk` and `agentsec_splunk` inside the Docker network), signed by a CA you give to the client. Splunk's default certificate has **no** subject alternative name, so strict verification fails with `Hostname mismatch, certificate is not valid for 'splunk'`. The certificate must allow **both server and client authentication** (the KV store uses it for mutual TLS) and Splunk must trust the CA (`[sslConfig] serverCert` and `sslRootCAPath` in `server.conf`). Do not trust Splunk's default `SplunkCommonCA`.
2. A **working KV store** (see "Splunk KV store fails on Linux 6.19 or newer" below), because Splunk keeps authentication tokens there.
3. A **search-only role** on `agentsec_telemetry`, a user with it, and an **authentication token** for that user, stored in a one-line file with mode 0600 that the container's user can read.
4. The installer settings that carry the above into the Attack Service container (TESTED):
```bash
./agentsec --non-interactive --set gateway.ctf=true \
  --set splunk.rest_url=https://splunk:8089 \
  --set splunk.ca_file=/home/ubuntu/splunk-pki/ca.pem \
  --set splunk.token_file=/home/ubuntu/splunk-rest/token \
  --accept-warnings all --apply install
docker exec -i agentsec-attack-service python - <<'PY'
import os
from agentsec import splunk_client as sc
for stage, state, detail in sc.client_for_mode(dict(os.environ)).diagnose(None): print(stage, state, detail)
PY
```
Expected: `connectivity PASS`, `authentication PASS`, `authorization PASS`, `search PASS`, then `telemetry NOT VERIFIED` until you pass a run id. A live run then reads **VERIFIED** (22 of 22 events in the tested run). Any other outcome is one of the three states above, never a silent success.

An organization's own Splunk Enterprise or Splunk Cloud uses the same client with `splunk.mode` set to `external_enterprise` or `cloud`; that is **NOT TESTED** against a real service.

#### Optional Splunk dashboards for AI Security Assurance (TESTED on a disposable host)

Security Assurance in the Academy (`/learn/assurance`: findings, raw evidence, an investigation notebook and a retest comparison) needs nothing from this section. The installer also deploys the `agentsec` Splunk app, which holds five dashboards and a finding page ([guide](AI_SECURITY_ASSURANCE.md)): an **optional advanced view** of the same findings, never a required step. In Splunk Web they are at `http://127.0.0.1:18000/en-US/app/agentsec/ws_assurance_executive` on the host, use Splunk's own login, and are **not routed through the gateway**: on a remote host reach them through an SSH tunnel (`ssh -L 18000:127.0.0.1:18000 <host>`). They need the same Linux kernel older than 6.19 as Splunk's database (section 7.1). Scanner and garak panels stay empty until their evidence packs are ingested.

### Known issues, with the evidence to check

#### Splunk KV store fails on Linux 6.19 or newer (CONFIRMED on the test host)
Symptoms: Splunk is healthy and searches work, but `POST /services/authorization/tokens` answers `KVStore is not ready. Token auth system will not work.`

Diagnose (TESTED):
```bash
docker exec agentsec-splunk sh -c 'curl -sk -u "admin:$SPLUNK_PASSWORD" "https://localhost:8089/services/kvstore/status?output_mode=json"' | python3 -c 'import sys,json;print(json.load(sys.stdin)["entry"][0]["content"]["current"]["status"])'
docker exec -u root agentsec-splunk sh -c "grep -a 12257600 /opt/splunk/var/log/splunk/mongod.log | tail -1"
uname -r
```
Evidence from the tested host: status `failed`; `MongoDB cannot start: Linux kernel versions 6.19 and newer has a known incompatibility with this version of MongoDB (SERVER-121912)`; kernel `7.0.0-1014-aws`; the CPU had AVX, so it was not a CPU cause. Booting a 6.8 kernel (see "Kernel 6.19 or newer and the bundled Splunk" above) made the status `ready` with no Splunk change. Other causes show different log lines: read `mongod.log` and `splunkd.log` before changing anything.

#### After replacing the management certificate, the KV store fails again
Two causes were seen, both in the logs: Splunk did not trust the new CA (set `sslRootCAPath`), and `SSL peer certificate validation failed: unsuitable certificate purpose` (the certificate lacked the `clientAuth` extended key usage).

#### Other limits to expect
Splunk's REST VERIFIED path is not on by default (see "Turning on REST verification" above). The host-side Loan Desk verifier is legacy: only the older `scripts/lab-up.sh` starts it, and it is ignored behind the gateway, so an installer deployment never shows a Splunk-VERIFIED Loan Desk run by default; the Investigate notebook (see "Evidence verification states" above) is the in-Academy way to read the run's rows. The CTF challenges are simulated. There is no login throttling.
