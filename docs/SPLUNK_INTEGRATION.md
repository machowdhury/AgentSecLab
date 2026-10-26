# Splunk integration: bundled, external Enterprise, Splunk Cloud (v1.3.0)

AgentSecLab no longer assumes where Splunk runs. `AGENTSEC_SPLUNK_MODE` selects how the application searches and verifies evidence. Default `BUNDLED` is unchanged.

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
Certificate and hostname verification always on (wrong CA, wrong hostname, expired certificate all fail as `tls_verification_failed`); redirects are never followed, so a token cannot reach another host; tokens travel only in the `Authorization` header and never appear in findings, errors, reprs or the CLI output; responses are size-capped and searches have a wall-clock limit; only application-built read-only SPL is accepted (learners still send only a template id; commands such as `delete`, `outputlookup`, `collect`, `rest`, `script` are refused before any request); the REST client is used only server-side (verifier, readiness) and is not reachable from the learner interface.

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
