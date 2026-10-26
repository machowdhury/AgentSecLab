# Gateway POC (v1.3.0 Milestone 1): disposable, not a deployment

A throwaway proof of concept for one HTTPS entry point in front of the Academy, Attack Service and AcmeBank, plus a stand-in for Splunk Web and a mock external Splunk. **It does not touch the real lab** (compose project `agentseclab`) or any AWS resource. Everything it creates is named or labelled `agentsec-gw-poc`.

## Safety model
- Own compose project `agentsec-gw-poc`, own networks (`agentsec-gw-poc-backend` is `internal: true`), own images (`agentsec-gw-poc/*:m1`), own runtime directory `.runtime/` (git-ignored).
- Exactly one published port: `127.0.0.1:18443`. No host ports for the apps, no Ollama, no HEC, no OTel, no Splunk.
- Test-only certificates and random credentials are generated into `.runtime/`; keys never leave it and nothing is added to any trust store.
- `down` never uses `-v` or `--remove-orphans`. `cleanup --yes` removes only POC-named containers, images and `.runtime/`.

## Run
```bash
sh deploy/gateway-poc/scripts/run_poc.sh up                              # build + start (test-only certs and credentials)
PYTHONPATH=src python -m pytest deploy/gateway-poc/tests -p no:cacheprovider   # 22 tests; ~1 minute; needs docker, curl, openssl
sh deploy/gateway-poc/scripts/run_poc.sh down                            # stop
sh deploy/gateway-poc/scripts/run_poc.sh cleanup --yes                   # remove ONLY POC resources
```
URL used: `https://learn.poc.test:18443/learn` (clients pass `--resolve learn.poc.test:18443:127.0.0.1 --cacert .runtime/certs/local/ca.pem`; there is no `-k`). Hostnames: `learn.`, `bank.`, `splunk.poc.test`.

`POC_RUN_CLEANUP=1` additionally enables `tests/test_t24_cleanup.py`, which runs the cleanup and checks the real lab is unchanged. Rate limiting is per client (6 requests/minute on the attack tier), so repeated runs within a minute wait for the bucket to refill.

## Layout
`docker-compose.yml`; `gateway/` (nginx.conf, attack-tier.conf, identity-headers.conf, tls-probe.conf); `stubs/splunk_stub.py` (NOT Splunk); `scripts/make_certs.sh`, `scripts/run_poc.sh`; `tests/`; `config-examples/`; `ARCHITECTURE.md`; `evidence/` (matrix, results, resources).

## Milestone 2
See [MILESTONE2.md](MILESTONE2.md): environment proposal, real-Splunk test plan (not run), route-allowlist regression (`tests/test_route_allowlist.py`), enterprise readiness assessment.

## What this proves and does not prove
See [EVIDENCE.md](evidence/EVIDENCE.md). In short: gateway TLS modes, certificate failures, authentication and role separation, header-spoofing resistance, fail-closed routing, rate limiting, strict-TLS external-Splunk probe behaviour (against a mock) and isolation from the real lab are demonstrated. **Real Splunk Web, SSO, EDGE_TERMINATED mode, Splunk Cloud/Enterprise and production RBAC are NOT VERIFIED.**
