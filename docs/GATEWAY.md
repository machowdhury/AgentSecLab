# Unified HTTPS gateway (v1.3.0, opt-in)

One HTTPS entry point in front of the Academy and Attack Service. **It is off by default**: nothing changes for an existing install until you opt in. The base `docker-compose.yml` is not modified.

## What is implemented, tested, planned

| Capability | State |
|---|---|
| Gateway as an opt-in compose overlay + profile (`docker-compose.gateway.yml`, `--profile gateway`) | Implemented, **tested** |
| Canonical learner URL `https://<AGENTSEC_PUBLIC_HOST>:<AGENTSEC_HTTPS_PORT>/learn` (`/` redirects to `/learn`); port 443 by default, any port for local development | Implemented, **tested** |
| Attack Service and AcmeBank with no host ports (internal network only) | Implemented, **tested** |
| TLS mode `LOCAL_DEV` (generated test-only CA and certificate) | Implemented, **tested** |
| TLS mode `ORG_CERT` (your certificate, private key and CA chain from files) | Implemented, **tested** with a disposable private CA (root, intermediate, server) |
| Configuration validation that fails closed (certificate/key mismatch, expiry, hostname, wrong CA, missing intermediate, bad port/host/mode, weak htpasswd) | Implemented, **tested** |
| Authentication `LOCAL_BASIC` with two roles (`learner`, `operator`); attack routes need `operator` | Implemented, **tested** |
| Attack tier on/off (`AGENTSEC_ATTACK_TIER=enabled|disabled`) | Implemented, **tested** |
| Default-deny route allowlist checked against the real Flask routes and against what the Academy actually calls | Implemented, **tested** |
| TLS mode `EDGE_TERMINATED` (your own load balancer terminates TLS) | **Planned**; refused by the validator |
| OIDC / edge-header authentication | **Planned**; refused by the validator |
| Splunk Web behind the gateway | **NOT VERIFIED**; not routed (Splunk stays on its loopback port 8000) |
| External Splunk Enterprise, Splunk Cloud | **Not implemented**; no support is claimed |
| Gateway-aware `lab-ready.sh` and capture scripts | **Planned** (they still assume `127.0.0.1:5001`/`:5000`) |

## Quick start (local development)
```bash
AGENTSEC_PUBLIC_HOST=localhost AGENTSEC_HTTPS_PORT=8443 sh scripts/gateway.sh init     # test-only certificate + users in ./.gateway (git-ignored)
sh scripts/gateway.sh validate                                                         # fails closed with a specific error code
sh scripts/gateway.sh up                                                               # gateway + attack_service + acmebank only
# open https://localhost:8443/learn ; credentials are in .gateway/credentials.txt (mode 0600)
sh scripts/gateway.sh down                                                             # removes only the gateway container
```
`init` never changes a trust store; trust `.gateway/tls/ca.pem` in your browser yourself if you want a green padlock. Requires Docker Compose 2.24 or later (`!reset`/`!override`).

## Organization-provided certificate
Put the files anywhere readable and set (see `.env.example`): `AGENTSEC_TLS_MODE=ORG_CERT`, `AGENTSEC_PUBLIC_HOST`, `AGENTSEC_TLS_CERT_FILE` (server certificate), `AGENTSEC_TLS_KEY_FILE` (unencrypted PEM key, mode 0400/0600), `AGENTSEC_TLS_CHAIN_FILE` (intermediates plus root), `AGENTSEC_AUTH_FILE` (htpasswd with users `learner` and `operator`, hashes only). `gateway.sh up` validates first, builds `fullchain.pem` (certificate plus chain, no secrets) and starts the gateway; the key is mounted read-only from where you keep it. There is no option to skip certificate or hostname verification.

## Configuration reference
`AGENTSEC_PUBLIC_HOST` (DNS name, default `localhost`), `AGENTSEC_HTTPS_PORT` (default 443), `AGENTSEC_GATEWAY_BIND` (default `127.0.0.1`; a non-loopback value warns until you set `AGENTSEC_GATEWAY_ALLOW_NONLOOPBACK=1`), `AGENTSEC_TLS_MODE`, `AGENTSEC_TLS_CERT_FILE`, `AGENTSEC_TLS_KEY_FILE`, `AGENTSEC_TLS_CHAIN_FILE`, `AGENTSEC_AUTH_MODE` (`LOCAL_BASIC`), `AGENTSEC_AUTH_FILE`, `AGENTSEC_ATTACK_TIER`, `AGENTSEC_GATEWAY_DIR` (default `./.gateway`). Run `python -m agentsec.gateway_config validate` (with `PYTHONPATH=src`) to check them.

## Security properties (tested)
Only the gateway publishes a port; unknown hosts fail the TLS handshake; anonymous requests get 401; a learner gets 403 on every attack route; unlisted routes and non-GET methods on the learner tier fail closed; client-supplied identity headers are overwritten or removed before a request reaches a backend; the attack tier is rate-limited; redirects stay relative. Basic authentication is a stand-in, not production RBAC or SSO. The Attack Service itself still has no authentication or TLS: **never publish it directly**.

## Migrating an existing install (safe, reversible)
1. Nothing happens until you opt in. Your Splunk volumes, `.env`, credentials and host verifier are not touched by any gateway command.
2. Update the checkout, run `gateway.sh init` or prepare your certificate files, then `gateway.sh validate`.
3. `gateway.sh up` starts the gateway and **recreates `attack_service` and `acmebank`** without host ports (a short interruption). Their data lives in the bind-mounted `./artifacts` directory and the named `shared_telemetry` volume, which are kept. It never starts, stops or recreates Splunk, the collector or Ollama.
4. Consequence: `http://127.0.0.1:5001` and `:5000` stop answering; use the canonical URL. `lab-ready.sh` and the capture scripts still probe those ports and will report a failure until they are made gateway-aware.
5. Roll back: `gateway.sh down`, then `docker compose up -d --no-deps attack_service acmebank` from the unmodified compose file restores the original port mappings from the existing images.

## Data preservation and limits
Guaranteed by design and by the isolated runtime test: no Docker volume is created, modified or removed by the gateway; the runtime tests also snapshot the real lab's containers, mounts, networks and volumes before and after and require them to be identical. Not tested: running `gateway.sh up` against an existing populated lab (it was kept untouched on purpose). Installs whose Splunk uses the legacy anonymous volumes keep them; `lab-up.sh` still refuses to replace them without `--fresh-splunk-data`.

## Tests
`pytest tests/gateway` runs the configuration, compose and route tests (about 10 s). `AGENTSEC_GATEWAY_RUNTIME_TESTS=1 pytest tests/gateway/test_gateway_runtime.py` builds the images and starts an isolated project named `agentsec-gw-dev` (about a minute). The Academy-traffic route check also needs Playwright and `AGENTSEC_CHROMIUM`; without them it is skipped, not passed.
