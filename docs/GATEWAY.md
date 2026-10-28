# Unified HTTPS gateway (v1.3.0, **unreleased**, opt-in)

> **Status.** The published release is **v1.2.0**, a multi-port plain-HTTP deployment. Everything in this document is on the v1.3.0 development branch (`feature/v1.3.0-unified-gateway`): implemented and tested as stated below, **not merged, not released**. Where something is not proven it says NOT VERIFIED or BLOCKED.

One externally reachable application port: **443 (default) or 8000**, both HTTPS. Everything else (Attack Service, AcmeBank, Splunk, Ollama, HEC, OTel) stays internal or loopback-only. The gateway is **off by default**: nothing changes for an existing install until you opt in, and the base `docker-compose.yml` is not modified. The v1.2.0 documentation and release history are unchanged.

## Deployment modes at a glance

| | **Published v1.2.0** | **v1.3.0 opt-in HTTPS gateway** (unreleased) |
|---|---|---|
| Externally reachable application ports | Three when published for remote use: 5001 (Academy and Attack Service), 5000 (AcmeBank), 8000 (Splunk Web), via `lab-up.sh --remote` | **Exactly one: 443 (default) or 8000**, HTTPS only (target contract) |
| Transport | Plain HTTP, no TLS | HTTPS: your certificate (`ORG_CERT`) or a generated test certificate (`LOCAL_DEV`) |
| Authentication | None on the Attack Service or AcmeBank | Gateway basic auth with two roles (a stand-in, not SSO); attack routes need `operator` |
| Attack Service, AcmeBank, Ollama, HEC, OTel | Host ports published (loopback by default) | Attack Service and AcmeBank unpublished; HEC and OTel loopback only |
| Splunk Web | `http://127.0.0.1:8000` | **Not reachable through the gateway (NOT VERIFIED, not routed).** It moves to `127.0.0.1:18000`, host loopback only |
| Splunk back end | Bundled container only | `BUNDLED` (real-verified), `EXTERNAL_ENTERPRISE` and `CLOUD` (**mock-tested only**; real Splunk **NOT VERIFIED**, authenticated stages against real Splunk **BLOCKED**, see [Splunk integration](SPLUNK_INTEGRATION.md)) |
| How to use | `./scripts/lab-up.sh` ([Getting started](GETTING_STARTED.md)) | `scripts/gateway.sh` (this page) |

The v1.2.0 column describes what is published and unchanged. The target for a hosted deployment is the right-hand column's single HTTPS port; the gateway does not make the old multi-port deployment safe, and `lab-up.sh --remote` is not the gateway.

## Implemented, tested, planned

| Capability | State |
|---|---|
| Opt-in overlay `docker-compose.gateway.yml` + profile `gateway`; `scripts/gateway.sh` | Implemented, **tested** |
| Exactly one externally reachable port: 443 or 8000 (`AGENTSEC_PUBLIC_PORT`); validated in the fully rendered compose for both values | Implemented, **tested** (config level for both; real host bind tested for 443 on macOS Docker Desktop; **real bind of 8000 NOT VERIFIED**, see below) |
| Canonical URL `https://<AGENTSEC_PUBLIC_HOST>[:8000]/learn`; `/` redirects there | Implemented, **tested** |
| Attack Service and AcmeBank with no host ports; Splunk Web moved off 8000 to a loopback-only port (`AGENTSEC_SPLUNK_LOCAL_PORT`, default 18000); HEC and OTel stay loopback-only | Implemented, **tested** (rendered config) |
| TLS `LOCAL_DEV` (generated test-only material) and `ORG_CERT` (your certificate, key and chain from files) | Implemented, **tested** (disposable private CA: root, intermediate, server) |
| Fail-closed configuration validation incl. port, certificate, hostname, chain, expiry, htpasswd, occupied port | Implemented, **tested** |
| `LOCAL_BASIC` authentication, roles `learner` and `operator`; attack tier on/off; default-deny allowlist checked against the real routes and the Academy's real traffic | Implemented, **tested** |
| Gateway-aware readiness (`lab-ready.sh` delegates to `gateway-ready.sh`) | Implemented; tested with shim commands only, **not end to end** |
| TLS `EDGE_TERMINATED`; OIDC / edge-header authentication | **Planned**; refused by the validator |
| Splunk Web behind the gateway | **NOT VERIFIED**; not routed |
| Classic Attack Service page (`/`, `/labs/*`, `/academy/*`) behind the gateway | **Not routed** (known v1.3.0 limitation). The gateway serves `/learn`, `/static/`, health and the read/attack APIs, and answers `/` with a 302 to `/learn`, so the Academy sidebar has no Attack Service link. The Attack stage inside the Academy is unaffected. A later gateway phase should investigate a dedicated route such as `/attack-service/` that proxies the existing UI with its assets, API calls, authentication and role enforcement. Not implemented. |
| External Splunk Enterprise; Splunk Cloud (search and verification layer, see [Splunk integration](SPLUNK_INTEGRATION.md)) | Implemented and **mock-tested** only; real Splunk **NOT VERIFIED**; HEC export and app installation not covered |

## 443 or 8000
- **443** is the default. A rootful Docker daemon (Docker Desktop, standard Docker Engine) can bind it. Rootless Docker and Podman-rootless cannot bind ports below 1024 unless the host allows it (for example `net.ipv4.ip_unprivileged_port_start`); use 8000 there.
- **8000** is the alternative. Splunk Web normally publishes host port 8000 (loopback), so in gateway mode the overlay moves it to `127.0.0.1:18000`. `gateway.sh up` refuses with `PORT_IN_USE` if something already listens on the public port, and never stops it. An already-running lab keeps Splunk on 8000 until Splunk is recreated with the overlay, so on such a host use 443 or move Splunk first (a separate, deliberate step).
- Any other port is accepted for local development with a warning. Internal service ports (5000, 5001, 8088, 8089, 4317, 4318, 11434) are refused as the public port.

## Install
**Local Docker (macOS, Linux, Windows with Docker Desktop):**
```bash
AGENTSEC_PUBLIC_HOST=localhost AGENTSEC_PUBLIC_PORT=8000 sh scripts/gateway.sh init   # test-only certificate + users in ./.gateway (git-ignored)
sh scripts/gateway.sh validate
sh scripts/gateway.sh up                      # gateway + attack_service + acmebank only; prints the canonical URL
sh scripts/lab-ready.sh                       # gateway-aware readiness (see below)
sh scripts/gateway.sh down                    # removes only the gateway container
```
**Generic Linux server or VM (including cloud VMs):** the same commands, with `AGENTSEC_GATEWAY_BIND=0.0.0.0` and `AGENTSEC_GATEWAY_ALLOW_NONLOOPBACK=1` to make the one port reachable, your DNS name in `AGENTSEC_PUBLIC_HOST`, and your own certificate (below). Open only the chosen port in whatever firewall or network rule your environment uses; nothing here depends on a cloud provider's services.

**Organization-provided certificate:** set `AGENTSEC_TLS_MODE=ORG_CERT`, `AGENTSEC_TLS_CERT_FILE` (server certificate), `AGENTSEC_TLS_KEY_FILE` (unencrypted PEM key, mode 0400/0600), `AGENTSEC_TLS_CHAIN_FILE` (intermediates plus root) and `AGENTSEC_AUTH_FILE` (htpasswd with users `learner` and `operator`, hashes only). Validation checks the key matches, the dates, the hostname against `AGENTSEC_PUBLIC_HOST`, and that the chain verifies. There is no option to skip certificate or hostname verification, and no certificate or key is ever written outside `./.gateway`.

## Readiness (what each word means)
`lab-ready.sh` switches to gateway mode when the `agentsec_gateway` container exists and runs `scripts/gateway-ready.sh`. It reports separate facts and never lets one stand in for another:
**GATEWAY READY** (container, nginx config, TLS verified against your CA, authentication required) · **ACADEMY READY** (`/learn` served, checked inside the network) · **ATTACK SERVICE READY** (`/health`; not proof an attack runs) · **SPLUNK REACHABLE** (loopback Splunk Web only) · **TELEMETRY NOT VERIFIED** (always, unless you pass `--run-id <id>` and indexed events for that run are found) · **LIVE WORKFLOW NOT VERIFIED** (always; a readiness check never launches an attack). Exit status reflects gateway, Academy and Attack Service only.

## Bundled and external Splunk
- **Bundled Splunk** (default) is unchanged: the telemetry pipeline, dashboards, volumes and credentials are untouched. In gateway mode its web UI is on `127.0.0.1:18000` only (reach it from another machine through your own tunnel). Proxying Splunk Web through the gateway is **NOT VERIFIED** and not routed.
- **External Splunk Enterprise and Splunk Cloud:** the search, verifier and probe paths can use a strict-TLS REST client ([Splunk integration](SPLUNK_INTEGRATION.md)). It is **mock-tested only**: real Splunk Enterprise and Splunk Cloud are **NOT VERIFIED**, and HEC export and app installation are not covered.

## Safe upgrade and rollback
1. Nothing runs until you opt in. Splunk volumes, `.env`, credentials and the host verifier are not touched by any gateway command.
2. `gateway.sh up` starts the gateway and **recreates `attack_service` and `acmebank`** without host ports (a short interruption). Their data lives in the bind-mounted `./artifacts` directory and the named `shared_telemetry` volume, which are kept. It never starts, stops or recreates Splunk, the collector or Ollama.
3. `http://127.0.0.1:5001` and `:5000` stop answering; use the canonical URL. The capture scripts still probe those ports.
4. Roll back: `gateway.sh down`, then `docker compose up -d --no-deps attack_service acmebank` from the unmodified compose file restores the original port mappings from the existing images.
5. Not tested: running `gateway.sh up` against an existing populated lab (kept untouched on purpose).

## Platform status (be precise)
| Platform | Status |
|---|---|
| macOS with Docker Desktop (Apple Silicon) | **Runtime-tested** (config, isolated runtime stack, real bind of 127.0.0.1:443) |
| Linux with Docker Engine | Shell syntax checked under Debian dash and Alpine busybox; compose rendered the same everywhere. **Not runtime-tested** |
| Windows with Docker Desktop, rootless Docker, Podman | **Not tested** |
| Generic VM, AWS, Azure, GCP VMs running Docker | **Not tested.** Static checks show no provider-specific service or non-portable container feature (no host networking, privileged mode, Docker socket or metadata service) |

Host prerequisites: Docker Engine or Desktop with Compose 2.24+ (`!reset`/`!override`), the `openssl` command (1.1.1+; LibreSSL untested), a public DNS name or `localhost`, and permission to bind the chosen port. Images are the official `nginx:1.27-alpine` (amd64 and arm64).

## Security properties (tested)
Unknown hosts fail the TLS handshake; anonymous requests get 401; a learner gets 403 on every attack route; unlisted routes and non-GET methods on the learner tier fail closed; client-supplied identity headers are overwritten or removed; the attack tier is rate-limited (6 state-changing requests per minute, burst 5, charged only to an authorized operator after the role check, so anonymous or learner traffic cannot spend it; GET polling is not counted; 429 with `Retry-After`); redirects stay relative; the gateway builds the `Host` it sends to the backends from its configured public host and port (never from a client header) and refuses a request whose Host port differs from the configured one (421), so the backends' same-origin check works on 443 and on every other port (browser-tested on 443 and a non-standard HTTPS port). Basic authentication is a stand-in, not production RBAC or SSO. The Attack Service itself still has no authentication or TLS: **never publish it directly**.

## Tests
`pytest tests/gateway` runs configuration, compose, route, readiness and portability checks in seconds. `AGENTSEC_GATEWAY_RUNTIME_TESTS=1 pytest tests/gateway/test_gateway_runtime.py` builds the images and starts an isolated project named `agentsec-gw-dev` (about a minute); it needs free host port 443 for the real-bind test and otherwise skips it. The Academy-traffic route check needs Playwright and `AGENTSEC_CHROMIUM`; without them it is skipped, not passed.
