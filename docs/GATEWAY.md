# Unified HTTPS gateway (v1.3.0, **unreleased**, opt-in)

> **Status in RC2.** The gateway is now the installer's default (`gateway.enabled: true`) and was **tested on one Ubuntu 24.04 host** in the RC2 acceptance runs (HTTPS verification, roles, CTF through the gateway, secret isolation): see [Installation and deployment](INSTALLATION_AND_DEPLOYMENT.md#5-https-gateway-certificates-authentication-and-tunnelling). The text below was written during development on `feature/v1.3.0-unified-gateway`, when the published release was **v1.2.0** (a multi-port plain-HTTP deployment); read its "v1.3.0" and "unreleased" wording in that light. Where something is not proven it says NOT VERIFIED or BLOCKED; the gateway on port 8000 and an organization certificate (`ORG_CERT`) are still untested on a host.

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
| Classic Attack Service page (`/`, `/labs/*`, `/academy/*`) behind the gateway | **Not routed** (known v1.3.0 limitation). The gateway serves `/learn`, `/static/`, health and the read/attack APIs, and answers `/` with a 302 to `/learn`, so the Academy sidebar has no Attack Service link. In the same way, in gateway mode (`AGENTSEC_GATEWAY_MODE=1`, set by the overlay) the Academy shows no link to the classic Academy pages (System Status, the classic path and lab pages), Splunk Web or AcmeBank: `/api/learn/config` reports their URLs as `null`, and the Investigate stage says to copy a search into your own Splunk session. A Chromium test crawls the Academy's pages through the gateway and fails on any link the gateway does not serve or any page that is not 200, and a source test requires every link that opens Splunk Web (including the search handoffs that only appear after a live launch) to go through the `SplunkLink` gate or the null-URL check. Not covered: links created by content the crawl cannot reach without a live model run. The Attack stage inside the Academy is unaffected. A later gateway phase should investigate a dedicated route such as `/attack-service/` that proxies the existing UI with its assets, API calls, authentication and role enforcement. Not implemented. |
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
`init` creates a 90-day test CA that is name-constrained (it can only vouch for `AGENTSEC_PUBLIC_HOST` and `localhost`, so trusting it in a browser cannot be abused for other sites) and deletes the CA's signing key as soon as the server certificate is signed, on every exit path. To renew, move `./.gateway` away and run `init` again, then trust the new CA. Keys you supply for `ORG_CERT` are yours: nothing here creates, changes or deletes them.

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

## Residual risks
The SPL policy constrains commands, not the base search's index or time range (the Splunk role is the control; on the bundled docker path, which uses the container's admin credential, the searches are application-built from fixed templates). Login throttling is open (below): keep the gateway on its loopback bind, or put an edge limiter in front of it. Real external Splunk, ORG_CERT chains from a production CA, Linux and rootless runtimes are not verified.

## Supported deployment modes (RC2 decision, 2026-10-28)
Only two modes are supported:
1. **Localhost-only learner installation**: the gateway (or the lab's own ports) bound to loopback on the learner's own machine (the default).
2. **Organization-managed deployment behind a trusted authentication, rate-limiting and network-access gateway** that the organization operates (its own SSO or reverse proxy, WAF or edge limiter, firewall or VPN). The lab's built-in Basic authentication is then a second factor at most, never the only control.
**Direct exposure to the public internet, or to an untrusted network, is unsupported.** `AGENTSEC_GATEWAY_BIND=0.0.0.0` and `lab-up.sh --remote` do not make a deployment safe; they are only for mode 2.
RC2 will **not** implement OAuth, SSO or application-level login throttling. The limitation below stays **UNRESOLVED**; the restriction above is how it is contained.

## Login throttling: not implemented, UNRESOLVED (decision recorded, RC1 M-2)
**Status: unresolved and not accepted.** Accepting this as a residual risk is the release owner's decision; until it is made, treat the gateway as safe only on its loopback bind or behind an edge limiter.
The gateway has **no per-client limit on failed logins**: wrong passwords all get `401` at any rate. This is a known v1.3.0 limitation, left open on purpose. What was evaluated: stock nginx cannot enforce a lockout. `limit_req` runs before the credential check and cannot tell a failure from a success, so any per-IP limit that is tight enough to stop guessing also throttles a whole classroom behind one NAT address (and static assets cannot be exempted without opening a bypass); counting failures after the fact (`error_page 401`) cannot stop a correct guess that follows; and a ban that applies to every request needs shared state, which means moving the credential check itself into a gate service (a cache-backed internal auth subrequest, njs, or a small sidecar). That is a redesign of the authentication path and was not made without review. Interim controls: the generated credentials are 96-bit random values; for `ORG_CERT` use long random passwords (the validator now warns on unsalted `{SHA}` hashes); keep the default loopback bind or restrict the port in your firewall; rate-limit or ban repeated `401`s at your edge (the gateway logs them with the client address: `docker logs agentsec_gateway`). Planned: OIDC / edge authentication (`AGENTSEC_AUTH_MODE`, refused today). Any gate design should answer every request identically while a client is locked out (no oracle for a correct guess), recover on its own, and document the shared-NAT trade-off.

## Container hardening (gateway overlay only)
Applied to the gateway, Attack Service and AcmeBank when the overlay is used (the base compose file is unchanged): `cap_drop: ALL` for the two Python services (they run as an unprivileged user), the capabilities nginx never uses dropped from the gateway (`NET_RAW`, `MKNOD`, `SETFCAP`, `SETPCAP`, `FSETID`, `AUDIT_WRITE`, `SYS_CHROOT`, `NET_BIND_SERVICE`; the master keeps `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `KILL`, `SETGID`, `SETUID`, and dropping everything and adding some back is deliberately not used because it breaks reading a 0600 key owned by another host user and is not portable), `no-new-privileges`, a memory limit (128 MiB gateway, 512 MiB Attack Service, 768 MiB AcmeBank; both Python services idle at about 30 to 40 MiB after days of use; raise with `AGENTSEC_GATEWAY_MEM_LIMIT`, `AGENTSEC_ATTACK_MEM_LIMIT`, `AGENTSEC_ACMEBANK_MEM_LIMIT`) and a process limit (128 / 256 / 256). Tested in the isolated stack: the limits are set on the running containers and 240 requests through the gateway at concurrency 16 all succeed with memory under 60 % of each limit. **Deferred, with reasons:** `read_only` root filesystems (the nginx entrypoint renders its configuration into `/etc/nginx/conf.d` at start, and the Python services' write paths, the bind-mounted artifacts and the collector's files, can only be proven with a populated lab that includes Ollama and the collector, which this qualification must not touch); CPU limits (no workload data; a wrong value slows learners); a non-root gateway image (a different image is an architectural change); the Attack Service and AcmeBank still have no authentication of their own and trust their network (see Security properties).

## Security properties (tested)
Unknown hosts fail the TLS handshake; anonymous requests get 401; a learner gets 403 on every attack route; unlisted routes and non-GET methods on the learner tier fail closed; client-supplied identity headers are overwritten or removed; the attack tier is rate-limited (6 state-changing requests per minute, burst 5, charged only to an authorized operator after the role check, so anonymous or learner traffic cannot spend it; GET polling is not counted; 429 with `Retry-After`); redirects stay relative; the gateway builds the `Host` it sends to the backends from its configured public host and port (never from a client header) and refuses a request whose Host port differs from the configured one (421), so the backends' same-origin check works on 443 and on every other port (browser-tested on 443 and a non-standard HTTPS port). Basic authentication is a stand-in, not production RBAC or SSO. The Attack Service itself still has no authentication or TLS: **never publish it directly**.

## CTF through the gateway (opt-in, default off)
`scripts/gateway.sh ctf-enable` then `up` publishes the Advanced CTF (`/attack-service/ctf...` pages, `/api/ctf/...`) through the gateway; see [CTF.md](CTF.md#through-the-https-gateway-opt-in-off-by-default). `init` generates a 32-byte secret into `.gateway/ctf-gateway-secret` and an nginx include `.gateway/ctf-secret.conf` (`set $gw_secret "..."`), both 0600, written by redirection so the value never appears in argv, logs or git. Only `docker-compose.gateway-ctf.yml` mounts them: the include into the gateway (read by the nginx master as root, like the TLS key) and the secret file into the Attack Service, which refuses a group/world-readable file. **Secret ownership:** both host files are 0600 and owned by the unprivileged user that installed the lab (never root: `gateway.sh ctf-enable` and `up` refuse to run under `sudo`, and refuse a secret that is not owned by you with mode 0600). The Attack Service runs as that same user (`user: AGENTSEC_CTF_UID:GID`, taken from `id` at enable time; no uid is assumed), so it can read its copy while nobody else on the host can; the nginx master reads its copy as root. The CTF ledger and key are in `.gateway/ctf-state` (0700, same owner), which `down` keeps. Installer path: set `gateway.ctf` to true and `agentsec up` applies the CTF overlay itself. **NOT re-verified on a host after this change** (it was written after the disposable-host run). Properties: every location blanks `X-AgentSec-Gateway-Secret` (identity-headers.conf, value `$gw_secret`, empty by default) and only the anchored CTF locations include the secret; the CTF POSTs apply the operator role, the Origin / Sec-Fetch-Site check and the attack quota before the secret is attached; method limits and anchored id captures rebuild the upstream URI. Not public multi-user hosting.

**Modelled, not nginx-verified:** `tests/gateway/nginx_model.py` (+ `test_gateway_ctf.py`, `tests/ui/test_gateway_ctf_browser.py`) reads the real conf files and models location choice, captures, `limit_except`, the Origin/operator checks, header overwrite and secret injection, then hands the resulting headers to the real Flask CTF app. nginx itself, TLS, the 8081 quota, `set` evaluation order and the compose mounts at runtime were NOT run (no nginx or Docker in this work). Run `AGENTSEC_GATEWAY_RUNTIME_TESTS=1` checks against a real stack before relying on it. **Real-nginx finding (disposable Linux VM, nginx from the pinned image):** the model said the secret reached the upstream on the CTF POST locations; real nginx did not send it there, because a `set` value is not visible to `proxy_set_header` in a location that uses `auth_request`. `ctf-secret.conf` now also carries `auth_request_set $gw_secret ...`, which real nginx honors after the operator check (verified: POSTs succeed, spoofed or absent secrets are refused). Regenerate a `ctf-secret.conf` written by an earlier build (rotation steps in CTF.md).

## Tests
The RC1 results (exact counts, the tested commit and what was not run) are in docs/security/RC1-QUALIFICATION.md. Chromium acceptance through the gateway is `tests/gateway/test_gateway_browser.py`; abuse controls (quota, wrong passwords, cross-site refusal, hardening, the 8000 configuration) are `tests/gateway/test_gateway_hardening.py`; certificate generation is `tests/gateway/test_gateway_init.py`; the SPL policy is `tests/test_spl_policy.py`. Browser and runtime tests need `AGENTSEC_CHROMIUM` and `AGENTSEC_GATEWAY_RUNTIME_TESTS=1` and are skipped (never passed) without them.

`pytest tests/gateway` runs configuration, compose, route, readiness and portability checks in seconds. `AGENTSEC_GATEWAY_RUNTIME_TESTS=1 pytest tests/gateway/test_gateway_runtime.py` builds the images and starts an isolated project named `agentsec-gw-dev` (about a minute); it needs free host port 443 for the real-bind test and otherwise skips it. The Academy-traffic route check needs Playwright and `AGENTSEC_CHROMIUM`; without them it is skipped, not passed.
