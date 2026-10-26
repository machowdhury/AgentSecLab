# Evidence report: gateway POC, 2026-10-26

Host: macOS, Docker Desktop VM 11.66 GiB RAM, 18 CPUs. nginx 1.27-alpine, python 3.11/3.12, OpenSSL 4.0.3 (host), curl 8.7.1. Baseline repository commit: `9b6a87c6e9f4f8a40594be3761e8e8ee3f35fdcb` (main).

## Resource gate and why real Splunk was not started
The protected lab's Splunk (amd64, emulated) already uses about 5.9 GiB of the VM's 11.66 GiB. A second Splunk would risk pushing the VM into memory pressure and an OOM kill of the existing lab, so the Splunk Web tests ran against a **stub** that mimics only proxy-relevant behaviour. Real-Splunk tests are marked NOT VERIFIED, with this plan: run on a separate machine/VM with at least 8 GiB free, `splunk/splunk:10.2`, the same gateway and the same flow (login, session cookies, CSRF form key, redirects, static assets, an app page, logout, a streaming/WebSocket request).

## Matrix (24 required tests + one extra)
See [MATRIX.md](MATRIX.md). Summary: **22 PASS, 3 NOT VERIFIED (T15-T17: stub mechanics PASS, real Splunk not run), 0 FAIL.**

## What each group establishes
- **Isolation (T01, T02, T21, T22, T24):** one published mapping (`127.0.0.1:18443->8443`); backends on an `internal` network and unreachable from a container on the default bridge; the protected lab's 7 containers (ids, images, start times, restart counts, mounts, networks) and 25 volumes are identical before and after, including after cleanup; the agentsec_telemetry index count is 3,986 before and after.
- **TLS (T03-T10):** valid LOCAL_DEV chain and hostname verified; simulated ORG_CERT (root -> intermediate -> server, files mounted) verified with only the root trusted; expired, wrong-hostname and wrong-CA certificates fail (curl exit 60 with the specific reason); a certificate with a mismatched key is refused by nginx. Unknown SNI hostnames fail the handshake.
- **Authentication and isolation (T11-T14, T25):** anonymous and wrong-credential attack requests get 401; a learner gets 403 on every attack route; an operator reaches the app; unlisted routes and non-GET methods on the read tier fail closed; spoofed `X-Remote-User`, `X-Auth-Role`, `X-Forwarded-User`, `X-Remote-Groups` do not grant access and are overwritten or removed before reaching the backend; the attack tier is rate-limited (HTTP 429).
- **Splunk Web through the gateway (T15-T17), STUB ONLY:** form login with disposable credentials, Secure + SameSite=Lax added to cookies without breaking a script-readable CSRF cookie, CSRF header honoured and forged or missing keys rejected, absolute backend redirects rewritten to the client's host:port, static assets served, logout clears the cookie and the session page redirects.
- **External Splunk mock (T18-T20):** the repository's `probe_splunk_count_rest` (product code) succeeds with the mock's CA bundle and a token read from a file; a wrong CA and a hostname mismatch both fail with `tls_verification_failed`; a missing CA file or an `http://` URL is `probe_misconfigured`; a bad token is `probe_auth_failed`; a refused connection is `splunk_probe_failed`. HEC URL/CA/token behaviour was checked against the mock with a test client. **Mock only: not evidence of Splunk Enterprise or Cloud compatibility.**
- **Secrets (T23):** 15 non-ignored files and the four container logs contain neither the generated passwords nor key blocks; the runtime directory is git-ignored.

## Resource consumption
Idle memory: gateway 6 MiB, attack 35 MiB, acmebank 35 MiB, stub 12 MiB (TLS scenario containers about 2 MiB each). Images: `agentsec-gw-poc/attack:m1` 290 MB, `acmebank:m1` 289 MB (sharing base layers). Full test run about 50 s. Net added load on the protected lab: none observed (its containers were not restarted).

## Residual risks and not-verified items
- Real Splunk Web behind a hostname proxy, enterprise SSO, WebSockets: NOT VERIFIED.
- EDGE_TERMINATED mode: not implemented, not claimed.
- Basic auth is a stand-in; OIDC, production RBAC, session timeout and CSRF for the Academy API are not designed or tested here.
- No Content-Security-Policy is applied (it could break the Academy UI; needs its own test).
- The path allowlist regex duplicates the app's route table and can drift; a route-table-driven test is needed.
- AcmeBank ran without Ollama/OTel (degraded), so LLM-backed attack execution was not exercised end to end; the operator call reached the app but its business result is out of scope.
- The OTel collector's HEC exporter and the lab's docker-exec search paths were not exercised.
- Rate limiting applies before authentication (floods consume the bucket).
