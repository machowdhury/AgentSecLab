# AgentSecLab v1.3.0 RC1 qualification (branch feature/v1.3.0-unified-gateway, HEAD de75241)

Recommendation: CONDITIONAL GO. NO-GO for advertising port 8000. See "Release blockers".

## Evidence files (kept in the qualification session's evidence folder; the final ones are copied here)
phase1_review.md (static review + STRIDE table), adv_results.txt (adversarial probes), journey_results.txt (browser journey, status, launch),
gw_runtime.txt (87 passed), protected_before.txt / snap_before.json (protected-lab snapshot; compared after every run: UNCHANGED),
test_rc1_adversarial.py / test_rc1_journey.py (probe code, outside the repo), shots/ (screenshots).

## Isolation
Host: Docker Desktop, 18 CPUs, 11.7 GiB, 489 GiB free. Protected lab running (agentsec_* containers; host ports 5000, 5001, 8000, 8088, 4317, 4318).
Disposable stack: project agentsec-gw-dev only (tests/gateway/compose.test.yml: unique container names, no bind mounts, no Splunk/Ollama/OTel, one loopback port 18543).
Protected snapshot (containers, ids, start times, volumes, networks) compared after every run: unchanged. Torn down at the end: 0 gw-dev containers left.
The DOCUMENTED install (scripts/gateway.sh up) was NOT run: docker-compose.yml uses fixed container_name agentsec_attack_service / agentsec_acmebank, so `up` would recreate the protected lab's containers.

## Release blockers
B-1 HIGH (CONFIRMED in curl and in a real browser). Browser POSTs to the Attack Service fail with 403 cross_origin_rejected on every non-443 public port, including the documented alternative 8000.
 Cause: gateway sends `Host $host` (no port); request_guard compares the browser's Origin netloc (host:8000) to request.host (host). Evidence: operator POST /api/launch with Origin https://agentsec.test:18543 -> 403 JSON cross_origin_rejected; same without the port -> reaches the handler; in-page fetch() from /learn/loan-desk/attack -> 403.
 Impact: the Academy Attack stage cannot launch in a browser on 8000 (AcmeBank guard likewise). Tests missed it because they use curl without Origin. Fix direction (not applied): `Host $http_host`, plus a browser test on a non-443 port.

## Other findings
M-1 MEDIUM confirmed: limit_req runs before auth. A learner's denied attack-route requests got 429, so denied or anonymous traffic spends the shared 6 r/m per-IP bucket the operator needs (behind NAT or Docker Desktop all clients share one IP).
M-2 MEDIUM confirmed: no brute-force control. 40 wrong operator passwords -> 40 x 401, no throttle or lockout.
M-3 MEDIUM confirmed by file listing: LOCAL_DEV `init` leaves ca.key in .gateway/tls (0600) and the CA has no nameConstraints, while output tells users to trust it in a browser.
M-4 MEDIUM (reading only): assert_read_only_spl checks only the first word after each `|` (bypasses via `[... | delete]`, comments/macros, unlisted commands). Safe today only because SPL is app-built and the token is search-only.
M-5 MEDIUM confirmed: evidence accuracy. In the isolated stack (no Splunk, Ollama absent, launch returned runtime 503) /api/academy/status reported "Splunk Web answered HTTP 200" and the LIVE ENVIRONMENT chip showed on every page. The probe tries host.docker.internal:8000, which reached the protected lab's Splunk (read-only GET of the login page; no data sent). The chip means "reachable", not "live evidence".
L-1 /api/learn/config returns http://host:5000 and :8000 links that are dead in gateway mode (confirmed). SPA also references /academy/status, /academy/path, /api/compare-handoff, which the gateway does not route.
L-2 tests/gateway/test_gateway_runtime.py: `assert not _free(8000) or True` can never fail; 8000 is validated by rendered config only.
L-3 No resource limits or hardening in compose: Memory 0, NanoCpus 0, PidsLimit none, no read_only, no cap_drop; gateway container runs with default user. Backends run as appuser.
L-4 Splunk client: slow-drip deadline gap (S-2), u.port ValueError not mapped to SplunkError (S-3).
L-5 gateway.sh: eval on gateway.env keys (W-5), password in argv for openssl passwd (W-6), non-loopback bind only warns (W-2), HSTS on localhost (W-1), Compose >= 2.24 not checked (W-9).
I-1 Attack Service and AcmeBank have no authentication; any container on the mesh can POST /api/launch (documented). No backend trusts X-Auth-* headers.
I-2 The earlier dependency probe once showed no response while the backend was stopping; on rerun the gateway answered 502 in 0.2 s and recovered to 200 after restart.

## Verified (runtime, isolated)
- tests/gateway: 87 passed, 0 skipped (incl. real bind of 127.0.0.1:443, ORG_CERT chain with intermediate, LOCAL_DEV, rate limit, attack tier disable/restore, Academy route allowlist).
- gateway.sh init + validate for ports 443, 8000, 18999 (warning for non-standard); credentials and keys 0600.
- Path and routing probes (26 vectors: encoded dots/slashes, //, %0a, %00, ;, backslash, authz internal route): all fail closed (400/404) or serve only allowlisted content. Learner cannot reach attack routes (403/429) even with spoofed X-Authz-User, X-Remote-User, method override.
- Auth edge cases (no creds, wrong role password, empty password, bearer, junk Basic, case-changed user): all 401.
- TLS: 1.0 and 1.1 rejected, 1.2 served, 1.3 negotiated (TLS_AES_256_GCM_SHA384); wrong CA, wrong SNI, wrong hostname rejected; verify code 0 after restart.
- Response headers: CSP, nosniff, X-Frame-Options DENY, no-store, HSTS present; server_tokens off; redirects relative.
- Backend exposure: isolated attack and acmebank publish no host ports; internal 8081 and 8443 not reachable on the host.
- Dependency failure: 502 (no internal names or traces), anonymous still 401, recovery to 200.
- Restart of all three containers: 6.6 s, service back, TLS valid, no secrets in logs.
- Browser journey (Chromium, SPKI-pinned test leaf; learner at 1280 px, operator at 390 px): 30 routes each (Home, Path, Foundations, Curriculum, 2 labs, Loan Desk 8 stages, EVAL 5 views, Risk 4, Governance 4, Assurance, MCP, Mastery): 0 responses >= 400, 0 console errors, no horizontal scroll at 390 px.
- Evidence labels seen: EVAL overview RECORDED/SIMULATED; findings NOT_VERIFIED; Risk SOURCE-BACKED FACT / DERIVED / ANALYST JUDGMENT / LOCAL DRAFT; Assurance LIVE/RECORDED/SIMULATED/NOT_VERIFIED/DOCUMENTED.
- Earlier on this HEAD: non-UI 2533 passed / 51 skipped; UI 320 passed (not rerun here); Splunk-client/config/gateway-config tests 94 passed (mock-based).

## Mock-tested only
External Splunk Enterprise and Splunk Cloud client (strict TLS, https-only, no redirects, token from file, redaction, response cap).

## NOT VERIFIED
- Documented install on a clean host (blocked by container_name collision on this host); Linux, Windows, rootless, cloud VMs.
- Real bind of public port 8000 (held by protected Splunk); config-level only.
- BUNDLED Splunk with a disposable instance (not provisioned: protected lab holds 8000/8088 and the overlay fixes 127.0.0.1:8088); real HEC ingestion and indexed evidence; Investigation in Splunk.
- Real attack execution with a real model: isolated stack has no Ollama; a launch returned runtime 503 with evidence_state WAITING_FOR_EVIDENCE (honest, but not live evidence).
- Completing a lab or the Loan Desk mission end to end; EVAL runs; Risk/Governance beyond page load; accessibility rerun.
- Data persistence of live evidence across recreate and upgrade (test overlay has no volumes; running `gateway.sh up` on a populated lab is documented as untested).
- Real EXTERNAL_ENTERPRISE / CLOUD authentication, searches, ingestion; Splunk Web through the gateway; OIDC; EDGE_TERMINATED.

## Unsupported (documented)
EDGE_TERMINATED, OIDC/edge-header auth, Splunk Web behind the gateway, classic Attack Service UI behind the gateway.

## Browser trust note
The browser journey used Chromium's SPKI pin for the exact test leaf instead of the system trust store. Chain and hostname validation were proven separately with openssl and curl using the test CA. No TLS verification was disabled in any product code path.

## Remediation plan
1. B-1: forward the port in Host (or compare ports in the guard); add a browser test on a non-443 port. Retest on 8000.
2. M-1/M-2: rate-limit only POST, add limit_conn and auth-failure throttling; apply limit_req after authorisation.
3. M-3: nameConstraints, delete ca.key after signing.
4. M-5: probe the configured Splunk URL only (drop host.docker.internal), and word the chip as "reachable".
5. M-4: parsed allowlist for SPL.
6. Install on a clean Linux VM from the docs (443 and 8000), run BUNDLED with a disposable Splunk, rerun this suite there.
7. Remove the vacuous 8000 assertion; fix dead links in learn config; add resource limits.
