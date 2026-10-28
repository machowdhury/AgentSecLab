# v1.3.0 unified gateway: read-only adversarial review
Repo <repo>, HEAD de75241, diff origin/main...HEAD. Read-only; nothing run. "Confirmed" = confirmed by reading code. Anything about nginx/browser runtime behaviour is marked "needs runtime confirmation" unless the nginx documented phase order settles it.

## Findings

### G-1 (Medium) limit_req runs before auth: anonymous clients can exhaust the operator's attack budget
gateway/attack-enabled.conf:2-8; gateway/templates/gateway.conf.template:7,27.
- `limit_req` is a PREACCESS-phase handler. `auth_basic` and `auth_request` run later, in the ACCESS phase.
- An unauthenticated client, who would get 401, still consumes the `attack` zone (6 r/m, burst 5, keyed by $binary_remote_addr).
- Scenario: the attacker sends ~10 requests to `/api/launch`. Every legitimate operator request from the same source IP then gets 429.
- Behind Docker Desktop NAT, or any front proxy or LB, all users share one source IP. Even without an attacker, the UI polling `GET /api/launches/<id>` and `GET .../runs/<id>` shares the 6 r/m budget with launches.
- Evidence: the zone is applied to GET and POST on every attack route, and nothing authenticates before it. Confidence: confirmed by reading. Documented nginx phase order. Needs runtime confirmation for the polling-UX effect.
- Fix: split the zone, rate-limit only POST (use `map $request_method`), and key on $remote_user after auth. A plain `limit_req` cannot be keyed on $remote_user before auth runs, so also add `limit_conn`.

### G-2 (Medium, functional, likely breaks port 8000) Host header drops the port, so the CSRF/origin guard rejects every browser POST on non-443 ports
gateway/templates/gateway.conf.template:29 (`proxy_set_header Host $host`); src/agentsec/request_guard.py:31-37.
- `$host` has no port. The backend's `request.host` is therefore `localhost`.
- `cross_origin()` compares `urlsplit(Origin).netloc` ("localhost:8000") to `request.host` ("localhost").
- Browsers send `Origin` on same-origin POSTs, so every launch POST would return 403 `cross_origin_rejected` when AGENTSEC_PUBLIC_PORT=8000 (a documented supported port). Port 443 is unaffected because the default port is omitted from Origin.
- Also affected: build_config() / `request.host` in learn_web.py:69 and any Flask-built absolute URL. These lose the port.
- Not a security hole, but it is the supported alternate configuration and tests do not cover it (tests/gateway/test_gateway_runtime.py uses curl, with no Origin header).
- Fix: `proxy_set_header Host $http_host`. This is safe because the server block is already bound to server_name. Confidence: confirmed by reading. Needs runtime confirmation in a browser.

### G-3 (Medium) CA key retained with no name constraints, and the docs tell users to trust the CA
scripts/gateway.sh:21-26,33.
- `init` creates a 90-day CA with no `nameConstraints` and leaves `ca.key` on disk (mode 0600 under umask 077) in the same directory as the server key and credentials.
- It then suggests importing ca.pem into the browser trust store.
- Theft of ca.key, or any local read of ./.gateway, gives a browser-trusted MITM CA for every site on that browser until it is removed.
- Fix: add `-addext nameConstraints=critical,permitted;DNS:$HOST,permitted;DNS:localhost` to the CA, and delete ca.key after signing, or sign the leaf with a throwaway CA. Confidence: confirmed by reading.

### S-1 (Medium) assert_read_only_spl is a first-word denylist and is bypassable
src/agentsec/splunk_client.py:160-168.
- The check splits on `|` and inspects only the first token of each segment. Bypasses:
  - Subsearch closer: `search x [ search y | delete]` or `[| makeresults | outputlookup f]`. The segment is `delete]`, which is not equal to `delete`, so the check passes. Splunk executes it.
  - Comment prefix: ``| ```c``` delete``` (and ``| `macro` ``). The first token is the comment or macro, so the check passes. Splunk strips the comment, or expands the macro to anything.
  - Commands not in the denylist: `outputtelemetry`, `webhook`, `runshellscript`, `ldapsearch`/`ldapfetch` (app dependent), `curl`-style app commands, `summaryindex`/`sichart`, and others.
  - `savedsearch` and `loadjob` are listed, but generating commands such as `from savedsearch:` and `| from lookup:` are not checked.
- Mitigations seen: the SPL is app-built only (loan_desk/search.py templates, completeness_spl, the diagnose run_id regex). Callers are not user-fed in this diff. The token is documented as search-only and least-privilege, so Splunk RBAC is the real control.
- Verdict: defence in depth that is weaker than it claims. The docstring and module text say "only fixed, read-only SPL ... is accepted". Today that holds only because of the callers. If any future caller passes user text, this guard gives false assurance.
- Fix: allowlist by parsing. Reject any `[`, `]`, backtick, `\n`, or `|` inside quotes, then allowlist the command set. Confidence: confirmed by reading. Bypass strings are derived from the algorithm, not executed.

### S-2 (Low) The wall-clock deadline is not enforced against a slow-drip server
splunk_client.py:184-202.
- `resp.read(65536)` blocks until 64 KiB arrive or EOF. Each socket operation has a 30 s timeout, but a server sending 1 byte per <30 s keeps the read alive for ~65536 x 29 s.
- The deadline is checked only between chunks, and `server_info` has no deadline at all.
- Needs a hostile or compromised Splunk endpoint, and the response is capped at 2 MiB.
- Fix: use read1() or smaller reads, and check the deadline per read. Confidence: confirmed by reading.

### S-3 (Low) validate_config can raise on a bad URL port
splunk_client.py:105.
- `u.port` raises ValueError for e.g. `https://h:abc`, giving an uncaught traceback instead of a classified error.
- config_from_env calls validate_config, so a SplunkError is not raised and callers that catch only SplunkError (default_backend, probe_splunk_count_client) will crash rather than fail closed with UnavailableBackend. Contents are not secret.
- Confidence: confirmed by reading.

### S-4 (Info) Docstring says a CA bundle "may ADD trust"
splunk_client.py:6,181.
- `ssl.create_default_context(cafile=...)` loads only that file and skips the system store. This is stricter, which is good, but it means a Splunk Cloud deployment that supplies a private bundle loses public CAs.
- ProxyHandler is included by default in build_opener, so HTTPS_PROXY in the environment is honoured. The token is still protected by end-to-end TLS (CONNECT).

### W-1 (Low) HSTS on localhost
gateway.conf.template:11.
- `max-age=31536000` is sent even in LOCAL_DEV with a self-signed CA and a host of localhost. HSTS is per host, not per port.
- Browsers may then force https for http://localhost:5000, :18000 and other local dev services, and cannot click through a cert error on localhost:443 for a year.
- Needs runtime confirmation (browser-specific). Fix: send HSTS only for ORG_CERT, or use a short max-age in LOCAL_DEV.

### W-2 (Low) AGENTSEC_GATEWAY_BIND non-loopback only warns
src/agentsec/gateway_config.py:95-97; gateway.sh:36.
- `0.0.0.0` yields a WARN, and exit is 0 whether or not AGENTSEC_GATEWAY_ALLOW_NONLOOPBACK is set. The acknowledgement variable is never enforced as an error, contrary to the "fail-closed" module claim.
- The gateway then publishes on every interface with LOCAL_DEV certs and basic-auth only.
- Fix: make it an ERROR unless the ack variable is set. Confidence: confirmed by reading.

### W-3 (Low) Rate limit and brute-force
- There is no limit on failed basic-auth attempts (limit_req applies only to attack routes). Generated credentials are 96-bit, so this is fine for init-created users. It is not fine for user-supplied htpasswd with weak passwords (validate checks only the hash format).
- X-Forwarded-For spoofing does not bypass the limit, because the key is $binary_remote_addr (sound). But behind any upstream proxy the key collapses to one IP (see G-1).

### W-4 (Low) Regex `$` accepts a trailing newline
gateway/templates/gateway.conf.template:33; attack-enabled.conf:2; attack-disabled.conf:2.
- PCRE `$` matches before a final `\n`, so `/api/launch%0a`, `/health%0a` and `/api/labs/x%0a` match the allowlist. The raw URI is forwarded unchanged to Flask (variable proxy_pass without a URI part passes the original request URI).
- Needs runtime confirmation of the forwarded form.
- Impact looks limited to a Flask 404, because attack routes still require auth_request. Fix: use `\z`, or `(?-m)` with `\z`, or `=` locations.
- Allowlisted regex locations run before the attack include. They do not overlap with attack paths, which I checked.

### W-5 (Low) gateway.env is parsed with eval
scripts/gateway.sh:12; scripts/gateway-ready.sh:13.
- `eval "[ -n \"\${$k+x}\" ]"` takes the key from a file. A key containing shell metacharacters (e.g. `x}"; cmd; echo "${y`) executes code, and a comment line (`#foo=1`) aborts with a bad substitution.
- The file is created by `init` in the user's own dir, so the trust boundary is the user. Still, `load_env` can export PATH, LD_PRELOAD or DOCKER_HOST (anything not already set).
- Fix: validate `k` against `^AGENTSEC_[A-Z_]+$` and use `case`. Confidence: confirmed by reading.

### W-6 (Low) Secrets in process argv
- scripts/gateway.sh:28: `openssl passwd -apr1 "$L"` exposes the password in argv for a moment (use `-stdin`).
- scripts/gateway-ready.sh:60: SPLUNK_PASSWORD goes through `docker exec -e` and then `bash -lc` + `curl -u admin:...` inside the container. This is a pre-existing pattern, with the password visible in ps on the host, and `-k` is loopback only.

### W-7 (Low/Info) credentials.txt holds plaintext credentials
gateway.sh:29. They are 0600 and never printed (sound). `.gateway/` is git-ignored (.gitignore:234). `fullchain.pem` is written by `up` with the default umask (public data only).

### W-8 (Info) Misleading config in gateway mode
- src/agentsec/learn_web.py:20-45: /api/learn/config builds URLs `http://<host>:8000` and `http://<host>:5000`. In gateway mode neither is reachable (Splunk is loopback :18000, AcmeBank is unpublished), and the scheme is http because there is no ProxyFix.
- The SPA references routes the gateway does not allowlist: /academy/status, /academy/path, /academy/labs/*, /api/compare-handoff. These return 404 in gateway mode.
- Needs runtime confirmation. Functional, not security.

### W-9 (Info) docker-compose.gateway.yml publish semantics
- `gateway.sh up` runs `--no-deps gateway attack_service acmebank`, so splunk is NOT recreated. If Splunk was previously up with 8000 on AGENTSEC_BIND_ADDRESS (could be 0.0.0.0), it keeps that mapping until the user recreates it. The docs claim "Splunk Web moves to loopback". Needs runtime confirmation.
- `!reset`/`!override` need Compose 2.24+. Older versions fail or, in some builds, ignore the tag. Documented, but there is no version check in gateway.sh. If the tag were ignored, 5000/5001 would stay published. Check the version before `up`.
- In the base compose, attack_service/acmebank bind to AGENTSEC_BIND_ADDRESS. The overlay removes them. The otel (4317/4318) and HEC 8088 ports stay on 127.0.0.1 (sound).

### B-1 (Info) Backends have no auth; the mesh is a flat trust zone
- attack_service and acmebank listen on 0.0.0.0 inside agentsec_mesh with no auth. Any other container on the mesh (Splunk, otel, ollama, anything added later) can POST to /api/launch directly.
- The header block in identity-headers.conf is informational only. No backend code reads X-Auth-Role or X-Remote-User (grep: no match in src/), so header spoofing is moot.
- request_guard.py itself says network reachability is the access control.

## Checked and found sound
- Default-deny: every location is allowlisted, then `location / { return 404; }`. The attack-disabled tier fails closed (404), and `/api/launch`, `attacks/`, `missions/loan-desk/runs`, `launches/` are not in the learner regex.
- Regex locations match the normalised URI (nginx decodes %2e, %2f and %2F and removes dot segments). `//`, `/learn/..%2fapi/launch` and `;` suffixes resolve to a path the regex rules decide (I did not find an allowlist bypass). Needs runtime confirmation of the raw-URI forwarding (see W-4).
- Role derivation: the `map $remote_user $role` and the auth_request target (127.0.0.1:8081, `X-Authz-User` overwritten by the gateway from $remote_user) cannot be influenced by client headers. Underscore headers are dropped by default. The identity-header block resets Authorization, X-Forwarded-*, X-Remote-*, and X-Forwarded-For is set to $remote_addr (no spoofing and no XFF rate-limit bypass).
- Methods: learner tier GET/HEAD only. Attack tier GET/POST only, 64k body, auth_request 403 for a learner on every method.
- TLS: TLSv1.2/1.3 only; unknown SNI fails the handshake (default server `ssl_reject_handshake`); a valid SNI with the wrong Host reaches the empty default server (no proxy). server_tokens off, absolute_redirect off, X-Content-Type-Options, X-Frame-Options, Referrer-Policy present. No ssl_ciphers override (nginx default is acceptable).
- Host handling: `server_name` is `${AGENTSEC_PUBLIC_HOST}`, restricted by HOST_RE (no `$`, spaces or wildcards). The envsubst filter `^AGENTSEC_` leaves nginx variables alone. The tier is validated to enabled|disabled, so the include path cannot be redirected.
- Cert/htpasswd generation: umask 077, nodes keys only under the gateway dir, no trust-store changes, hashes only in htpasswd (644 because the container reads it), credentials never echoed, plaintext htpasswd refused by validate, key/cert mismatch, expiry, hostname and chain checks implemented (hostname check needs OpenSSL, since LibreSSL lacks `-verify_hostname`).
- Splunk REST client: https only; hostname and certificate verification are always on (default context, no verify=False or CERT_NONE anywhere); `_NoRedirect` returns None and the 3xx maps to redirect_refused, so the token never follows a redirect; the token comes only from a file (<=4 KiB, single line), is excluded from repr, __str__ is redacted, and SplunkError messages are fixed strings (exc raised `from None`, so no URL or token); REST URL rejects userinfo, path, query and fragment; run_id and index validated by regex; 2 MiB response cap; the token file mode is warn-checked; external modes never fall back to docker (UnavailableBackend).
- Learner-reachable data: /api/labs/<id> reads a manifest by id (nginx limits to [A-Za-z0-9_-]), /api/learn/config, /api/academy/status, /api/missions/loan-desk/status, /health. These are read-only and show lab metadata and the internal acmebank URL (Info). Static files are served by Flask's safe static route. I did not find a way for a learner to trigger an attack or read evidence or run data.
- deploy/gateway-poc is a disposable POC (test-only keys, `.runtime/` git-ignored, 30-day certs). I found no real secrets or private keys committed in the new files; the only private-key matches in the tree are in existing test files, which I did not examine.

## Not checked / limits
No runtime execution. I did not read the full tests/, the 15 compiled JS bundles, loan_desk/search.py param validation beyond the diff, or the base docker-compose volume mounts. Did not verify the raw-URI forwarding or auth_request-vs-auth_basic subrequest behaviour (needs runtime confirmation; tests/gateway/test_gateway_runtime.py claims coverage).

## STRIDE threat model
| Asset | Boundary | Threat (STRIDE) | Existing mitigation | Gap |
|---|---|---|---|---|
| Attack launch / loan-desk run (state-changing API) | Internet/LAN -> nginx | S: forged identity headers. T: path tricks. E: learner launches attack | Header overwrite, map role from $remote_user, auth_request 403, regex allowlist, default 404 | Role = username string (no real RBAC); backends unauthenticated (B-1); `$` newline (W-4) |
| Operator availability | nginx | D: rate-limit exhaustion by anonymous or learner | limit_req 6 r/m + 429 | Anonymous consumes budget pre-auth; shared NAT IP; GET polling counted (G-1) |
| Credentials (learner/operator) | Host FS | I: disclosure; S: brute force | 96-bit random, apr1 hash, 0600 credentials.txt, never echoed | No auth-failure throttling; argv exposure (W-6); user-supplied weak passwords accepted |
| TLS private key / CA | Host FS -> container | I/S: key theft, rogue CA | umask 077, :ro mounts, validate perms (warn only) | Unconstrained CA + retained ca.key + "trust it" advice (G-3); key perms only WARN |
| Browser session / origin | Browser <-> gateway | S/T: CSRF, downgrade | Sec-Fetch-Site / Origin check, HSTS, XFO, nosniff | Port-less Host breaks Origin check on 8000 (G-2); HSTS on localhost (W-1) |
| Host exposure | Docker host network | I/E: services reachable externally | Overlay removes 5000/5001 ports; Splunk to loopback; bind defaults to 127.0.0.1 | Non-loopback bind only warns (W-2); Compose <2.24 unchecked; Splunk not recreated (W-9) |
| Splunk REST token | App -> Splunk 8089 | I: token leak; T/S: MITM, redirect; E: write SPL | Strict TLS, no redirects, token file, redacted errors, SPL denylist, 2 MiB cap | SPL denylist bypassable (S-1); slow-drip deadline (S-2); reliance on token RBAC |
| Telemetry / evidence | Collector -> Splunk | R/T: repudiation, tamper | Existing HEC/TLS pieces (out of scope here) | HEC path "NOT exercised" by client (per its own warning) |
| Internal mesh | Container <-> container | E: lateral call to attack_service | Network is private | No service auth; any mesh peer can launch |
