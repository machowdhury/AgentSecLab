| ID | Test | Result | Evidence / note |
|---|---|---|---|
| T01 | Exactly one published application ingress port | PASS | published mappings: ['127.0.0.1:18443->8443/tcp']; containers: 4 |
| T02 | No direct external access to backend service ports | PASS | backend network internal=True; outsider-container connections refused: [('agentsec-gw-poc-attack', True), ('agentsec-gw-poc-acmebank', True), ('agentsec-gw-poc-splunk-stub', True)]; no host publication (T01) |
| T03 | Academy loads through HTTPS | PASS | status 200; HSTS present |
| T04 | Canonical URL and redirects work | PASS | / -> 302 Location '/learn' (relative, no container port); deep link 200 |
| T05 | Valid LOCAL_DEV certificate succeeds | PASS | chain + hostname verified against the disposable local CA only (no trust-store change) |
| T06 | Valid simulated ORG_CERT succeeds | PASS | server sent 2 certs (leaf + intermediate); client trusts only the root file |
| T07 | Expired certificate fails | PASS | curl rc 60: curl: (60) SSL certificate problem: certificate has expired More details here: https://cur |
| T08 | Wrong-hostname certificate fails | PASS | curl rc 60: curl: (60) SSL: no alternative certificate subject name matches target host name 'learn.po |
| T09 | Wrong-CA certificate fails | PASS | curl rc 60: curl: (60) SSL certificate problem: unable to get local issuer certificate More details he |
| T10 | Mismatched certificate/key fails | PASS | nginx refuses to load a certificate whose private key does not match |
| T11 | Anonymous attack request is denied | PASS | anonymous 401, wrong credentials 401 |
| T12 | Unauthorized role cannot execute privileged operations | PASS | learner 403/403; operator reached the app: 400 |
| T13 | Unknown routes fail closed | PASS | unlisted GETs [404]; POST to read tier 403; unknown SNI handshake rc 35 |
| T14 | Spoofed identity headers do not grant access | PASS | spoofed role still 403; backend saw x-remote-user='learner', forwarded-user=None, authorization present=False |
| T15 | Splunk Web login works through gateway | NOT VERIFIED | login page, form login with disposable credentials, wrong password rejected, session page: stub mechanics PASS. STUB PROXY-BEHAVIOUR ONLY; real Splunk Web NOT run (resource gate: a second Splunk would risk the protected lab) |
| T16 | Splunk cookies and CSRF function correctly | NOT VERIFIED | Secure/SameSite added without HttpOnly on the CSRF cookie; CSRF header honoured and forged/missing header rejected: stub mechanics PASS. STUB PROXY-BEHAVIOUR ONLY; real Splunk Web NOT run (resource gate: a second Splunk would risk the protected lab) |
| T17 | Splunk redirects and static assets work | NOT VERIFIED | redirects rewritten to the gateway ('https://splunk.poc.test:18443/en-US/app/agentsec/home'), static asset served, logout clears the cookie and the session page then redirects: stub mechanics PASS. STUB PROXY-BEHAVIOUR ONLY; real Splunk Web NOT run (resource gate: a second Splunk would risk the protected lab) |
| T18 | External Splunk mock accepts valid CA configuration | PASS | strict REST probe over TLS with the mock's CA bundle and a token read from a file: {'splunk_attempted': True, 'splunk_ok': True, 'splunk_count': 3, 'error': None}. MOCK ONLY; not real Splunk |
| T19 | Invalid external CA fails closed | PASS | wrong CA -> tls_verification_failed; hostname mismatch -> tls_verification_failed; missing CA file -> probe_misconfigured; http:// URL -> probe_misconfigured; none reported success |
| T20 | Invalid external token fails authentication | PASS | invalid token -> probe_auth_failed; connection refused -> splunk_probe_failed |
| T21 | Existing running AgentSecLab containers remain unchanged | PASS | 7 protected containers: same ids, images, start times, restart counts, mounts, networks |
| T22 | Existing Splunk volumes and indexes remain unchanged | PASS | 25 non-POC volumes: same set and creation times; agentsec_telemetry index count read-only query = 3,986 after the POC (also 3,986 at the earlier diagnosis); the two anonymous Splunk volumes were not touched |
| T23 | No private keys, credentials or tokens in Git changes or logs | PASS | scanned 15 non-ignored files and 4 container logs for the generated passwords and key blocks; runtime dir git-ignored=True |
| T24 | POC resources can be removed independently without touching the existing lab | PASS | cleanup rc 0; POC containers/images/networks left: 0/0/0; .runtime removed; protected lab snapshot identical (containers, mounts, networks, 25 volumes) |
| T25 | Rate limit applies to privileged attack operations | PASS | statuses [429]; first 429 after 0 requests |
