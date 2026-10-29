# Milestone 2: real Splunk gateway validation (preparation, phases 1, 2, 4, 5; phase 3 awaits approval)

Status of each phase: **P1 done. P2 proposal below, awaiting approval. P3 NOT RUN (needs the approved isolated host). P4 partly done locally. P5 assessed below.**

## Phase 2: environment proposal (nothing provisioned)
The current Mac is not used: its Docker VM has 11.66 GiB and the protected lab's Splunk alone uses 5.9 GiB (measured, emulated amd64, idle, 3,986 events). Resizing Docker Desktop would restart the protected lab. The existing EC2 lab host (t3.2xlarge, 150 GiB gp3) is also protected and is not reused.

| Item | Proposal |
|---|---|
| Region / type | us-east-2, `m6i.xlarge` (4 vCPU, 16 GiB, x86_64, non-burstable; checked with `describe-instance-types`) |
| Memory budget | Splunk about 8 GiB (measured 5.9 GiB emulated), gateway + backends + stub about 0.5 GiB, OS and Docker about 1.5 GiB, so 16 GiB leaves headroom |
| Disk | 60 GiB gp3 root, delete on termination (Splunk image 1.9 GB plus `var`) |
| OS / software | Ubuntu 24.04 LTS (AMI from the Canonical public SSM parameter), `docker.io` + compose plugin, this repository's `deploy/gateway-poc` branch |
| Access | SSM Session Manager only (port-forward to the gateway's 18443); no key pair; reuse the existing instance profile `AmazonSSMRoleForInstancesQuickSetup` (no IAM change; that it grants SSM core is **NOT VERIFIED**) |
| Network | A new security group with **zero inbound rules** (requires approval); outbound HTTPS for image pulls and SSM; public IP only for outbound |
| Lifetime | 4 h target; `InstanceInitiatedShutdownBehavior=terminate` plus `shutdown -h +300` as a fuse |
| Teardown | Terminate the instance, delete the security group, confirm no volumes, ENIs or addresses remain |
| Cost (list price, **not verified live**) | on-demand about $0.192/h x 4 h = $0.77; EBS about $0.03; public IPv4 about $0.02; **about $0.82, cap $2**. Spot was $0.064/h in us-east-2b when checked (about $0.26) but can be interrupted mid-test, so on-demand is recommended |
| Approvals needed | create instance; create the zero-inbound security group; attach the existing instance profile; cost cap and 4 h limit |

## Phase 3: real Splunk test plan (NOT RUN)
Same gateway and hostnames, `splunk/splunk:10.2` in place of the stub, disposable admin password from the runtime dir, tests via Playwright (Chromium launched with the POC CA trusted through a per-run profile, never `--ignore-certificate-errors`) plus curl.

| ID | Check | Pass criterion |
|---|---|---|
| S01 | Login page and form login through `https://splunk.poc.test:<port>` | 200, login succeeds, lands on Splunk Home on the gateway hostname |
| S02 | Cookies | `splunkweb_csrf_token_*` and `session_id_*` set with Secure and SameSite; session cookie HttpOnly; no cookie scoped to an internal host; cookie names and ports behave when the public port differs from 8000 |
| S03 | CSRF | a POST with the correct `X-Splunk-Form-Key` succeeds; forged or missing key is rejected; nothing bypassed |
| S04 | Redirects | every `Location` stays on the gateway host and port, including login, logout and `/` redirects |
| S05 | Static assets and JavaScript | no 4xx/5xx and no console errors on the home and search pages |
| S06 | App navigation | the `agentsec` app and its dashboards load (app must be installed) |
| S07 | Search UI | run a search over a test index; results render; job polling works |
| S08 | Logout and expiry | logout clears the session; a request after logout redirects to login; an expired session is rejected |
| S09 | WebSocket / streaming | whether Splunk 10.2 uses WebSockets here, and that the upgrade headers pass; otherwise record "not applicable" |
| S10 | Browser console and network | zero unexpected errors; list any warnings |
| S11 | Hostname and port | no absolute URL to the container host or port; works on 8443 and on 443 |
| S12 | TLS | all client verification on; the gateway-to-Splunk hop is internal HTTP or verified TLS, never skip-verify |

Splunk security controls are not weakened (default `web.conf`, `tools.proxy`/`root_endpoint` changes only if a test proves they are required, and then recorded as a finding).

## Phase 4: regression checks run in this milestone
| Check | Result |
|---|---|
| Only the gateway port is published; backends isolated | PASS (T01, T02 re-run) |
| Unknown hosts and unknown routes | PASS (T13) |
| Unauthorized users cannot launch attacks | PASS (T11, T12) |
| Spoofed identity headers | PASS (T14) |
| Certificate and authentication tests | all 22 original executed tests PASS again after the allowlist change |
| Allowlist vs the actual application routes | **R1 PASS, R2 PASS, R3 PASS after a fix (below)** |
| Backend isolation, protected lab unchanged | PASS (T21, T22, T24; uptimes unchanged) |

**Finding and gateway change.** Crawling 16 Academy pages in Chromium showed the UI calls `GET /api/labs/<lab_id>` and `GET /api/missions/loan-desk/status`. The first allowlist blocked both for a learner (the second was in the operator-only tier, the first was denied). Both are read-only, so they moved to the read tier; the attack tier now contains only `search/templates`, run reads and the six POST routes. Route classification (`evidence/route_classification.json`): 38 route/method pairs; read tier 10, attack tier 11, denied 17. `POST /api/compare-handoff` is denied and was not seen in the crawl; whether any feature needs it is **NOT VERIFIED**. The crawl ran against the direct app on loopback, not through the gateway (Chromium cannot trust the POC CA without changing a trust store).

## Phase 5: enterprise readiness
| Capability | Status |
|---|---|
| Organization-provided TLS certificate (cert, key, chain from files) | **VERIFIED** with a simulated private CA (valid and four failure modes). Real enterprise certificates, CA chains with CRL/OCSP, and rotation NOT VERIFIED |
| Certificate rotation | **NOT VERIFIED** (nginx reload picks up files; not tested with a changing certificate) |
| OIDC | **NOT VERIFIED**. Only basic auth and an `auth_request` role check were tested; OIDC needs an identity provider and its own tests |
| Enterprise reverse proxy / load balancer termination (EDGE_TERMINATED) | **NOT VERIFIED**, not implemented |
| External Splunk Enterprise connectivity | strict-TLS REST probe against a mock **VERIFIED as a contract**; real Splunk Enterprise **NOT VERIFIED** |
| Splunk Cloud | **BLOCKED** until the supported REST/HEC/app-install paths for a given stack are confirmed (needs a stack and Splunk's documentation; not available here) |
| Splunk Web through the gateway | stub **VERIFIED**; real Splunk **NOT VERIFIED** (phase 3) |
| Splunk SSO behind a proxy | **NOT VERIFIED** |
| Persistent data preservation and rollback | preservation of the protected lab's volumes **VERIFIED** for the POC; migration/rollback for a real deployment NOT VERIFIED (the existing lab uses anonymous Splunk volumes; the v1.2.0 compose uses named ones, which `lab-up.sh` refuses to adopt without `--fresh-splunk-data`) |

## Updated architecture decisions
- D1 unchanged: one gateway, host-based routing.
- D2 (new detail): the read tier is defined by what the Academy actually calls (R3), not by a guess; keep this crawl as a required test whenever the UI changes.
- D3: authorization uses `auth_request` after authentication; header sanitising is a shared include.
- D4: Splunk Web gets its own hostname with gateway authentication in front of Splunk's login (double login, to be assessed in S01-S04).
- D5: real Splunk Web proxying remains a hypothesis until phase 3.

## GO / NO-GO
- **Integrating the gateway into AgentSecLab: NO-GO today.** Real Splunk Web is untested, the HEC/collector and docker-exec search paths are unchanged, and auth is basic only.
- **Proceeding to phase 3 on the approved isolated host: GO** (estimated cost about $0.82, capped at $2).

## Recommended sequence
1. Approve the host proposal; run phase 3 (S01-S12) once, record findings, tear down.
2. Fix gateway issues the real run exposes.
3. Config contract plus `validate` command; static no-skip-verify check.
4. Strict REST search backend replacing docker-exec; external Splunk exporter and CA bundle.
5. OIDC and ORG_CERT/EDGE_TERMINATED prototypes with rotation tests.
6. Integrate the gateway behind a compose profile; keep the protected-lab invariants as release gates.
