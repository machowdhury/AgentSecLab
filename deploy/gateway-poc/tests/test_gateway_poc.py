"""Gateway POC acceptance tests. Needs the POC stack up (scripts/run_poc.sh up) and docker. Run: pytest deploy/gateway-poc/tests -p no:cacheprovider"""
import json, re, subprocess, time
import pytest
from conftest import CERTS, EVID, MATRIX, PORT, POC, RT, check, creds, curl, protected_snapshot, rec, sh

SNAP = EVID / ".snap" / "protected_before.json"
H = lambda r, n: (r.h(n) or [""])[0]


@pytest.fixture(scope="session", autouse=True)
def snapshot_before():
    if not SNAP.exists():
        SNAP.write_text(json.dumps(protected_snapshot(), indent=1, sort_keys=True))


@pytest.fixture(scope="session")
def stack_up():
    r = curl("learn.poc.test", "/health", user="learner")
    assert r.status == 200, f"stack not up: {r.rc} {r.status} {r.err[:120]}"


def test_t01_exactly_one_published_port(stack_up):
    out = sh("docker", "ps", "--filter", "label=com.docker.compose.project=agentsec-gw-poc", "--format", "{{.Names}}|{{.Ports}}").stdout.strip().splitlines()
    maps = [m for line in out for m in re.findall(r"[\d.:]+:\d+->\d+/tcp", line.split("|", 1)[1])]
    check("T01", maps == [f"127.0.0.1:{PORT}->8443/tcp"] and len(out) == 4, f"published mappings: {maps}; containers: {len(out)}")


def test_t02_backends_not_reachable_from_outside(stack_up):
    net = json.loads(sh("docker", "network", "inspect", "agentsec-gw-poc-backend").stdout)[0]
    ips = {c["Name"]: c["IPv4Address"].split("/")[0] for c in net["Containers"].values()}
    internal = net["Internal"]
    results = []
    for name, port in (("agentsec-gw-poc-attack", 5001), ("agentsec-gw-poc-acmebank", 5000), ("agentsec-gw-poc-splunk-stub", 8000)):
        p = sh("docker", "run", "--rm", "--network", "bridge", "--label", "agentsec.poc=probe", "curlimages/curl:8.5.0", "-sS", "-m", "4", f"http://{ips[name]}:{port}/")
        results.append((name, p.returncode != 0))
    host_try = [sh("curl", "-sS", "-m", "3", f"http://127.0.0.1:{p}/health").returncode != 0 for p in (15001, 15000)]  # unpublished here
    check("T02", internal and all(ok for _, ok in results), f"backend network internal={internal}; outsider-container connections refused: {results}; no host publication (T01)")


def test_t03_academy_over_https(stack_up):
    r = curl("learn.poc.test", "/learn", user="learner")
    check("T03", r.rc == 0 and r.status == 200 and "<div id=\"root\"" in r.body.replace("'", '"') and "strict-transport-security" in r.headers, f"status {r.status}; HSTS present")


def test_t04_canonical_url_and_redirects(stack_up):
    r = curl("learn.poc.test", "/", user="learner")
    r2 = curl("learn.poc.test", "/learn/lab/LAB-HITL-APPROVAL", user="learner")
    check("T04", r.status == 302 and H(r, "location") == "/learn" and ":8443" not in H(r, "location") and r2.status == 200, f"/ -> {r.status} Location {H(r, 'location')!r} (relative, no container port); deep link {r2.status}")


def test_t05_local_dev_cert_valid(stack_up):
    s = sh("openssl", "s_client", "-connect", f"127.0.0.1:{PORT}", "-servername", "learn.poc.test", "-verify_hostname", "learn.poc.test",
           "-CAfile", str(CERTS / "local" / "ca.pem"), "-verify_return_error", input="", timeout=20)
    r = curl("learn.poc.test", "/health", user="learner")
    check("T05", "Verify return code: 0 (ok)" in s.stdout + s.stderr and r.rc == 0, "chain + hostname verified against the disposable local CA only (no trust-store change)")


def _scenario(name, certset, port):
    """Throwaway TLS-only nginx (own container, labelled) serving one certificate set."""
    sh("docker", "rm", "-f", f"agentsec-gw-poc-tls-{name}")
    p = sh("docker", "run", "-d", "--name", f"agentsec-gw-poc-tls-{name}", "--label", "agentsec.poc=tls-scenario", "-p", f"127.0.0.1:{port}:8443",
           "-v", f"{POC}/gateway/tls-probe.conf:/etc/nginx/nginx.conf:ro", "-v", f"{CERTS / certset}:/certs:ro", "nginx:1.27-alpine")
    time.sleep(1.5)
    return p


def _tls(port, ca):
    r = curl("learn.poc.test", "/", ca=ca, port=port)
    return r


def test_t06_org_cert_chain_valid():
    _scenario("org", "org", 18461)
    s = sh("openssl", "s_client", "-connect", "127.0.0.1:18461", "-servername", "learn.poc.test", "-verify_hostname", "learn.poc.test", "-CAfile", str(CERTS / "org" / "ca.pem"), "-verify_return_error", "-showcerts", input="", timeout=20)
    r = _tls(18461, CERTS / "org" / "ca.pem")
    depth = s.stdout.count("BEGIN CERTIFICATE")
    check("T06", r.rc == 0 and "tls-ok" in r.body and "Verify return code: 0 (ok)" in s.stdout + s.stderr and depth == 2, f"server sent {depth} certs (leaf + intermediate); client trusts only the root file")


def test_t07_expired_fails():
    _scenario("expired", "bad-expired", 18462); r = _tls(18462, CERTS / "org" / "ca.pem")
    check("T07", r.rc == 60 and "expired" in r.err.lower(), f"curl rc {r.rc}: {r.err.strip()[:90]}")


def test_t08_wrong_hostname_fails():
    _scenario("hostname", "bad-hostname", 18463); r = _tls(18463, CERTS / "org" / "ca.pem")
    check("T08", r.rc == 60 and ("no alternative certificate subject name" in r.err.lower() or "does not match" in r.err.lower()), f"curl rc {r.rc}: {r.err.strip()[:90]}")


def test_t09_wrong_ca_fails():
    r = _tls(18461, CERTS / "local" / "ca.pem")       # org-issued server certificate, client trusting only the other CA
    check("T09", r.rc == 60 and "issuer" in r.err.lower(), f"curl rc {r.rc}: {r.err.strip()[:90]}")


def test_t10_mismatched_key_refused():
    p = sh("docker", "run", "--rm", "--label", "agentsec.poc=tls-scenario", "-v", f"{POC}/gateway/tls-probe.conf:/etc/nginx/nginx.conf:ro", "-v", f"{CERTS / 'bad-mismatch'}:/certs:ro", "nginx:1.27-alpine", "nginx", "-t")
    check("T10", p.returncode != 0 and "mismatch" in (p.stderr + p.stdout).lower(), "nginx refuses to load a certificate whose private key does not match")


def test_t11_anonymous_attack_denied(stack_up):
    a = curl("learn.poc.test", "/api/launch", method="POST", data="{}", headers=["Content-Type: application/json"])
    b = curl("learn.poc.test", "/api/launch", method="POST", data="{}", headers=["Authorization: Basic Ym9ndXM6Ym9ndXM="])
    check("T11", a.status == 401 and b.status == 401, f"anonymous {a.status}, wrong credentials {b.status}")


def wait_bucket():
    """The attack tier is rate-limited per client; wait until the bucket refills so functional tests are not 429."""
    for _ in range(40):
        if curl("learn.poc.test", "/api/missions/loan-desk/search/templates", user="operator").status != 429:
            time.sleep(11); return                      # one more token (6 requests/minute) so the next call is certain to pass
        time.sleep(3)


def test_t12_role_separation(stack_up):
    wait_bucket()
    j = ["Content-Type: application/json"]
    l = curl("learn.poc.test", "/api/launch", user="learner", method="POST", data="{}", headers=j)
    l2 = curl("learn.poc.test", "/api/missions/loan-desk/runs", user="learner", method="POST", data="{}", headers=j)
    o = curl("learn.poc.test", "/api/launch", user="operator", method="POST", data="{}", headers=j)
    check("T12", l.status == 403 and l2.status == 403 and o.status not in (401, 403, 404, 502), f"learner {l.status}/{l2.status}; operator reached the app: {o.status}")


def test_t13_unknown_routes_fail_closed(stack_up):
    codes = {p: curl("learn.poc.test", p, user="operator").status for p in ("/api/allowlist", "/api/compare-handoff", "/api/academy/evidence/x", "/nonexistent", "/admin")}
    post = curl("learn.poc.test", "/learn", user="operator", method="POST", data="{}").status
    bank_post = curl("bank.poc.test", "/health", user="operator", method="POST", data="{}").status
    sni = curl("other.poc.test", "/", user="operator")
    check("T13", all(c == 404 for c in codes.values()) and post == 403 and bank_post == 403 and sni.rc != 0, f"unlisted GETs {sorted(set(codes.values()))}; POST to read tier {post}; unknown SNI handshake rc {sni.rc}")


def test_t14_spoofed_identity_headers(stack_up):
    wait_bucket()
    sp = ["X-Remote-User: operator", "X-Auth-Role: operator", "X-Forwarded-User: operator", "X-Remote-Groups: admins", "Content-Type: application/json"]
    r = curl("learn.poc.test", "/api/launch", user="learner", method="POST", data="{}", headers=sp)
    e = curl("splunk.poc.test", "/_echo", user="learner", headers=sp[:4])
    got = json.loads(e.body)
    ok = r.status == 403 and got.get("x-remote-user") == "learner" and not got.get("x-forwarded-user") and not got.get("x-remote-groups") and "authorization" not in got
    check("T14", ok, f"spoofed role still {r.status}; backend saw x-remote-user={got.get('x-remote-user')!r}, forwarded-user={got.get('x-forwarded-user')!r}, authorization present={'authorization' in got}")


def test_t25_rate_limit(stack_up):
    codes = [curl("learn.poc.test", "/api/launch", user="operator", method="POST", data="{}", headers=["Content-Type: application/json"]).status for _ in range(14)]
    check("T25", 429 in codes, f"statuses {sorted(set(codes))}; first 429 after {codes.index(429) if 429 in codes else '-'} requests")


def _splunk_flow(tmp_path):
    jar = tmp_path / "jar.txt"; out = {}
    out["login_page"] = curl("splunk.poc.test", "/en-US/account/login", user="learner", jar=jar)
    sp = creds()["STUB_PASSWORD"]
    out["login"] = curl("splunk.poc.test", "/en-US/account/login", user="learner", jar=jar, method="POST", data=f"username=poc-splunk&password={sp}", headers=["Content-Type: application/x-www-form-urlencoded"])
    out["bad_login"] = curl("splunk.poc.test", "/en-US/account/login", user="learner", jar=tmp_path / "j2.txt", method="POST", data="username=poc-splunk&password=wrong")
    out["home"] = curl("splunk.poc.test", "/en-US/app/agentsec/home", user="learner", jar=jar)
    tok = "stubcsrf-token-1"
    out["csrf_ok"] = curl("splunk.poc.test", "/en-US/splunkd/__raw/action", user="learner", jar=jar, method="POST", data="x=1", headers=[f"X-Splunk-Form-Key: {tok}"])
    out["csrf_missing"] = curl("splunk.poc.test", "/en-US/splunkd/__raw/action", user="learner", jar=jar, method="POST", data="x=1")
    out["csrf_wrong"] = curl("splunk.poc.test", "/en-US/splunkd/__raw/action", user="learner", jar=jar, method="POST", data="x=1", headers=["X-Splunk-Form-Key: forged"])
    out["static"] = curl("splunk.poc.test", "/static/app/x.js", user="learner")
    out["logout"] = curl("splunk.poc.test", "/en-US/account/logout", user="learner", jar=jar)
    out["after_logout"] = curl("splunk.poc.test", "/en-US/app/agentsec/home", user="learner", jar=jar)
    return out


@pytest.fixture(scope="module")
def sp(stack_up, tmp_path_factory):
    return _splunk_flow(tmp_path_factory.mktemp("splunk"))


NOTE = "STUB PROXY-BEHAVIOUR ONLY; real Splunk Web NOT run (resource gate: a second Splunk would risk the protected lab)"


def test_t15_t16_t17_splunk_proxy_mechanics_against_stub(sp):
    ok15 = sp["login_page"].status == 200 and sp["login"].status == 303 and sp["home"].status == 200 and sp["bad_login"].status == 401
    ck = " ".join(sp["login_page"].h("set-cookie")).lower(); sk = " ".join(sp["login"].h("set-cookie")).lower()
    ok16 = "secure" in ck and "samesite=lax" in ck and "secure" in sk and "httponly" in sk and sp["csrf_ok"].status == 200 and sp["csrf_missing"].status == 403 and sp["csrf_wrong"].status == 403
    loc = H(sp["login"], "location"); loc2 = H(sp["logout"], "location")
    ok17 = loc == f"https://splunk.poc.test:{PORT}/en-US/app/agentsec/home" and "splunk-stub" not in loc + loc2 and ":8443" not in loc + loc2 and sp["static"].status == 200 and "javascript" in H(sp["static"], "content-type") \
        and any("max-age=0" in c.lower() for c in sp["logout"].h("set-cookie")) and sp["after_logout"].status == 303
    for tid, ok, what in (("T15", ok15, "login page, form login with disposable credentials, wrong password rejected, session page"), ("T16", ok16, "Secure/SameSite added without HttpOnly on the CSRF cookie; CSRF header honoured and forged/missing header rejected"),
                          ("T17", ok17, f"redirects rewritten to the gateway ({loc!r}), static asset served, logout clears the cookie and the session page then redirects")):
        rec(tid, "NOT VERIFIED" if ok else "FAIL", f"{what}: stub mechanics {'PASS' if ok else 'FAIL'}. {NOTE}")
    assert ok15 and ok16 and ok17, {k: v.status for k, v in sp.items()}


def test_t21_t22_protected_lab_unchanged(stack_up):
    before = json.loads(SNAP.read_text()); after = json.loads(json.dumps(protected_snapshot()))   # JSON round-trip: tuples vs lists
    check("T21", before["containers"] == after["containers"] and before["networks"] == after["networks"], f"{len(after['containers'])} protected containers: same ids, images, start times, restart counts, mounts, networks")
    vols_same = before["volume_created"] == after["volume_created"]
    check("T22", vols_same, f"{len(after['volume_created'])} non-POC volumes: same set and creation times (index event count not re-queried in this run)")


def test_t23_no_secrets_in_git_or_logs(stack_up):
    c = creds(); secrets = [v for v in c.values() if len(v) >= 12]
    files = sh("git", "-C", str(POC), "ls-files", "--others", "--exclude-standard", "--cached", "--", str(POC)).stdout.split()
    leaks, keyblocks = [], []
    root = sh("git", "-C", str(POC), "rev-parse", "--show-toplevel").stdout.strip()
    for f in files:
        try: t = open(f"{root}/{f}", encoding="utf-8", errors="ignore").read()
        except OSError: continue
        if "PRIVATE KEY-----" in t and f.endswith((".pem", ".key")): keyblocks.append(f)
        if any(s in t for s in secrets): leaks.append(f)
    logs = "".join(sh("docker", "logs", n).stdout + sh("docker", "logs", n).stderr for n in ("agentsec-gw-poc-gateway", "agentsec-gw-poc-attack", "agentsec-gw-poc-acmebank", "agentsec-gw-poc-splunk-stub"))
    ignored = sh("git", "-C", str(POC), "check-ignore", str(RT / "creds.env")).returncode == 0
    ok = not leaks and not keyblocks and not any(s in logs for s in secrets) and ignored
    check("T23", ok, f"scanned {len(files)} non-ignored files and 4 container logs for the generated passwords and key blocks; runtime dir git-ignored={ignored}")


def test_resources_snapshot(stack_up):
    st = sh("docker", "stats", "--no-stream", "--format", "{{.Name}} cpu={{.CPUPerc}} mem={{.MemUsage}}").stdout.strip().splitlines()
    imgs = sh("docker", "images", "--format", "{{.Repository}}:{{.Tag}} {{.Size}}").stdout.splitlines()
    (EVID / "resources.txt").write_text("\n".join([l for l in st if "agentsec-gw-poc" in l] + [l for l in imgs if "agentsec-gw-poc" in l or l.startswith(("nginx:1.27", "python:3.12-alpine"))]) + "\n")
