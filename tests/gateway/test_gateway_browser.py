"""Browser acceptance through the ISOLATED HTTPS gateway (project agentsec-gw-dev): state-changing requests made by a real browser, on 443 and on a
non-standard port, plus negative origin/host tests. The RC1 qualification found that a browser POST to /api/launch was rejected with 403
cross_origin_rejected on every non-443 port (including 8000) because the gateway dropped the port from Host; curl-based tests never saw it because
curl sends no Origin header. These tests drive a real Chromium so the browser's own Origin/Sec-Fetch-Site headers are in play.

Chromium trusts only the exact public key of the test server certificate (--ignore-certificate-errors-spki-list); chain and hostname validation are
proven with openssl/curl in test_gateway_runtime.py. Skipped (never passed) without playwright, AGENTSEC_CHROMIUM or the runtime opt-in."""
import base64, hashlib, json, os, subprocess, time
import pytest
from gwhelpers import needs_docker, needs_openssl, sh
from test_gateway_runtime import HOST, PORT, stack  # noqa: F401  (the module-scoped isolated stack fixture)

sync_api = pytest.importorskip("playwright.sync_api", reason="playwright not installed: browser acceptance NOT VERIFIED")
CHROMIUM = os.environ.get("AGENTSEC_CHROMIUM")
pytestmark = [needs_docker, needs_openssl,
              pytest.mark.skipif(os.environ.get("AGENTSEC_GATEWAY_RUNTIME_TESTS") != "1", reason="opt-in: starts an isolated compose project; set AGENTSEC_GATEWAY_RUNTIME_TESTS=1"),
              pytest.mark.skipif(not CHROMIUM, reason="AGENTSEC_CHROMIUM not set: browser acceptance NOT VERIFIED")]
LAUNCH = {"lab_id": "LAB-PI-001", "specimen_id": "ATK-002", "mode": "ATTACK", "execution": "live"}


def _spki(port):
    pem = subprocess.run(["openssl", "s_client", "-connect", f"127.0.0.1:{port}", "-servername", HOST], input="", capture_output=True, text=True).stdout
    pub = subprocess.run(["openssl", "x509", "-pubkey", "-noout"], input=pem[pem.index("-----BEGIN CERT"):], capture_output=True, text=True).stdout
    der = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "der"], input=pub.encode(), capture_output=True).stdout
    return base64.b64encode(hashlib.sha256(der).digest()).decode()


def _browser(p, port, *, via=None):
    """via: connect to this real loopback port while the page's origin keeps `port` (Chromium maps host:port to host:via), so the 8000 deployment can be
    exercised with its real https://host:8000 origin without binding host port 8000."""
    rules = f"MAP {HOST} 127.0.0.1" if via is None else f"MAP {HOST}:{port} 127.0.0.1:{via}"
    return p.chromium.launch(executable_path=CHROMIUM, args=[f"--host-resolver-rules={rules}", f"--ignore-certificate-errors-spki-list={_spki(via or port)}"])


def _origin(port):
    return f"https://{HOST}" + ("" if port == 443 else f":{port}")


def _operator(browser):
    return browser.new_context(http_credentials={"username": "operator", "password": "o-pass"}).new_page()


def _post(page, path, body):
    """A same-origin fetch from the Academy page: the browser adds Origin / Sec-Fetch-Site itself."""
    return page.evaluate("""async ([path, body]) => { const r = await fetch(path, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
                            return [r.status, await r.json().catch(() => null)]; }""", [path, body])


def _browser_attack(stack, port, *, via=None):
    with sync_api.sync_playwright() as p:
        b = _browser(p, port, via=via)
        page = _operator(b)
        page.goto(f"{_origin(port)}/learn/loan-desk/prepare", wait_until="networkidle")
        # 1. the real UI control: "Run normal application" POSTs /api/missions/loan-desk/runs
        time.sleep(12)  # let the attack-tier bucket refill after earlier tests
        with page.expect_response(lambda r: r.request.method == "POST" and "/api/missions/loan-desk/runs" in r.url, timeout=60000) as info:
            page.get_by_role("button", name="Run normal application").click()
        ui = info.value
        ui_body = ui.json() if ui.headers.get("content-type", "").startswith("application/json") else {}
        assert ui.status != 403 and ui_body.get("error") != "cross_origin_rejected", (ui.status, ui_body)
        assert ui.request.headers.get("origin") == _origin(port)  # the browser really sent the port-carrying Origin
        # 2. the attack launch itself
        time.sleep(12)
        status, body = _post(page, "/api/launch", LAUNCH)
        assert status == 200 and body["execution_mode"] == "LIVE" and body["lab_id"] == "LAB-PI-001", (status, body)
        assert body.get("error") != "cross_origin_rejected"
        b.close()


def test_browser_attack_launch_works_on_a_non_standard_https_port(stack):
    assert PORT != 443 and stack.port == PORT
    _browser_attack(stack, PORT)


def test_browser_attack_launch_works_on_443(stack):
    try:
        stack.up_gateway(AGENTSEC_PUBLIC_PORT="443")
    except AssertionError as e:  # port 443 occupied on this machine: an existing service is never interrupted
        pytest.skip(f"host port 443 not available: {e}")
    try:
        assert stack.port == 443
        _browser_attack(stack, 443)
    finally:
        stack.up_gateway(AGENTSEC_PUBLIC_PORT=str(PORT))


def test_a_cross_site_page_cannot_launch_even_when_the_operator_is_signed_in(stack):
    time.sleep(12)
    with sync_api.sync_playwright() as p:
        b = _browser(p, PORT)
        ctx = b.new_context(http_credentials={"username": "operator", "password": "o-pass"})
        page = ctx.new_page()
        page.goto(f"{_origin(PORT)}/learn", wait_until="networkidle")        # the operator is authenticated to the gateway in this context
        # an attacker page on another origin (served by interception; no network) auto-submits a form to the launch endpoint: a top-level cross-site
        # POST navigation, which carries the browser's cached credentials. (A cross-site fetch() would be blocked by the browser's own loopback
        # protection before it ever reached the server, which would prove nothing about the guard.)
        evil = "https://evil.test/"
        page.route(evil, lambda route: route.fulfill(status=200, content_type="text/html", body="<html><body>x</body></html>"))
        page.goto(evil)
        with page.expect_response(lambda r: "/api/launch" in r.url, timeout=30000) as info:
            page.evaluate("""(url) => { const f = document.createElement('form'); f.method = 'POST'; f.action = url; f.enctype = 'text/plain';
                             const i = document.createElement('input'); i.name = '{"lab_id":"LAB-PI-001","specimen_id":"ATK-002","mode":"ATTACK","execution":"live","x":"'; i.value = '"}';
                             f.appendChild(i); document.body.appendChild(f); f.submit(); }""", f"{_origin(PORT)}/api/launch")
        r = info.value
        assert r.request.headers.get("origin") == "https://evil.test"
        # refused by the gateway itself (nginx page, rewrite phase, before authorization and before the attack quota), not by the backend's JSON guard
        assert r.status == 403 and "nginx" in r.text() and "cross_origin_rejected" not in r.text(), (r.status, r.text()[:150])
        b.close()


def test_mismatched_origins_and_hosts_are_refused(stack):
    j = ["Content-Type: application/json"]
    body = json.dumps(LAUNCH)
    cases = {  # label -> (extra headers, expected status, expected error)
        "port dropped from Origin": ([f"Origin: https://{HOST}"], 403, "cross_origin_rejected"),
        "other port in Origin": ([f"Origin: https://{HOST}:{PORT + 1}"], 403, "cross_origin_rejected"),
        "other host in Origin": ([f"Origin: https://evil.test:{PORT}"], 403, "cross_origin_rejected"),
        "userinfo trick in Origin": ([f"Origin: https://{HOST}:{PORT}@evil.test"], 403, "cross_origin_rejected"),
        "http scheme-less null Origin": (["Origin: null"], 403, "cross_origin_rejected"),
        "cross-site Sec-Fetch-Site": (["Sec-Fetch-Site: cross-site"], 403, "cross_origin_rejected"),
    }
    for label, (hdr, want_status, want_err) in cases.items():
        time.sleep(12)
        r = stack.curl("/api/launch", user="operator", method="POST", data=body, headers=j + hdr)
        # the gateway refuses these itself (nginx page, before authorization and the quota); the backend guard behind it is covered by tests/test_launch_guard.py
        assert r.status == want_status and "nginx" in r.body and want_err not in r.body, (label, r.status, r.body[:120])
    time.sleep(12)
    ok = stack.curl("/api/launch", user="operator", method="POST", data=body, headers=j + [f"Origin: {_origin(PORT)}"])
    assert ok.status == 200 and "cross_origin_rejected" not in ok.body, (ok.status, ok.body[:120])
    # a Host with the wrong port is refused by the gateway itself, before any backend sees it
    for host in (f"{HOST}:{PORT + 1}", f"{HOST}:443", f"{HOST}:abc", f"{HOST}:"):
        r = stack.curl("/health", user="learner", headers=[f"Host: {host}"])
        assert r.status == 421, (host, r.status)
    assert stack.curl("/health", user="learner", headers=[f"Host: {HOST}:{PORT}"]).status == 200
    assert stack.curl("/health", user="learner", headers=[f"Host: {HOST.upper()}:{PORT}"]).status == 200       # hostnames are case-insensitive
    # a forwarding header from the client never changes the authority the backend sees or the authorization decision
    r = stack.curl("/api/launch", user="learner", method="POST", data=body, headers=j + ["X-Forwarded-Host: evil.test", "X-Forwarded-Port: 1", f"Origin: {_origin(PORT)}"])
    assert r.status == 403


ROUTES = ["/learn", "/learn/path", "/learn/foundations", "/learn/curriculum", "/learn/mastery", "/learn/mcp", "/learn/assurance", "/learn/lab/LAB-MCP-001", "/learn/lab/LAB-PI-001",
          "/learn/lab/LAB-HITL-APPROVAL", "/learn/loan-desk", "/learn/loan-desk/prepare", "/learn/loan-desk/attack", "/learn/loan-desk/investigate", "/learn/loan-desk/retest",
          "/learn/evals", "/learn/evals/catalog", "/learn/evals/results", "/learn/evals/findings", "/learn/evals/export", "/learn/risk", "/learn/risk/register",
          "/learn/risk/method", "/learn/risk/new", "/learn/governance", "/learn/governance/frameworks", "/learn/governance/threats", "/learn/governance/export"]


def test_every_link_the_academy_offers_through_the_gateway_is_implemented_by_it(stack):
    """RC1 L-1: no navigation or configuration link may point at a route the gateway does not implement (classic Academy pages, Splunk Web, AcmeBank)."""
    origin = _origin(PORT)
    cfg = stack.curl("/api/learn/config", user="learner")
    assert cfg.status == 200 and json.loads(cfg.body)["gateway"] is True and json.loads(cfg.body)["urls"] == {"splunk_web": None, "acmebank": None}
    seen, dead, foreign, queue = set(), [], [], list(ROUTES)
    with sync_api.sync_playwright() as p:
        b = _browser(p, PORT)
        ctx = b.new_context(http_credentials={"username": "learner", "password": "l-pass"})
        page = ctx.new_page()
        while queue and len(seen) < 120:
            route = queue.pop(0)
            if route in seen: continue
            seen.add(route)
            resp = page.goto(origin + route, wait_until="networkidle")
            assert resp is not None and resp.status == 200, (route, resp and resp.status)        # an nginx error page has no anchors and would otherwise pass
            hrefs = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
            assert not page.get_by_text("Open in Splunk").count() and not page.get_by_role("link", name="System Status").count(), route
            for h in sorted(set(hrefs)):
                if h.startswith(origin + "/") or h == origin:
                    path = h[len(origin):].split("#")[0] or "/"
                    status = page.evaluate("p => fetch(p).then(r => r.status)", path)       # in the page, so Chromium's host mapping and trust apply
                    if status != 200: dead.append((route, path, status))
                    if path.startswith("/learn") and path.split("?")[0] not in seen and path.split("?")[0] not in queue: queue.append(path.split("?")[0])
                elif h.startswith(("http://", "https://")):
                    host = h.split("/")[2]
                    if host.split(":")[0] == HOST: foreign.append((route, h))          # same machine, another port: a service the gateway does not publish
                elif not h.startswith(("mailto:", "javascript:")):
                    foreign.append((route, h))
        b.close()
    assert len(seen) >= len(ROUTES)
    assert not dead, f"links the gateway answers with an error: {dead[:10]}"
    assert not foreign, f"links to unpublished services: {foreign[:10]}"


def test_browser_attack_launch_works_in_the_8000_deployment_with_its_real_origin(stack):
    """AGENTSEC_PUBLIC_PORT=8000 in the gateway; Chromium uses the real origin https://host:8000 (so it sends Origin: https://host:8000 and Host: host:8000) but is
    routed to a free loopback port, because host port 8000 is held by the real lab's Splunk Web on the development machine and is never touched."""
    from test_gateway_runtime import FILES, ROOT
    alt = 18544
    files = FILES + ["-f", "tests/gateway/compose.port8000.test.yml"]
    env = {**os.environ, **stack.vars, "AGENTSEC_PUBLIC_PORT": "8000", "TEST_ALT_PORT": str(alt)}
    up = subprocess.run(["docker", "compose", "-p", "agentsec-gw-dev", *files, "--profile", "gateway", "up", "-d", "--no-deps", "--force-recreate", "gateway"], cwd=ROOT, capture_output=True, text=True, env=env)
    assert up.returncode == 0, up.stderr
    try:
        for _ in range(40):
            if subprocess.run(["curl", "-sS", "-m", "5", "-o", "/dev/null", "-w", "%{http_code}", "--cacert", str(stack.pki["root"]), "--resolve", f"{HOST}:{alt}:127.0.0.1", "-u", "learner:l-pass",
                               "-H", f"Host: {HOST}:8000", f"https://{HOST}:{alt}/health"], capture_output=True, text=True).stdout == "200": break
            time.sleep(1.5)
        _browser_attack(stack, 8000, via=alt)
    finally:
        stack.up_gateway(AGENTSEC_PUBLIC_PORT=str(PORT))
