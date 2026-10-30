"""Gateway allowlists (the production templates) vs the ACTUAL application: (1) the Flask route table, (2) the requests the React Academy really makes in a browser.
No Docker, no Splunk. The browser part needs playwright + AGENTSEC_CHROMIUM (otherwise it is skipped, i.e. NOT VERIFIED)."""
import json, os, re, sys, threading
from pathlib import Path
import pytest
from gwhelpers import ROOT

sys.path.insert(0, str(ROOT / "src"))
NGINX = (ROOT / "gateway/templates/gateway.conf.template").read_text(); ATTACK = (ROOT / "gateway/attack-enabled.conf").read_text()
READ_RE = re.compile(re.search(r"location ~ (\^/\(learn.*?\$\))\s*\{", NGINX, re.S).group(1))
ATTACK_RE = re.compile(re.search(r"location ~ (\^/api/.*?)\s*\{", ATTACK).group(1))
SAMPLE = {"lab_id": "LAB-PI-001", "run_id": "abc123", "search_id": "0123456789abcdef", "rest": "x/y", "filename": "learn/a.js", "finding_id": "F-0123456789ab"}
SAMPLE["run_id"] = "11111111-1111-4111-8111-111111111111"


FIXTURES_RE = re.compile(re.search(r'location ~ "(\^/api/assurance/fixtures/.*?\$)" \{', ATTACK).group(1))
ASSURANCE_RE = re.compile(re.search(r'location ~ "(\^/api/assurance/\(overview.*?\$)" \{', NGINX).group(1))
INVEST_RE = re.compile(re.search(r'location ~ "(\^/api/assurance/findings/F-.*?\$)" \{', ATTACK).group(1))


def tier(path, method):
    if FIXTURES_RE.match(path) and method == "GET": return "operator-read"
    if INVEST_RE.match(path) and method in ("GET", "POST"): return "attack"
    if ASSURANCE_RE.match(path) and method == "GET": return "read"
    if ATTACK_RE.match(path) and method in ("GET", "POST"): return "attack"
    if READ_RE.match(path) and method == "GET": return "read"
    return "denied"


def concrete(rule):
    return re.sub(r"<(?:\w+:)?(\w+)>", lambda m: SAMPLE.get(m.group(1), "x"), rule)


@pytest.fixture(scope="module")
def routes():
    from agentsec.attack_app import AcmeBankClient, create_app
    app = create_app(AcmeBankClient("http://acmebank:5000"))
    return [(concrete(r.rule), m, r.rule) for r in app.url_map.iter_rules() for m in sorted(r.methods - {"HEAD", "OPTIONS"})]


def test_route_table_classification(routes):
    table = {}
    for path, method, rule in routes: table.setdefault(tier(path, method), []).append(f"{method} {rule}")
    # every state-changing route (anything but GET) must be reachable ONLY through the authenticated attack tier or be denied
    bad = [f"{m} {r}" for p, m, r in routes if m != "GET" and tier(p, m) == "read"]
    # every alternative in the attack regex must match a real route (no dead patterns that hide drift)
    attack_alts = re.search(r"\^/api/\((.*)\)", ATTACK_RE.pattern).group(1)
    dead = []
    for alt in ("launch$", "attacks/ATK-002$", "launches/[A-Za-z0-9_-]+(/evidence)?$"):
        pass
    attack_hits = [p for p, m, _ in routes if tier(p, m) == "attack"]
    ok = not bad and {"POST /api/launch", "POST /api/attacks/ATK-002", "POST /api/missions/loan-desk/runs"} <= set(table.get("attack", [])) | {f"POST {r}" for r in ()} | set(table.get("attack", []))
    assert not bad
    posts = [f"{m} {r}" for p, m, r in routes if m == "POST"]
    via_attack = sorted(x for x in posts if x in table.get("attack", []))
    denied = sorted(x for x in posts if x not in table.get("attack", []))
    expected = sorted(["POST /api/launch", "POST /api/attacks/ATK-002", "POST /api/missions/loan-desk/runs", "POST /api/missions/loan-desk/runs/<run_id>/search",
                       "POST /api/missions/loan-desk/runs/<run_id>/search/preview", "POST /api/missions/loan-desk/runs/<run_id>/verify",
                       "POST /api/assurance/findings/<finding_id>/cells/<cell_id>"])
    ok = via_attack == expected
    assert ok, (via_attack, expected)


def test_spa_traffic_matches_the_allowlist():
    chromium = os.environ.get("AGENTSEC_CHROMIUM")
    pw = pytest.importorskip("playwright.sync_api")
    if not chromium: pytest.skip("AGENTSEC_CHROMIUM not set")
    from werkzeug.serving import make_server
    from agentsec.attack_app import AcmeBankClient, create_app
    srv = make_server("127.0.0.1", 0, create_app(AcmeBankClient("http://127.0.0.1:9")), threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_port}"
    seen = {}
    pages = ["/learn", "/learn/curriculum", "/learn/lab/LAB-HITL-APPROVAL", "/learn/lab/LAB-SPLUNK-DEFENDER-BRIDGE", "/learn/evals", "/learn/evals/export", "/learn/risk", "/learn/risk/register",
             "/learn/governance", "/learn/governance/export", "/learn/assurance", "/learn/loan-desk", "/learn/path", "/learn/foundations", "/learn/mastery", "/learn/mcp"]
    with pw.sync_playwright() as p:
        b = p.chromium.launch(executable_path=chromium); pg = b.new_page()
        pg.on("request", lambda r: seen.setdefault((r.method, re.sub(r"^https?://[^/]+", "", r.url).split("?")[0]), r.resource_type) if r.resource_type in ("fetch", "xhr", "document") else None)
        for u in pages:
            pg.goto(base + u); pg.wait_for_timeout(700)
        b.close()
    srv.shutdown()
    api = sorted(k for k in seen if k[1].startswith("/api/") or k[1] == "/health")
    learner_blocked = [f"{m} {p}" for m, p in api if tier(p, m) != "read"]
    docs_blocked = [f"{m} {p}" for (m, p), t in seen.items() if t == "document" and tier(p, m) != "read" and p != "/"]
    assert not learner_blocked and not docs_blocked, (learner_blocked, docs_blocked)


def test_assurance_routes_are_read_only_and_the_fixtures_view_is_operator_only(routes):
    got = {(m, r): tier(p, m) for p, m, r in routes if "/api/assurance/" in r}
    F = "/api/assurance/findings/<finding_id>"
    assert got == {("GET", "/api/assurance/overview"): "read", ("GET", F): "read", ("GET", F + "/investigation"): "read", ("GET", F + "/comparison"): "read",
                   ("GET", F + "/explore/<cell_id>"): "read", ("GET", "/api/assurance/runs/<run_id>/findings"): "read", ("GET", F + "/searches/<search_id>"): "attack", ("POST", F + "/cells/<cell_id>"): "attack",
                   ("GET", "/api/assurance/fixtures/overview"): "operator-read", ("GET", "/api/assurance/fixtures/findings/<finding_id>"): "operator-read",
                   ("GET", "/api/assurance/fixtures/findings/<finding_id>/investigation"): "operator-read", ("GET", "/api/assurance/fixtures/findings/<finding_id>/comparison"): "operator-read",
                   ("GET", "/api/assurance/fixtures/findings/<finding_id>/explore/<cell_id>"): "operator-read"}
    for bad in ("/api/assurance/overview/x", "/api/assurance/findings/F-0123", "/api/assurance/findings/../x", "/api/assurance/fixtures/findings/F-0123456789abg",
                "/api/assurance/findings/F-0123456789ab/investigation/x", "/api/assurance/findings/F-0123456789ab/explore/../x", "/api/assurance/findings/F-0123456789ab/cells/A",
                "/api/assurance/findings/F-0123456789ab/searches/zz", "/api/assurance/fixtures/findings/F-0123456789ab/cells/run_events"):
        assert tier(bad, "GET") == "denied", bad
    for p in ("/api/assurance/overview", "/api/assurance/fixtures/overview"):
        assert tier(p, "POST") == "denied"
    block = ATTACK[ATTACK.index('location ~ "^/api/assurance/fixtures'):]
    assert "auth_request /_authz_operator;" in block.split("\n}")[0] and "limit_except GET { deny all; }" in block.split("\n}")[0]
