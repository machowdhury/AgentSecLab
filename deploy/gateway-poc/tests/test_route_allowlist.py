"""Gateway allowlists vs the ACTUAL application: (1) the Flask route table, (2) the requests the React Academy really makes in a browser.
No Docker, no Splunk. The browser part needs playwright + AGENTSEC_CHROMIUM (otherwise NOT VERIFIED/skip)."""
import json, os, re, sys, threading
from pathlib import Path
import pytest
from conftest import EVID, POC, rec

sys.path.insert(0, str(POC.parents[1] / "src"))
NGINX = (POC / "gateway/nginx.conf").read_text(); ATTACK = (POC / "gateway/attack-tier.conf").read_text()
READ_RE = re.compile(re.search(r"location ~ (\^/\(learn.*?\$\))\s*\{", NGINX, re.S).group(1))
ATTACK_RE = re.compile(re.search(r"location ~ (\^/api/.*?)\s*\{", ATTACK).group(1))
SAMPLE = {"lab_id": "LAB-PI-001", "run_id": "abc123", "search_id": "s1", "rest": "x/y", "filename": "learn/a.js"}


def tier(path, method):
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
    (EVID / "route_classification.json").write_text(json.dumps({k: sorted(v) for k, v in table.items()}, indent=1))
    ok = not bad and {"POST /api/launch", "POST /api/attacks/ATK-002", "POST /api/missions/loan-desk/runs"} <= set(table.get("attack", [])) | {f"POST {r}" for r in ()} | set(table.get("attack", []))
    rec("R1", "PASS" if not bad else "FAIL", f"{len(routes)} route/method pairs: attack tier {len(table.get('attack', []))}, read tier {len(table.get('read', []))}, denied {len(table.get('denied', []))}; non-GET routes reachable on the read tier: {bad or 'none'}")
    assert not bad
    posts = [f"{m} {r}" for p, m, r in routes if m == "POST"]
    via_attack = sorted(x for x in posts if x in table.get("attack", []))
    denied = sorted(x for x in posts if x not in table.get("attack", []))
    expected = sorted(["POST /api/launch", "POST /api/attacks/ATK-002", "POST /api/missions/loan-desk/runs", "POST /api/missions/loan-desk/runs/<run_id>/search",
                       "POST /api/missions/loan-desk/runs/<run_id>/search/preview", "POST /api/missions/loan-desk/runs/<run_id>/verify"])
    ok = via_attack == expected
    rec("R2", "PASS" if ok else "FAIL", f"{len(posts)} POST routes: {len(via_attack)} reachable only via the operator-only attack tier (exactly the intended set), {len(denied)} denied by default: {denied}")
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
    (EVID / "spa_requests.json").write_text(json.dumps({"api_requests": [f"{m} {p}" for m, p in api], "learner_blocked_by_gateway": learner_blocked, "documents_blocked": docs_blocked}, indent=1))
    rec("R3", "PASS" if not learner_blocked and not docs_blocked else "FAIL",
        f"{len(pages)} Academy pages crawled in Chromium; API/fetch requests seen: {[p for _, p in api]}; blocked for a plain learner by the gateway: {learner_blocked or 'none'}; documents blocked: {docs_blocked or 'none'}")
    assert not learner_blocked and not docs_blocked, (learner_blocked, docs_blocked)
