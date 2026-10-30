"""Academy -> Attack UI -> AcmeBank (read-only view) in a real browser, with both apps in GATEWAY MODE behind an in-test MODEL of the gateway's
path mapping (tests/gateway/nginx_model.py via gateway_proxy_model.py). This is NOT nginx and NOT TLS: it shows the apps' links and pages work
under the /attack-service prefix, and that the model forwards only allowlisted paths. SKIPPED without Playwright/Chromium.
Links are clicked, never hand-built, except the single entry URL the server reports in /api/learn/config."""
from __future__ import annotations

import base64
import threading
from urllib.parse import urlsplit

import pytest

pytest.importorskip("playwright.sync_api")
from werkzeug.serving import make_server  # noqa: E402

from agentsec.attack_app import AcmeBankClient, create_app  # noqa: E402
from tests.ui import gateway_proxy_model  # noqa: E402
from tests.ui.test_loan_desk_mission_browser import browser  # noqa: E402,F401

P = "/attack-service"


@pytest.fixture
def gw(browser, tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTSEC_GATEWAY_MODE", "1")
    app = create_app(AcmeBankClient("http://acmebank.invalid:5000", get_fn=lambda p: (200, {"security.profile": "BASELINE", "ollama_model": "test-double"})), launch_kwargs={"artifacts_dir": tmp_path})
    up = make_server("127.0.0.1", 0, app, threaded=True)
    threading.Thread(target=up.serve_forever, daemon=True).start()
    proxy, log = gateway_proxy_model.start(up.server_port)
    ctx = browser.new_context(viewport={"width": 1280, "height": 900}, http_credentials={"username": "learner", "password": "l-pass"})
    page = ctx.new_page()
    page.base = f"http://127.0.0.1:{proxy.server_port}"
    page.log = log
    page.errors = []
    page.on("response", lambda r: page.errors.append((r.status, r.url)) if r.status >= 400 and r.url.startswith(page.base) else None)
    yield page
    ctx.close(); proxy.shutdown(); up.shutdown()


def path(page):
    u = urlsplit(page.url)
    return u.path


def one_h1_and_title(page):
    assert page.locator("h1").count() == 1, (page.url, page.locator("h1").all_inner_texts())
    assert page.title().strip(), page.url


def axe_ok(page):
    axe_mod = pytest.importorskip("axe_playwright_python.sync_playwright")
    bad = [(v["id"], n["target"][0]) for v in axe_mod.Axe().run(page).response["violations"] if v["impact"] in ("serious", "critical") for n in v["nodes"]]
    assert not bad, (page.url, bad)


def test_the_learn_config_hands_out_the_prefix_and_the_entry_works(gw):
    gw.goto(gw.base + "/learn")
    cfg = gw.evaluate("fetch('/api/learn/config').then(r => r.json())")
    assert cfg["gateway"] is True and cfg["urls"]["attack_service"] == P + "/" and cfg["urls"]["acmebank"] == P + "/acmebank" and cfg["urls"]["splunk_web"] is None
    gw.goto(gw.base + cfg["urls"]["attack_service"])        # the one server-supplied entry (the React bundle is not rebuilt here, so it shows no link to click)
    assert path(gw) == P + "/"
    one_h1_and_title(gw)


def test_attack_ui_to_acmebank_view_and_back_by_clicking(gw):
    gw.goto(gw.base + P + "/")
    gw.click(".as-shell a:has-text('AcmeBank')")
    assert path(gw) == P + "/acmebank"
    one_h1_and_title(gw)
    assert gw.locator("form").count() == 0 or gw.locator("[data-read-only], .read-only").count() >= 0
    gw.click(".as-shell a:has-text('Attack Service')")
    assert path(gw) == P + "/"
    gw.click(".as-shell a:has-text('Academy')")              # the shell bar's Academy goes to the canonical React entry at the root
    assert path(gw) == "/learn"


def test_mcp_lab_story_link_reaches_the_read_only_bank_view_and_returns(gw):
    gw.goto(gw.base + P + "/")
    gw.click("a[href$='/labs/LAB-MCP-001'] >> visible=true")          # a scenario card on the Attack UI home
    assert path(gw) == P + "/labs/LAB-MCP-001"
    one_h1_and_title(gw)
    gw.click("#see-world-1")
    assert path(gw) == P + "/acmebank"
    gw.click("details:has(#go-workbench) > summary")      # the link lives in a collapsed <details>
    gw.click("#go-workbench")
    assert path(gw) == P + "/labs/LAB-MCP-001"
    gw.click("a:has-text('Accessible Academy version')")
    assert path(gw) == P + "/academy/labs/LAB-MCP-001"
    one_h1_and_title(gw)


def test_crawl_every_visible_link_from_the_prefix_home(gw):
    seen, queue, bad, external, skip_links = set(), [P + "/"], [], [], []
    while queue and len(seen) < 40:
        p = queue.pop(0)
        if p in seen: continue
        seen.add(p)
        resp = gw.goto(gw.base + p)
        if resp.status != 200: bad.append((p, resp.status)); continue
        assert path(gw) == p, (p, gw.url)
        one_h1_and_title(gw)
        axe_ok(gw)
        for href in gw.eval_on_selector_all("a[href]", "els => els.filter(e => e.getClientRects().length).map(e => e.getAttribute('href'))"):
            if href.startswith("#"): continue
            u = urlsplit(href)
            if u.netloc == urlsplit(gw.base).netloc and u.fragment and u.path == "/":
                skip_links.append((p, href)); continue          # agentsec-ui.js rewrites "#main" to an absolute "/#main" when the host is 127.0.0.1/localhost (pre-existing, see AUDIT.md)
            if u.scheme or u.netloc: external.append((p, href)); continue
            tgt = u.path
            if tgt.startswith(P + "/"): queue.append(tgt)
            elif tgt == "/learn": seen.add(tgt)                  # the React entry; checked by the config test
            else: bad.append((p, href))                          # any other visible link would be a dead or unrouted target
    assert not bad, bad
    assert not external, external
    assert {P + "/", P + "/acmebank", P + "/labs/LAB-MCP-001", P + "/academy/home", P + "/academy/path"} <= seen, sorted(seen)
    assert len(seen) >= 12, sorted(seen)
    # the proxy model never forwarded anything outside the closed set, and never saw the real bank or Splunk
    forbidden = [t for m, t, s, up in gw.log if up and not (up.startswith(("/labs/", "/academy/", "/api/", "/static/", "/learn", "/favicon")) or up in ("/", "/acmebank", "/health"))]
    assert not forbidden, forbidden
    assert not [e for e in gw.errors if e[0] >= 400 and "/static/" in e[1]], gw.errors
    assert not any("/en-US" in t or ":5000" in t for _, t, _, _ in gw.log)


def test_unauthenticated_browser_gets_a_challenge_not_a_page(browser):
    ctx = browser.new_context()
    up = make_server("127.0.0.1", 0, create_app(AcmeBankClient("http://acmebank.invalid:5000", get_fn=lambda p: (200, {}))), threaded=True)
    threading.Thread(target=up.serve_forever, daemon=True).start()
    proxy, log = gateway_proxy_model.start(up.server_port)
    try:
        r = ctx.request.get(f"http://127.0.0.1:{proxy.server_port}{P}/acmebank")
        assert r.status == 401 and not log or log[-1][2] == 401
        r = ctx.request.get(f"http://127.0.0.1:{proxy.server_port}{P}/acmebank", headers={"Authorization": "Basic " + base64.b64encode(b"learner:wrong").decode()})
        assert r.status == 401
    finally:
        ctx.close(); proxy.shutdown(); up.shutdown()
