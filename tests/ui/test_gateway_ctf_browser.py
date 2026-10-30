"""The CTF through the gateway in a real browser, behind an in-test MODEL of the gateway (tests/gateway/nginx_model.py via gateway_proxy_model.py). NOT nginx, NOT TLS.
The upstream is the real Attack Service app (gateway mode, real CTF engines, temp state dir). The browser uses the host name ctf.localhost (Chromium resolves it to loopback), so the
upstream sees a NON-loopback Host and must rely on the gateway-injected secret. Shows: a CTF page loads and a challenge can be started through /attack-service/ctf with the secret,
and is refused without it (or with a wrong one). SKIPPED without Playwright/Chromium (set AGENTSEC_CHROMIUM)."""
from __future__ import annotations

import threading

import pytest

pytest.importorskip("playwright.sync_api")
from playwright.sync_api import expect  # noqa: E402
from werkzeug.serving import make_server  # noqa: E402

from agentsec.attack_app import AcmeBankClient, create_app  # noqa: E402
from tests.ui import gateway_proxy_model  # noqa: E402
from tests.ui.test_loan_desk_mission_browser import browser  # noqa: E402,F401

SECRET = "ab" * 32
P = "/attack-service"


def make_gw(browser, tmp_path, monkeypatch, injected, app_secret=SECRET):
    monkeypatch.setenv("AGENTSEC_GATEWAY_MODE", "1")
    monkeypatch.setenv("AGENTSEC_CTF_STATE_DIR", str(tmp_path / "ctf-state"))
    monkeypatch.setenv("AGENTSEC_CTF_ALLOW_GATEWAY", "1")
    monkeypatch.setenv("AGENTSEC_CTF_GATEWAY_SECRET", app_secret)
    app = create_app(AcmeBankClient("http://acmebank.invalid:5000", get_fn=lambda p: (200, {"security.profile": "BASELINE", "ollama_model": "test-double"})), launch_kwargs={"artifacts_dir": tmp_path})
    up = make_server("127.0.0.1", 0, app, threaded=True)
    threading.Thread(target=up.serve_forever, daemon=True).start()
    proxy, log = gateway_proxy_model.start(up.server_port, host="ctf.localhost", ctf="enabled", ctf_secret=injected, scheme="http")
    ctx = browser.new_context(viewport={"width": 1280, "height": 900}, http_credentials={"username": "operator", "password": "o-pass"})
    page = ctx.new_page()
    page.base, page.log = f"http://ctf.localhost:{proxy.server_port}", log
    return page, ctx, proxy, up


@pytest.fixture
def with_secret(browser, tmp_path, monkeypatch):
    page, ctx, proxy, up = make_gw(browser, tmp_path, monkeypatch, injected=SECRET)
    yield page
    ctx.close(); proxy.shutdown(); up.shutdown()


@pytest.fixture(params=["not-injected", "wrong"])
def without_secret(request, browser, tmp_path, monkeypatch):
    page, ctx, proxy, up = make_gw(browser, tmp_path, monkeypatch, injected=None if request.param == "not-injected" else "cd" * 32)
    yield page
    ctx.close(); proxy.shutdown(); up.shutdown()


def test_ctf_page_loads_and_a_challenge_starts_through_the_gateway_path(with_secret):
    pg = with_secret
    pg.goto(pg.base + P + "/ctf")
    expect(pg.locator("h1")).to_have_count(1)
    link = pg.locator("tbody th a").first
    assert link.get_attribute("href").startswith(P + "/ctf/")            # links were rewritten to the approved prefix
    link.click()
    pg.wait_for_url(f"{pg.base}{P}/ctf/*")
    pg.click("[data-act=start]")
    expect(pg.locator("#attempt-state")).to_contain_text("NEW")
    posts = [e for e in pg.log if e[0] == "POST"]
    assert posts and all(e[2] == 201 and e[3].startswith("/api/ctf/challenges/") for e in posts), pg.log
    assert not [e for e in pg.log if e[2] >= 400 and e[2] != 401], pg.log      # 401 = the browser's Basic-auth challenge round trip


def test_ctf_is_refused_without_the_gateway_secret(without_secret):
    pg = without_secret
    r = pg.goto(pg.base + P + "/ctf")
    assert r.status == 403 and "local_only" in pg.content()                # the app refuses: no valid secret arrived with the request
    assert pg.evaluate("fetch('/api/ctf/challenges').then(r => r.status)") == 403
    assert pg.evaluate("fetch('/api/ctf/challenges/x/attempts', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: '{}'}).then(r => r.status)") == 403
