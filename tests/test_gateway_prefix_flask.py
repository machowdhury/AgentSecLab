"""The Attack Service behind the /attack-service prefix: link rewriting, and the rule that forwarded headers from an untrusted client are never honoured."""
import re
import pytest
from agentsec.attack_app import AcmeBankClient, create_app
from agentsec.gateway_prefix import PREFIX, rewrite_html

GW = {"X-Forwarded-Prefix": PREFIX}
PAGES = ["/", "/labs/LAB-PI-001", "/labs/LAB-MCP-001", "/acmebank", "/academy/home", "/academy/path", "/academy/foundations", "/academy/status", "/academy/labs/LAB-MCP-001"]
ROOT_HREF = re.compile(r'\bhref="(/[^"]*)"')


@pytest.fixture()
def app(tmp_path):
    return create_app(AcmeBankClient("http://acmebank.example:5000", get_fn=lambda p: (200, {"status": "healthy"})), launch_kwargs={"artifacts_dir": tmp_path})


def hrefs(html):
    return ROOT_HREF.findall(html)


@pytest.mark.parametrize("path", PAGES)
def test_gateway_mode_with_the_gateway_header_prefixes_every_page_link(app, monkeypatch, path):
    monkeypatch.setenv("AGENTSEC_GATEWAY_MODE", "1")
    r = app.test_client().get(path, headers=GW)
    assert r.status_code == 200
    for h in hrefs(r.get_data(as_text=True)):
        assert h.startswith((PREFIX + "/", "/static/", "/learn", "/api/")), (path, h)          # nothing left pointing at an unrouted root page or Splunk Web
    assert "/en-US" not in "".join(hrefs(r.get_data(as_text=True))) and ":8000" not in r.get_data(as_text=True).replace("8000-", "")


def test_the_shell_bar_academy_link_goes_to_the_canonical_react_entry(app, monkeypatch):
    monkeypatch.setenv("AGENTSEC_GATEWAY_MODE", "1")
    html = app.test_client().get("/labs/LAB-MCP-001", headers=GW).get_data(as_text=True)
    assert 'href="/learn"' in html and f'href="{PREFIX}/acmebank"' in html and f'href="{PREFIX}/"' in html


def test_splunk_links_become_inert_but_keep_their_ids(app, monkeypatch):
    monkeypatch.setenv("AGENTSEC_GATEWAY_MODE", "1")
    html = app.test_client().get("/labs/LAB-MCP-001", headers=GW).get_data(as_text=True)
    assert 'id="open-search"' in html and 'data-gateway-unavailable="splunk"' in html          # scripts look these up by id; the elements stay, hidden, without an href


@pytest.mark.parametrize("path", PAGES)
def test_direct_mode_is_byte_identical_and_ignores_the_header(app, monkeypatch, path):
    monkeypatch.delenv("AGENTSEC_GATEWAY_MODE", raising=False)
    c = app.test_client()
    plain = c.get(path).get_data()
    assert c.get(path, headers=GW).get_data() == plain and PREFIX.encode() not in plain


@pytest.mark.parametrize("value", ["/evil", "/attack-service/", "attack-service", "/attack-service/../x", "//evil.example", "/attack-service\r\nX: 1", "https://evil.example", ""])
def test_gateway_mode_honours_only_the_exact_prefix_value(app, monkeypatch, value):
    monkeypatch.setenv("AGENTSEC_GATEWAY_MODE", "1")
    c = app.test_client()
    assert c.get("/acmebank", headers={"X-Forwarded-Prefix": value} if "\r" not in value else {}).get_data() == c.get("/acmebank").get_data()


def test_gateway_mode_without_the_header_serves_unmodified_root_links(app, monkeypatch):
    monkeypatch.setenv("AGENTSEC_GATEWAY_MODE", "1")
    assert PREFIX not in app.test_client().get("/labs/LAB-PI-001").get_data(as_text=True)


@pytest.mark.parametrize("hdr", [{"X-Forwarded-Host": "evil.example"}, {"X-Forwarded-Proto": "http"}, {"X-Forwarded-For": "6.6.6.6"}, {"X-Remote-User": "operator", "X-Auth-Role": "operator"},
                                 {"X-Forwarded-Prefix": "/evil", "Host": "evil.example"}])
def test_other_forwarded_headers_change_nothing(app, monkeypatch, hdr):
    monkeypatch.setenv("AGENTSEC_GATEWAY_MODE", "1")
    c = app.test_client()
    r = c.get("/labs/LAB-PI-001", headers=hdr)
    assert r.status_code == 200 and "evil.example" not in r.get_data(as_text=True) and "6.6.6.6" not in r.get_data(as_text=True)
    assert "Location" not in r.headers and not any("evil" in v for v in r.headers.values())


def test_redirects_stay_constant_and_cannot_be_split(app, monkeypatch):
    monkeypatch.setenv("AGENTSEC_GATEWAY_MODE", "1")
    r = app.test_client().get("/academy", headers={**GW, "X-Forwarded-Host": "evil.example"})
    assert r.status_code == 302 and r.headers["Location"] == "/learn" and "\n" not in r.headers["Location"]
    assert app.test_client().get("/academy%0d%0aSet-Cookie:x=1").status_code in (400, 404)


@pytest.mark.parametrize("path", ["/attack-service/acmebank", "/labs/../acmebank/process", "/labs/%2e%2e/x", "/process", "/en-US/", "/services/", "/v1/ollama", "/api/tags", "/acmebank/process"])
def test_the_backend_itself_has_no_route_for_these(app, monkeypatch, path):
    monkeypatch.setenv("AGENTSEC_GATEWAY_MODE", "1")
    assert app.test_client().get(path, headers=GW).status_code in (400, 404)   # the app's not_found handler answers with its unknown_lab status


@pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH", "POST"])
def test_pages_accept_get_only(app, monkeypatch, method):
    monkeypatch.setenv("AGENTSEC_GATEWAY_MODE", "1")
    for p in ("/acmebank", "/labs/LAB-PI-001", "/academy/home"):
        assert app.test_client().open(p, method=method, headers=GW).status_code in (403, 404, 405)


def test_cross_origin_post_is_refused_by_the_backend_too(app, monkeypatch):
    monkeypatch.setenv("AGENTSEC_GATEWAY_MODE", "1")
    r = app.test_client().post("/api/launch", json={}, headers={"Origin": "https://evil.example"}, base_url="https://lab.example")
    assert r.status_code == 403 and r.get_json()["error"] == "cross_origin_rejected"


def test_the_read_only_view_has_no_form_that_posts_to_the_real_bank(app, monkeypatch):
    monkeypatch.setenv("AGENTSEC_GATEWAY_MODE", "1")
    html = app.test_client().get("/acmebank", headers=GW).get_data(as_text=True)
    assert "<form" not in html.lower() or 'action=' not in html.lower()
    assert ":5000" not in html and "acmebank:" not in html


def test_rewrite_only_touches_page_hrefs():
    out = rewrite_html('<a href="/labs/X?a=1">a</a><a href="/academy">b</a><a href="/api/x">c</a><a href="/static/s.css">d</a><a href="//evil/x">e</a>'
                       '<a id="s" class="c" href="/en-US/app/x?y=1" target="_blank">s</a><a href="https://x/labs/1">f</a>')
    assert out.count(PREFIX + "/labs/X?a=1") == 1 and 'href="/learn"' in out and 'href="/api/x"' in out and 'href="/static/s.css"' in out
    assert 'href="//evil/x"' in out and 'href="https://x/labs/1"' in out and 'href="/en-US' not in out and 'id="s"' in out


@pytest.mark.parametrize("href", ["/academy/missions/other", "/academy/missions", "/academy/labs/a.b", "/academy/labs/x/y", "/labs/a b", "/labs/", "/acmebank/process", "/academy/home/x", "/academyx"])
def test_hrefs_the_gateway_would_not_route_are_left_untouched(href):
    assert rewrite_html(f'<a href="{href}">x</a>') == f'<a href="{href}">x</a>'


def test_prefixed_links_match_the_gateway_allowlist_text():
    import pathlib
    conf = (pathlib.Path(__file__).resolve().parents[1] / "gateway/templates/gateway.conf.template").read_text()
    nginx = re.compile(re.search(r"location ~ (\^/attack-service/.*?\$) \{", conf).group(1).replace("(?<asp>", "(?P<asp>"))
    for p in ["/", "/labs/LAB-PI-001", "/acmebank", "/academy/home", "/academy/path", "/academy/status", "/academy/foundations", "/academy/missions/loan-desk",
              "/academy/labs/LAB-MCP-001", "/academy/missions/x", "/labs/a.b", "/academy/labs/x/y", "/academy", "/academy/", "/labs/"]:
        rewritten = rewrite_html(f'<a href="{p}">x</a>')
        prefixed = PREFIX in rewritten
        if p == "/academy": assert 'href="/learn"' in rewritten; continue
        assert prefixed == bool(nginx.match(PREFIX + p)), p


def test_gateway_mode_hides_target_internals(monkeypatch, tmp_path):
    calls = []
    def get(p):
        calls.append(p); return 200, {"security.profile": "SECRET-PROFILE", "ollama_model": "SECRET-MODEL", "acmebank_url": "http://acmebank:5000"}
    app = create_app(AcmeBankClient("http://acmebank:5000", get_fn=get), launch_kwargs={"artifacts_dir": tmp_path})
    monkeypatch.setenv("AGENTSEC_GATEWAY_MODE", "1")
    c = app.test_client()
    bodies = [c.get("/api/target-health").get_data(as_text=True) for _ in range(5)] + [c.get("/acmebank", headers=GW).get_data(as_text=True)]
    assert all("SECRET" not in b and "5000" not in b and "acmebank:" not in b for b in bodies)
    assert c.get("/api/target-health").get_json() == {"status": "healthy"} and len(calls) == 1      # cached: one upstream probe for five requests
    down = create_app(AcmeBankClient("http://acmebank:5000", get_fn=lambda p: (503, {"error": "cannot reach AcmeBank: http://acmebank:5000"})), launch_kwargs={"artifacts_dir": tmp_path})
    r = down.test_client().get("/api/target-health")
    assert r.status_code == 503 and r.get_json() == {"status": "unreachable"}


def test_direct_mode_target_health_is_unchanged(monkeypatch, tmp_path):
    monkeypatch.delenv("AGENTSEC_GATEWAY_MODE", raising=False)
    app = create_app(AcmeBankClient("http://acmebank:5000", get_fn=lambda p: (200, {"ollama_model": "m"})), launch_kwargs={"artifacts_dir": tmp_path})
    assert app.test_client().get("/api/target-health").get_json() == {"ollama_model": "m"}
