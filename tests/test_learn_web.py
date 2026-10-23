"""The unified Academy shell at /learn: SPA routes, CSP, deployment config derived from the browser's host, and the /academy entry redirect."""

from __future__ import annotations

import pytest

from agentsec.attack_app import create_app
from agentsec.learn_web import _browser_origin, build_config


@pytest.fixture()
def client():
    return create_app().test_client()


def test_academy_entry_redirects_to_learn_and_classic_home_remains(client):
    r = client.get("/academy")
    assert r.status_code == 302 and r.headers["Location"].endswith("/learn")
    assert client.get("/academy/home").status_code == 200


@pytest.mark.parametrize("path", ["/learn", "/learn/", "/learn/loan-desk/learn", "/learn/loan-desk/investigate", "/learn/anything/else"])
def test_learn_routes_serve_the_spa_under_the_strict_csp(client, path):
    r = client.get(path)
    assert r.status_code == 200 and b'id="root"' in r.data
    csp = r.headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp and "script-src 'self'" in csp and "unsafe-inline" not in csp.split("script-src")[1].split(";")[0]
    assert r.headers["Cache-Control"] == "no-store" and r.headers["X-Frame-Options"] == "DENY"


def test_learn_is_read_only(client):
    assert client.post("/learn").status_code == 405
    assert client.post("/api/learn/config").status_code == 405


def test_config_derives_urls_from_the_browser_host_not_loopback(client):
    body = client.get("/api/learn/config", headers={"Host": "lab.example.test:5001"}).get_json()
    assert body["urls"] == {"splunk_web": "http://lab.example.test:8000", "acmebank": "http://lab.example.test:5000"}
    assert body["mission"]["id"] == "loan-desk" and body["mission"]["lab_id"] == "LAB-LOANDESK-001"


@pytest.mark.parametrize("host,scheme,expected", [
    ("[::1]:5001", "http", "http://[::1]:8000"),
    ("0.0.0.0:5001", "http", "http://127.0.0.1:8000"),
    ("lab.test", "https", "https://lab.test:8000"),
    ("lab.test:5001, evil.test", "http", "http://lab.test:8000"),
    ("", "ftp", "http://127.0.0.1:8000"),
])
def test_browser_origin_handles_ipv6_unspecified_and_odd_inputs(host, scheme, expected):
    assert _browser_origin(host, scheme, 8000) == expected


def test_config_carries_no_secrets():
    text = str(build_config("lab.test", "http", "1")).lower()
    assert not any(w in text for w in ("password", "token", "secret", "api_key"))


def test_acmebank_page_is_an_in_academy_route(client):
    assert b'id="root"' in client.get("/learn/acmebank").data


def test_mission_proxy_has_fixed_endpoints_and_no_catch_all(client):
    rules = sorted(r.rule for r in client.application.url_map.iter_rules() if r.rule.startswith("/api/missions"))
    assert rules == ["/api/missions/loan-desk/runs", "/api/missions/loan-desk/runs/<run_id>", "/api/missions/loan-desk/runs/<run_id>/search",
                     "/api/missions/loan-desk/runs/<run_id>/search/<search_id>", "/api/missions/loan-desk/runs/<run_id>/search/preview",
                     "/api/missions/loan-desk/runs/<run_id>/verify", "/api/missions/loan-desk/search/templates", "/api/missions/loan-desk/status"]
    assert not any("path:" in r for r in rules)


def test_unknown_run_ids_and_extra_fields_are_refused(client):
    assert client.get("/api/missions/loan-desk/runs/not-a-run").status_code == 404
    bad = client.post("/api/missions/loan-desk/runs", json={"application": {}, "posture": "baseline", "url": "http://evil.test/"})
    assert bad.status_code == 400


@pytest.mark.parametrize("path", ["/learn", "/learn/acmebank", "/api/learn/config", "/api/missions/loan-desk/status"])
def test_no_cors_and_no_framing(client, path):
    r = client.get(path, headers={"Origin": "http://evil.test"})
    assert "Access-Control-Allow-Origin" not in r.headers


def test_academy_source_embeds_no_iframes_and_csp_blocks_framing_by_others(client):
    from pathlib import Path
    src = Path(__file__).resolve().parents[1] / "academy-ui" / "src"
    assert not [p.name for p in src.rglob("*.ts*") if "iframe" in p.read_text(encoding="utf-8").lower()]
    assert "frame-ancestors 'none'" in client.get("/learn").headers["Content-Security-Policy"]
