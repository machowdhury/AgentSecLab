"""A remote learner's browser must never be sent to ITS OWN loopback. No Docker, no network: Flask test client with a remote Host."""
from __future__ import annotations

import re

import pytest

from agentsec.attack_app import AcmeBankClient, create_app

REMOTE = "http://203.0.113.10:5001"  # documentation address (RFC 5737), stands in for an EC2 public IP
PAGES = ("/", "/academy", "/academy/foundations", "/academy/path", "/academy/status", "/academy/missions/loan-desk",
         "/academy/labs/LAB-MCP-001", "/labs/LAB-MCP-001", "/labs/LAB-PI-001")
LOOPBACK = re.compile(r"(?:127\.0\.0\.1|localhost|\[::1\])")
URL_ATTR = re.compile(r"""\b(?:href|src|action|data-[\w-]*(?:url|href|link)[\w-]*)\s*=\s*["']([^"']*)["']""", re.I)


def _healthy(_path):
    return 200, {"status": "healthy", "security.profile": "defended", "ollama_model": "model-label"}


@pytest.fixture()
def client(tmp_path):
    app = create_app(AcmeBankClient("http://acmebank.example:5000", get_fn=_healthy), launch_kwargs={"artifacts_dir": tmp_path})
    app.config["TESTING"] = True
    return app.test_client()


@pytest.mark.parametrize("path", PAGES)
def test_no_server_rendered_url_or_redirect_points_at_loopback(client, path):
    r = client.get(path, base_url=REMOTE, follow_redirects=False)
    assert r.status_code in (200, 301, 302, 308), (path, r.status_code)
    assert not LOOPBACK.search(r.headers.get("Location", "")), (path, r.headers.get("Location"))
    if r.status_code != 200:
        return
    bad = [u for u in URL_ATTR.findall(r.get_data(as_text=True)) if LOOPBACK.search(u)]
    assert not bad, (path, bad)


def test_api_responses_shown_to_the_browser_carry_no_loopback_urls(client):
    for path in ("/api/academy/status", "/api/academy/live-runs", "/health"):
        r = client.get(path, base_url=REMOTE)
        urls = re.findall(r'https?://[^"\s\\]+', r.get_data(as_text=True))
        assert not [u for u in urls if LOOPBACK.search(u)], (path, urls)
