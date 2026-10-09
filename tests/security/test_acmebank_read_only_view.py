"""The Attack Service renders AcmeBank read-only. It must not become a proxy.

AcmeBank binds to loopback on the lab host and is deliberately unreachable from
a browser, because it is an intentionally vulnerable target. A learner still has
to read WORLD 1, the business story, before investigating the AI behind it, so
the Attack Service renders the same template with submission removed.

The risk this guards is that a convenience view quietly turns into a request
forwarder: a caller-supplied upstream would hand an attacker a server-side
fetch from inside the lab host, and a forwarded POST would let the browser
reach the vulnerable /process endpoint the loopback binding exists to protect.

Threat          attacker reaches AcmeBank, or the lab host's network, via 5001
Attacker        anyone who can load the Attack Service in a browser
Asset           the intentionally vulnerable AcmeBank target and its host
Trust boundary  browser -> Attack Service -> AcmeBank
Invariant       the read-only view forwards nothing a caller controls
Expected        GET only, no upstream parameter, no /process path, no scripts
"""

from __future__ import annotations

import pytest

from agentsec.attack_app import AcmeBankClient, create_app
from agentsec.bank_app import create_app as create_bank_app

ROUTE = "/acmebank"
FORBIDDEN_HOSTS = ("localhost", "127.0.0.1", "3.17.29.24")


def _unreachable_app():
    """Pin the unreachable case so a live lab on :5000 cannot hide NOT MEASURED."""
    return create_app(AcmeBankClient("http://acmebank.example:5000", get_fn=lambda _p: (503, {"error": "down"})))


@pytest.fixture(scope="module")
def page() -> str:
    response = _unreachable_app().test_client().get(ROUTE)
    assert response.status_code == 200
    return response.get_data(as_text=True)


@pytest.fixture(scope="module")
def client():
    return _unreachable_app().test_client()


@pytest.mark.parametrize("method", ["post", "put", "patch", "delete"])
def test_read_only_view_accepts_get_only(client, method):
    """A write verb must not reach AcmeBank through this route."""
    response = getattr(client, method)(ROUTE)
    assert response.status_code == 405


@pytest.mark.parametrize(
    "query",
    [
        "target=http://169.254.169.254/latest/meta-data/",
        "url=http://evil.test",
        "base_url=http://evil.test",
        "upstream=http://evil.test",
        "path=/process",
    ],
)
def test_caller_cannot_choose_the_upstream(client, page, query):
    """No request-forgery surface: the response ignores anything the caller sends."""
    response = client.get(f"{ROUTE}?{query}")
    assert response.status_code == 200
    assert response.get_data(as_text=True) == page


def test_read_only_view_cannot_submit_an_application(page):
    """Removing the form is the control. A disabled button would not be."""
    assert '<form id="loan-form"' not in page
    assert 'id="submit-loan"' not in page
    assert '"/process"' not in page


def test_read_only_view_ships_no_script(page):
    """No client code means no path back to a submission or a minted run.id."""
    assert "<script" not in page
    assert "captureLaunch" not in page


def test_read_only_view_says_what_it_is(page):
    assert 'id="readonly-notice"' in page
    assert "DOCUMENTED" in page


def test_read_only_view_keeps_the_world_1_teaching(page):
    """The reason this route exists at all."""
    assert 'id="behind-the-ai"' in page
    assert 'id="go-workbench"' in page


def test_workbench_link_stays_same_origin(page):
    """The learner is already on the Attack Service, so no port rewrite runs."""
    assert 'href="/labs/LAB-MCP-001"' in page
    for host in FORBIDDEN_HOSTS:
        assert host not in page, f"{host} must not be hard-coded in a shipped page"


def test_target_labels_are_probed_not_asserted(page):
    """If AcmeBank is unreachable the page must not invent its profile."""
    assert "NOT MEASURED" in page


def test_workbench_links_to_the_read_only_view(client):
    workbench = client.get("/labs/LAB-MCP-001").get_data(as_text=True)
    assert 'id="see-world-1"' in workbench
    assert f'href="{ROUTE}"' in workbench


def test_acmebank_itself_is_unchanged():
    """The real service keeps its form. Only the rendered copy is read-only."""
    served = create_bank_app().test_client().get("/").get_data(as_text=True)
    assert '<form id="loan-form"' in served
    assert '"/process"' in served
    assert 'id="readonly-notice"' not in served
