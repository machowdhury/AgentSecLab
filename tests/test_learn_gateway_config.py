"""Behind the HTTPS gateway the Academy must not point at routes the gateway does not implement (RC1 L-1): Splunk Web, AcmeBank, classic pages."""
import pytest
from agentsec.attack_app import AcmeBankClient, create_app
from agentsec.learn_web import build_config


def test_direct_deployments_keep_their_service_links():
    c = build_config("lab.example:5001", "http", "1.3.0")
    assert c["gateway"] is False and c["urls"] == {"splunk_web": "http://lab.example:8000", "acmebank": "http://lab.example:5000"}


def test_gateway_mode_reports_no_urls_for_services_it_does_not_route():
    c = build_config("lab.example", "https", "1.3.0", gateway=True)
    assert c["gateway"] is True and c["urls"] == {"splunk_web": None, "acmebank": None}
    assert "8000" not in str(c["urls"]) and "5000" not in str(c["urls"])


@pytest.fixture()
def app(tmp_path):
    return create_app(AcmeBankClient("http://acmebank.example:5000", get_fn=lambda p: (200, {"status": "healthy"})), launch_kwargs={"artifacts_dir": tmp_path})


def test_the_endpoint_follows_the_environment_flag(app, monkeypatch):
    monkeypatch.delenv("AGENTSEC_GATEWAY_MODE", raising=False)
    assert app.test_client().get("/api/learn/config").get_json()["urls"]["splunk_web"]
    monkeypatch.setenv("AGENTSEC_GATEWAY_MODE", "1")
    body = app.test_client().get("/api/learn/config", base_url="https://lab.example").get_json()
    assert body["gateway"] is True and body["urls"] == {"splunk_web": None, "acmebank": None}


def test_the_status_page_offers_no_splunk_link_behind_the_gateway(app, monkeypatch):
    monkeypatch.delenv("AGENTSEC_GATEWAY_MODE", raising=False)
    direct = {c["name"]: c for c in app.test_client().get("/api/academy/status").get_json()["checks"]}
    assert direct["Splunk indexing"]["href"].endswith("/en-US/app/search/search")
    monkeypatch.setenv("AGENTSEC_GATEWAY_MODE", "1")
    gw = {c["name"]: c for c in app.test_client().get("/api/academy/status").get_json()["checks"]}
    assert "href" not in gw["Splunk indexing"]
