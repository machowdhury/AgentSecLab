"""Learner Flask pages: landmarks, shared CSS, no fabricated security copy."""

from __future__ import annotations

from agentsec.attack_app import AcmeBankClient, create_app as create_attack_app
from agentsec.attacks import ATK_002_PAYLOAD


def test_acmebank_index_has_banking_hierarchy(acme_client):
    response = acme_client.get("/")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert 'lang="en"' in html
    assert 'href="#main"' in html
    assert "<h1>AcmeBank</h1>" in html
    assert "Home loan application" in html
    assert 'for="input"' in html
    assert "Submit loan" in html
    assert 'data-state="READY"' in html
    assert "READY" in html
    assert "/process" in html
    assert "ALLOW is a control decision" in html
    assert "not a control DENY" in html
    css = acme_client.get("/static/agentsec.css")
    assert css.status_code == 200
    assert "#007F86" in css.get_data(as_text=True)


def test_attack_index_states_technique_and_target():
    app = create_attack_app(AcmeBankClient("http://acmebank.example:5000"))
    app.config["TESTING"] = True
    client = app.test_client()
    response = client.get("/")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Direct prompt injection" in html
    assert "ATK-002" in html
    assert "AML.T0054" in html
    assert "AcmeBank" in html
    assert "http://acmebank.example:5000" in html
    assert "lab URL" in html
    assert "Run ATK-002" in html
    assert ATK_002_PAYLOAD in html
    assert "Sending a request is not proof" in html
    assert "/api/attacks/ATK-002" in html
    css = client.get("/static/agentsec.css")
    assert css.status_code == 200
