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
    assert "Direct prompt injection" in html or "Direct Prompt Injection" in html
    assert "ATK-002" in html
    assert "AML.T0054" in html
    assert "AcmeBank" in html
    assert "http://acmebank.example:5000" in html
    assert "lab URL" in html
    assert "Launch ATTACK (LIVE)" in html
    assert "http://acmebank.example:5000" in html
    assert "/api/target-health" in html
    assert "Launch BASELINE (LIVE)" in html
    assert "Launch RETEST (LIVE)" in html
    assert "LIVE RUN PAIR" in html
    assert "Copy ATTACK run.id" in html
    assert "Copy RETEST run.id" in html
    assert "Predict before RETEST" in html
    assert "WHAT WOULD FALSIFY THIS?" in html
    assert 'execution: "live"' in html
    assert "profile: profile" not in html
    assert "LIVE RUN PAIR" in html
    assert "Open ATTACK in Search" in html
    assert "Open RETEST in Search" in html
    assert "Predict before ATTACK" in html
    assert "WHAT IS THE ATTACKER TRYING TO INFLUENCE?" in html
    assert "WHAT SHOULD THE DEFENSE DO?" in html
    assert "LOCAL EDUCATIONAL SERVICE" in html
    assert ATK_002_PAYLOAD in html
    assert "Sending a request is not proof" in html
    assert "/api/launch" in html
    css = client.get("/static/agentsec.css")
    assert css.status_code == 200


def test_attack_target_health_is_same_origin_proxy():
    app = create_attack_app(
        AcmeBankClient(
            "http://acmebank.example:5000",
            get_fn=lambda _path: (200, {"security.profile": "defended", "service": "acmebank"}),
        )
    )
    app.config["TESTING"] = True
    client = app.test_client()
    response = client.get("/api/target-health")
    assert response.status_code == 200
    body = response.get_json()
    assert body["security.profile"] == "defended"
    assert body["service"] == "acmebank"


def test_mcp_reference_workbench_is_guided_closed_and_accessible():
    app = create_attack_app(AcmeBankClient("http://acmebank.example:5000"))
    app.config["TESTING"] = True
    client = app.test_client()
    html = client.get("/labs/LAB-MCP-001").get_data(as_text=True)

    assert 'href="#main"' in html
    assert "<h1>Tool Authorization</h1>" in html
    assert "Can the agent invoke a tool outside the authority granted to it?" in html
    assert ">Principal<" in html and ">Authorization<" in html and ">Execution<" in html
    assert "Run ATTACK" in html and "Run RETEST" in html
    assert "Copy Run ID" in html
    assert 'aria-live="polite"' in html
    assert "Evidence / Advanced" in html
    assert "REQUEST ≠ GRANT" in html
    assert "ALLOW ≠ EXECUTION" in html
    assert "SPLUNK ≠ ENFORCEMENT" in html
    assert 'body: JSON.stringify({lab_id: "LAB-MCP-001", specimen_id: specimenId, mode: mode, execution: "live"})' in html
    assert "allowed_tools:" not in html
    assert "requested_scope:" not in html

    css = client.get("/static/mcp-workbench.css")
    assert css.status_code == 200
    css_text = css.get_data(as_text=True)
    assert "@media (max-width: 1200px)" in css_text
    assert "@media (max-width: 900px)" in css_text
