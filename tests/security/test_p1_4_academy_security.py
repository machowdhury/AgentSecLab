"""P1.4 security: the Academy is read-only, cannot authorize, and shows no demo data.

* Academy routes are GET only; launching still uses the existing closed
  POST /api/launch contract, and the browser never sends a prediction.
* Pages run under a strict CSP with no inline script, inline handlers or
  inline styles; the client writes server values with textContent only.
* The evidence endpoint cannot be used to browse the artifacts tree.
* None of the Figma prototype's demonstration data is presented as evidence.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from agentsec.attack_app import AcmeBankClient, create_app

ROOT = Path(__file__).resolve().parents[2]
TEMPLATES = ROOT / "src" / "agentsec" / "templates" / "academy"
SCRIPT = ROOT / "src" / "agentsec" / "static" / "academy.js"
PAGES = ("/academy", "/academy/foundations", "/academy/path", "/academy/status", "/academy/labs/LAB-MCP-001")
LIVE_ID = "11111111-2222-4333-8444-555555555555"


def _healthy(_path):
    return 200, {"status": "healthy", "security.profile": "defended", "ollama_model": "model-label"}


@pytest.fixture()
def app(tmp_path):
    application = create_app(AcmeBankClient("http://acmebank.example:5000", get_fn=_healthy), launch_kwargs={"artifacts_dir": tmp_path})
    application.config["TESTING"] = True
    return application


def test_academy_routes_are_read_only(app):
    for rule in app.url_map.iter_rules():
        if rule.rule.startswith(("/academy", "/api/academy")):
            assert rule.methods - {"HEAD", "OPTIONS"} == {"GET"}, rule.rule


@pytest.mark.parametrize("path", PAGES)
def test_pages_send_a_strict_csp_and_hardening_headers(app, path):
    response = app.test_client().get(path)
    assert response.status_code == 200
    csp = response.headers["Content-Security-Policy"]
    for directive in ("default-src 'self'", "script-src 'self'", "style-src 'self'", "object-src 'none'", "frame-ancestors 'none'", "base-uri 'none'"):
        assert directive in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"


@pytest.mark.parametrize("path", PAGES)
def test_pages_have_no_inline_script_handlers_or_styles(app, path):
    html = app.test_client().get(path).get_data(as_text=True)
    scripts = re.findall(r"<script\b[^>]*>(.*?)</script>", html, flags=re.S)
    assert all(not body.strip() for body in scripts)
    assert re.findall(r'<script\b[^>]*\bsrc="([^"]+)"', html) == ["/static/academy.js"]
    assert not re.search(r"\son[a-z]+\s*=", html)
    assert " style=" not in html
    assert "fonts.googleapis" not in html


def test_client_script_never_writes_markup_or_evaluates_code():
    source = SCRIPT.read_text(encoding="utf-8")
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", ".style."):
        assert sink not in source, sink


def test_launch_body_is_the_closed_contract_without_prediction():
    source = SCRIPT.read_text(encoding="utf-8")
    bodies = re.findall(r"body:\s*JSON\.stringify\((\{[^}]*\})\)", source)
    assert bodies == ['{lab_id: LAB, specimen_id: SPECIMEN[mode], mode: mode, execution: "live"}']
    assert source.count('fetch("/api/launch"') == 1
    assert "prediction" not in bodies[0]


def test_evidence_endpoint_refuses_runs_this_service_did_not_launch(app, tmp_path):
    directory = tmp_path / LIVE_ID
    directory.mkdir()
    (directory / "events.jsonl").write_text(json.dumps({"agentsec.run.id": LIVE_ID, "event.name": "agentsec.run.started", "timestamp": "t"}) + "\n")
    response = app.test_client().get(f"/api/academy/evidence/{LIVE_ID}")
    assert response.status_code == 404
    assert response.get_json()["error"] == "unknown_run"


@pytest.mark.parametrize("bad", ["..%2F..%2Fetc%2Fpasswd", "UPPER-CASE", "5e8f55f3-eb46-47ee-b979-b72d9c9b1f49x"])
def test_evidence_endpoint_rejects_malformed_ids(app, bad):
    response = app.test_client().get(f"/api/academy/evidence/{bad}")
    assert response.status_code in (400, 404)
    body = response.get_json()
    assert body["error_class"] == "ERROR"


def test_compare_rejects_unknown_parameters(app):
    response = app.test_client().get("/api/academy/compare?attack=a&retest=b&profile=vulnerable")
    assert response.status_code == 400
    assert response.get_json()["error"] == "unknown_fields"


def test_academy_cannot_reach_a_policy_decision_point():
    source = (ROOT / "src" / "agentsec" / "academy_web.py").read_text(encoding="utf-8")
    source += (ROOT / "src" / "agentsec" / "academy_evidence.py").read_text(encoding="utf-8")
    for forbidden in ("authorize_tool", "evaluate_mcp_control", "AllowTicket", "settings_for_experiment", "requests.post"):
        assert forbidden not in source


#: Values that exist only in the Figma prototype's in-memory demo data.
FIGMA_DEMO_VALUES = (
    "5ff6c21f", "09a4e621", "Today, 09:42", "14:32:08", "input_pattern_matched",
    "Indexed evidence found · 3 events", "Indexing latency", "KV Store", "Last tested: 2 min ago",
    "LIVE ENVIRONMENT", "llama3.2:1b", "curriculumStats", "3 / 5 labs", "Good morning, Alex",
    "mcp-authz-01", "transfer-tool",
)


def test_no_figma_demo_data_is_shipped():
    shipped = SCRIPT.read_text(encoding="utf-8") + "".join(p.read_text(encoding="utf-8") for p in TEMPLATES.glob("*.html"))
    for value in FIGMA_DEMO_VALUES:
        assert value not in shipped, value


def test_workshop_keeps_the_lab_boundary_statements(app):
    html = app.test_client().get("/academy/labs/LAB-MCP-001").get_data(as_text=True)
    start = html.split('id="step-start"')[1].split("</section>\n\n<!-- 2")[0]
    for statement in (
        "DET-MCP-001 is packaged disabled",
        "This workshop does not enable it",
        "Not a notable-event pack",
        "Splunk does not ALLOW or DENY a tool",
        "only policy decision point",
    ):
        assert statement in start


def _section(html: str, step: str) -> str:
    return html.split(f'id="step-{step}"')[1].split("<!--")[0]


def test_predict_step_is_unbiased(app):
    predict = _section(app.test_client().get("/academy/labs/LAB-MCP-001").get_data(as_text=True), "predict")
    assert re.findall(r'name="predict-control" value="(\w+)"', predict) == ["ALLOW", "DENY", "ERROR", "UNSURE"]
    assert re.findall(r'name="predict-execution" value="(\w+)"', predict) == ["YES", "NO", "UNSURE"]
    assert "checked" not in predict
    lowered = predict.lower()
    for leak in ("tool_not_granted", "fail_open", "fail open", "vulnerable", "handler count", "pipeline stopped", "mcp.started", "defended"):
        assert leak not in lowered, leak
    assert "not graded" in predict


def test_status_never_claims_splunk_indexing(app):
    checks = {c["name"]: c for c in app.test_client().get("/api/academy/status").get_json()["checks"]}
    splunk = checks["Splunk indexing"]
    assert splunk["state"] == "NOT CHECKED"
    assert splunk["evidence"] == "UNTESTED"


def test_status_reports_an_unreachable_runtime_as_unavailable(tmp_path):
    application = create_app(AcmeBankClient("http://acmebank.example:5000", get_fn=lambda _p: (503, {"error": "down"})), launch_kwargs={"artifacts_dir": tmp_path})
    checks = {c["name"]: c for c in application.test_client().get("/api/academy/status").get_json()["checks"]}
    assert checks["AcmeBank runtime"]["state"] == "UNAVAILABLE"
