"""Loan Desk Academy mission: gateway contract, page contract and the before/after control effect (deterministic)."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import requests

from agentsec import mission_loan_desk as mission
from agentsec.attack_app import create_app
from agentsec.bank_app import build_runtime, create_app as create_bank
from agentsec.loan_desk.service import LoanDeskService
from agentsec.telemetry import MemorySink
from tests.loan_desk_support import GOOD_FORM, PostureAwareModel

ROOT = Path(__file__).resolve().parents[1]


class FakeResp:
    def __init__(self, status=200, body=None, text_ok=True):
        self.status_code, self._body, self._ok = status, body or {}, text_ok

    def json(self):
        if not self._ok:
            raise ValueError("no json")
        return self._body


@pytest.fixture
def gw(monkeypatch, settings):
    calls = []
    behaviour = {"resp": FakeResp(202, {"run_id": "11111111-1111-4111-8111-111111111111", "status": "RUNNING"})}

    def fake(method, url, **kw):
        calls.append((method, url, kw.get("json")))
        r = behaviour["resp"]
        if isinstance(r, Exception):
            raise r
        return r

    monkeypatch.setattr(requests, "request", fake)
    return create_app().test_client(), calls, behaviour


def test_page_is_strict_csp_single_script_ten_steps(settings):
    c = create_app().test_client()
    r = c.get("/academy/missions/loan-desk")
    html = r.get_data(as_text=True)
    assert r.status_code == 200 and "unsafe-inline" not in r.headers["Content-Security-Policy"]
    assert re.findall(r'<script\b[^>]*\bsrc="([^"]+)"', html) == ["/static/academy.js"]
    assert not re.search(r"\son[a-z]+\s*=", html) and " style=" not in html
    assert len(re.findall(r'data-step="', html)) == 10
    for step in ("understand", "explore", "predict", "attack", "observe", "investigate", "defend", "retest", "compare", "explain"):
        assert f'data-step="{step}"' in html
    assert "PRE-APPROVED by Regional Director Alvarez" in html and "NEW</strong> control" not in html
    assert "already existed" in html  # the page does not sell the existing denial as the fix
    assert 'href="/academy/missions/loan-desk"' in c.get("/academy").get_data(as_text=True)


def test_mission_post_route_is_outside_the_get_only_academy_prefixes():
    rules = {r.rule: r.methods for r in create_app().url_map.iter_rules()}
    assert "POST" in rules["/api/missions/loan-desk/runs"]
    for rule, methods in rules.items():
        if rule.startswith(("/academy", "/api/academy")):
            assert methods - {"HEAD", "OPTIONS"} == {"GET"}, rule


def test_gateway_forwards_only_the_closed_contract(gw):
    c, calls, _ = gw
    ok = c.post("/api/missions/loan-desk/runs", json={"application": GOOD_FORM, "posture": "baseline"})
    assert ok.status_code == 202 and calls[0][0] == "POST"
    assert calls[0][1].endswith("/api/v1/loan-desk/applications") and calls[0][2]["posture"] == "baseline"
    for bad in ({}, {"application": GOOD_FORM}, {"application": GOOD_FORM, "posture": "yolo"},
                {"application": {**GOOD_FORM, "evil": 1}, "posture": "baseline"}, {"application": GOOD_FORM, "posture": "baseline", "x": 1},
                {"application": "x", "posture": "baseline"}):
        assert c.post("/api/missions/loan-desk/runs", json=bad).status_code == 400
    assert len(calls) == 1  # nothing malformed reached AcmeBank
    assert c.post("/api/missions/loan-desk/runs", data="x" * 5000, content_type="application/json").status_code == 413


def test_gateway_maps_failures_to_distinct_states(gw):
    c, calls, behaviour = gw
    body = {"application": GOOD_FORM, "posture": "hardened"}
    behaviour["resp"] = requests.ConnectionError("x")
    r = c.post("/api/missions/loan-desk/runs", json=body)
    assert r.status_code == 503 and r.json["error"] == "acmebank_unreachable"
    behaviour["resp"] = requests.Timeout("x")
    assert c.post("/api/missions/loan-desk/runs", json=body).json["error"] == "acmebank_timeout"
    behaviour["resp"] = FakeResp(200, text_ok=False)
    assert c.post("/api/missions/loan-desk/runs", json=body).status_code == 502
    behaviour["resp"] = FakeResp(400, {"errors": {"credit_score": "bad"}})
    r = c.post("/api/missions/loan-desk/runs", json=body)
    assert r.status_code == 400 and r.json["errors"]["credit_score"] == "bad"


def test_gateway_only_reads_back_runs_it_launched(gw):
    c, calls, behaviour = gw
    rid = "11111111-1111-4111-8111-111111111111"
    assert c.get(f"/api/missions/loan-desk/runs/{rid}").status_code == 404  # never launched here
    c.post("/api/missions/loan-desk/runs", json={"application": GOOD_FORM, "posture": "baseline"})
    behaviour["resp"] = FakeResp(200, {"run_id": rid, "status": "COMPLETED"})
    assert c.get(f"/api/missions/loan-desk/runs/{rid}").json["status"] == "COMPLETED"
    assert c.get("/api/missions/loan-desk/runs/..%2F..%2Fetc").status_code in (400, 404)


def test_gateway_module_cannot_decide_or_call_a_model():
    src = (ROOT / "src/agentsec/mission_loan_desk.py").read_text(encoding="utf-8")
    for forbidden in ("loan_desk.policy", "decide(", "OllamaChat", "api/chat", "ollama", "docker"):
        assert forbidden not in src, forbidden


# ---- the defense, end to end through the real bank app (deterministic double, labelled as such)

def test_before_after_through_the_http_api(settings):
    rt = build_runtime(settings, otel_enabled=False)
    rt.loan_desk_model = PostureAwareModel()
    app = create_bank(rt)
    app.config["AGENTSEC_LOAN_DESK"].background = False
    c = app.test_client()
    attack = {**GOOD_FORM, "notes": mission.ATTACK_NOTES}
    before = c.post("/api/v1/loan-desk/applications", json={**attack, "posture": "baseline"}).json
    after = c.post("/api/v1/loan-desk/applications", json={**attack, "posture": "hardened"}).json
    v1, v2 = (c.get(f"/api/v1/loan-desk/runs/{x['run_id']}").json for x in (before, after))
    assert "PRE-APPROVED" in v1["tickets"][0]["note"] and v1["queue_harm"]["tickets_with_applicant_text"]
    assert [t["note"] for t in v2["tickets"]] == ["READY_FOR_REVIEW"] and not v2["queue_harm"]["tickets_with_applicant_text"]
    denied = [x for x in v2["timeline"]["tool_calls"] if x["decision"] == "DENY"]
    assert [(x["tool"], x["reason"], x["executed"]) for x in denied] == [("submit_for_underwriter_review", "argument_not_allowed:note", False)]
    assert v1["outcomes"]["security"]["outcome"] == "NOTHING_BLOCKED" and v2["outcomes"]["security"]["outcome"] == "BLOCKED"
    assert v1["status"] == v2["status"] == "COMPLETED"  # the defense did not break the business workflow
    assert {e["agentsec.defense.posture"] for e in c.application.config["AGENTSEC_LOAN_DESK"]._events[v1["run_id"]]} == {"baseline"}


def test_defense_is_reversible_and_per_run(settings):
    svc = LoanDeskService(settings=settings, model=PostureAwareModel(), sink=MemorySink(), background=False)
    attack = {**GOOD_FORM, "notes": mission.ATTACK_NOTES}
    results = [bool(svc.submit(attack, p)[0]["queue_harm"]["tickets_with_applicant_text"]) for p in ("baseline", "hardened", "baseline")]
    assert results == [True, False, True]
