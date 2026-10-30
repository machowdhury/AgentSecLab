"""The Attack Service's native notebook search: fail-closed availability, ownership, bounds, rate limits and honest failure states.
Backends are fakes: nothing here talks to Splunk."""
from __future__ import annotations

import time

import pytest
import requests

from agentsec.academy_search import SearchService
from agentsec.attack_app import create_app
from agentsec.loan_desk import search as srch

RUN = "11111111-1111-4111-8111-111111111111"
OTHER = "22222222-2222-4222-8222-222222222222"


class FakeBackend:
    name = "fake"

    def __init__(self, outcome=None, boom=False, delay=0.0):
        self.outcome = outcome or srch.Outcome(True, ["event.name", "events"], [["agentsec.run.started", "1"]], False, None, 12)
        self.calls, self.boom, self.delay = [], boom, delay

    def run(self, spl, *, timeout_s, max_rows):
        self.calls.append((spl, timeout_s, max_rows))
        if self.delay: time.sleep(self.delay)
        if self.boom: raise RuntimeError("secret-token-xyz leaked in a stack trace")
        return self.outcome


def wait(svc, run, sid, tries=200):
    for _ in range(tries):
        r = svc.result(run, sid)
        if r and r["status"] != "PENDING": return r
        time.sleep(0.01)
    raise AssertionError("still pending")


def service(backend="default", **kw):
    b = FakeBackend() if backend == "default" else backend
    return SearchService(backend_factory=lambda env: b, **kw), b


# ------------------------------------------------------------ service
def test_ready_result_carries_provenance_and_is_bounded():
    svc, backend = service()
    code, info = svc.request(RUN, "events_by_field", {"field": "event.name", "limit": 5})
    assert code == "REQUESTED" and len(info["search_id"]) == 16
    r = wait(svc, RUN, info["search_id"])
    assert r["status"] == "READY" and r["rows"] == [["agentsec.run.started", "1"]] and r["row_count"] == 1
    assert (r["evidence_class"], r["backend"], r["duration_ms"]) == ("LIVE", "rest", 12) and "last 24 hours" in r["window"] and r["spl"].startswith("index=agentsec_telemetry")
    assert backend.calls and backend.calls[0][1] == srch.SEARCH_TIMEOUT_S and backend.calls[0][2] == srch.MAX_ROWS


def test_no_provisioned_access_is_unavailable_and_nothing_runs():
    svc = SearchService(backend_factory=lambda env: None)
    assert not svc.available()
    code, info = svc.request(RUN, "events_by_field", {})
    assert code == "UNAVAILABLE" and "search_id" not in info
    assert svc.preview(RUN, "events_by_field", {})[0] == "OK"                     # the printed SPL is still shown, never executed


def test_a_search_id_belongs_to_one_run_and_must_be_well_formed():
    svc, _ = service()
    _, info = svc.request(RUN, "decisions", {})
    assert svc.result(OTHER, info["search_id"]) is None and svc.result(RUN, "../etc/passwd") is None and svc.result(RUN, "0" * 16) is None


def test_bad_template_or_parameters_are_refused_before_any_search():
    svc, backend = service()
    for tpl, params in (("nope", {}), ("events_by_field", {"limit": 999}), ("events_by_field", {"field": "x; delete"}), ("events_by_field", {"extra": 1}), ("decisions", "x")):
        assert svc.request(RUN, tpl, params)[0] == "BAD_REQUEST", (tpl, params)
    assert svc.request("not-a-uuid", "decisions", {})[0] == "BAD_REQUEST"
    assert backend.calls == []


def test_comparison_needs_two_distinct_runs():
    svc, _ = service()
    assert svc.request(RUN, "compare_overview", {})[0] == "BAD_REQUEST"
    assert svc.request(RUN, "compare_overview", {}, RUN)[0] == "BAD_REQUEST"
    code, info = svc.request(RUN, "compare_overview", {}, OTHER)
    assert code == "REQUESTED" and wait(svc, RUN, info["search_id"])["compare_run_id"] == OTHER


def test_a_backend_failure_reads_as_failed_never_as_an_empty_success():
    svc, _ = service(FakeBackend(srch.Outcome(False, error="timeout", duration_ms=30000)))
    r = wait(svc, RUN, svc.request(RUN, "decisions", {})[1]["search_id"])
    assert (r["status"], r["error"], r["ok"]) == ("FAILED", "timeout", False) and "rows" not in r
    svc2, _ = service(FakeBackend(srch.Outcome(False, error="backend_unavailable")))
    assert wait(svc2, RUN, svc2.request(RUN, "decisions", {})[1]["search_id"])["status"] == "UNAVAILABLE"


def test_a_backend_exception_is_a_generic_failure_and_leaks_nothing():
    svc, _ = service(FakeBackend(boom=True))
    r = wait(svc, RUN, svc.request(RUN, "decisions", {})[1]["search_id"])
    assert r["status"] == "FAILED" and r["error"] == "search_failed" and "secret-token" not in str(r)


def test_per_run_and_global_rate_limits_use_the_clock_not_wall_time():
    now = [1000.0]
    svc, _ = service(clock=lambda: now[0])
    codes = []
    for _ in range(22):
        code, info = svc.request(RUN, "decisions", {})
        codes.append(code)
        if code == "REQUESTED": wait(svc, RUN, info["search_id"])                  # finished jobs do not count as in flight
    assert codes.count("REQUESTED") == 20 and codes[-1] == "RATE_LIMITED"
    assert svc.request(OTHER, "decisions", {})[0] == "REQUESTED"                   # another run is not throttled by this one
    now[0] += 61
    assert svc.request(RUN, "decisions", {})[0] == "REQUESTED"


def test_too_many_in_flight_searches_are_refused():
    svc, _ = service(FakeBackend(delay=0.3), workers=1)
    codes = [svc.request(f"{i:08x}-1111-4111-8111-111111111111", "decisions", {})[0] for i in range(12)]
    assert codes.count("RATE_LIMITED") >= 1 and codes[0] == "REQUESTED"


# ------------------------------------------------------------ routes
@pytest.fixture
def client(monkeypatch, settings):
    launched = {"resp": None}

    class R:
        status_code = 202
        def json(self): return {"run_id": launched["id"], "status": "RUNNING"}

    def fake(method, url, **kw):
        launched["id"] = launched.get("next", RUN); return R()

    monkeypatch.setattr(requests, "request", fake)
    return launched


def make(monkeypatch, backend):
    monkeypatch.setenv("AGENTSEC_GATEWAY_MODE", "1")
    app = create_app()
    app.config["AGENTSEC_SEARCH_SERVICE"] = None
    return app


def app_with(monkeypatch, svc, *, gateway=True):
    if gateway: monkeypatch.setenv("AGENTSEC_GATEWAY_MODE", "1")
    from agentsec import attack_app
    import flask
    app = flask.Flask(__name__)
    from agentsec.mission_loan_desk import register_loan_desk_mission
    register_loan_desk_mission(app, acmebank_url="http://acmebank.invalid", version="t", search=svc)
    return app.test_client()


@pytest.fixture
def launcher(monkeypatch):
    state = {"id": RUN}

    class R:
        status_code = 202
        def json(self): return {"run_id": state["id"], "status": "RUNNING"}

    monkeypatch.setattr(requests, "request", lambda *a, **k: R())
    return state


def launch(c, state, run):
    state["id"] = run
    r = c.post("/api/missions/loan-desk/runs", json={"application": {}, "posture": "baseline"})
    assert r.status_code == 202


def test_routes_run_the_search_natively_behind_the_gateway(monkeypatch, launcher):
    svc, backend = service()
    c = app_with(monkeypatch, svc)
    launch(c, launcher, RUN)
    t = c.get("/api/missions/loan-desk/search/templates")
    assert t.status_code == 200 and {x["id"] for x in t.get_json()["templates"]} == set(srch.TEMPLATES)
    p = c.post(f"/api/missions/loan-desk/runs/{RUN}/search/preview", json={"template": "decisions", "params": {"limit": 3}})
    assert p.status_code == 200 and p.get_json()["spl"].startswith("index=agentsec_telemetry") and backend.calls == []
    s = c.post(f"/api/missions/loan-desk/runs/{RUN}/search", json={"template": "decisions", "params": {"limit": 3}})
    assert s.status_code == 202
    sid = s.get_json()["search_id"]
    for _ in range(100):
        r = c.get(f"/api/missions/loan-desk/runs/{RUN}/search/{sid}")
        if r.get_json()["status"] != "PENDING": break
        time.sleep(0.01)
    assert r.status_code == 200 and r.get_json()["status"] == "READY" and r.headers["Cache-Control"].startswith("no-store")


def test_routes_fail_closed_with_a_clear_code_when_access_is_not_provisioned(monkeypatch, launcher):
    c = app_with(monkeypatch, SearchService(backend_factory=lambda env: None))
    launch(c, launcher, RUN)
    s = c.post(f"/api/missions/loan-desk/runs/{RUN}/search", json={"template": "decisions"})
    assert s.status_code == 503 and s.get_json()["error"] == "search_unavailable" and "host verifier" not in s.get_data(as_text=True)
    assert c.get("/api/missions/loan-desk/search/templates").status_code == 200       # the catalog needs no Splunk


def test_routes_refuse_runs_this_service_did_not_launch_and_unknown_body_keys(monkeypatch, launcher):
    svc, backend = service()
    c = app_with(monkeypatch, svc)
    launch(c, launcher, RUN)
    assert c.post(f"/api/missions/loan-desk/runs/{OTHER}/search", json={"template": "decisions"}).status_code == 404
    assert c.post(f"/api/missions/loan-desk/runs/{RUN}/search", json={"template": "decisions", "spl": "search *"}).status_code == 400
    assert c.post(f"/api/missions/loan-desk/runs/{RUN}/search", json={"template": "compare_overview", "compare_run": OTHER}).status_code == 404
    assert c.get(f"/api/missions/loan-desk/runs/{RUN}/search/not-hex").status_code == 404
    assert backend.calls == []


def test_the_browser_can_never_submit_spl(monkeypatch, launcher):
    svc, backend = service()
    c = app_with(monkeypatch, svc)
    launch(c, launcher, RUN)
    for body in ({"spl": "index=* | delete"}, {"template": "decisions", "params": {"field": "| delete"}}, {"template": "index=* | head 1"}, {"template": "decisions", "query": "x"}):
        assert c.post(f"/api/missions/loan-desk/runs/{RUN}/search", json=body).status_code == 400, body
    assert backend.calls == []


def test_the_legacy_bridge_is_off_by_default_and_only_on_explicit_opt_in_outside_the_gateway(monkeypatch, launcher):
    monkeypatch.delenv("AGENTSEC_GATEWAY_MODE", raising=False)
    monkeypatch.delenv("AGENTSEC_LEGACY_HOST_VERIFIER", raising=False)
    svc = SearchService(backend_factory=lambda env: None)
    c = app_with(monkeypatch, svc, gateway=False)
    launch(c, launcher, RUN)
    s = c.post(f"/api/missions/loan-desk/runs/{RUN}/search", json={"template": "decisions"})
    assert s.status_code == 503 and s.get_json()["error"] == "search_unavailable"                       # default: fail closed, nothing forwarded
    monkeypatch.setenv("AGENTSEC_LEGACY_HOST_VERIFIER", "1")
    assert c.get("/api/missions/loan-desk/search/templates").status_code == 202                         # explicit legacy opt-in: forwarded to AcmeBank's bridge as before (stubbed)
    monkeypatch.setenv("AGENTSEC_GATEWAY_MODE", "1")
    assert c.get("/api/missions/loan-desk/search/templates").status_code == 200                         # behind the gateway the flag is ignored



def test_a_run_id_with_a_trailing_newline_is_not_a_run_id(monkeypatch, launcher):
    svc, backend = service()
    assert svc.request(RUN + "\n", "decisions", {})[0] == "BAD_REQUEST" and svc.result(RUN, "0" * 16 + "\n") is None
    c = app_with(monkeypatch, svc)
    launch(c, launcher, RUN)
    assert c.post(f"/api/missions/loan-desk/runs/{RUN}%0A/search", json={"template": "decisions"}).status_code == 404
    assert backend.calls == []


# ------------------------------------------------------------ refused identity is not an empty result
@pytest.mark.parametrize("stage,code,expected", [("authentication", "auth_failed", "access_denied"), ("authorization", "forbidden", "access_denied"),
                                                   ("connectivity", "connect_failed", "backend_unavailable"), ("search", "bad_search", "search_failed")])
def test_rest_backend_tells_a_refused_identity_from_an_unreachable_splunk_and_from_an_empty_result(stage, code, expected):
    from agentsec import splunk_client as sc

    class Client:
        def export_csv(self, spl, *, timeout_s=None, max_bytes=None):
            raise sc.SplunkError(stage, code)
    out = srch.RestBackend(Client()).run("x", timeout_s=1, max_rows=1)
    assert (out.ok, out.error) == (False, expected) and out.rows == []


def test_an_empty_result_is_a_successful_search_with_no_rows_and_a_refusal_never_is():
    class Empty:
        def export_csv(self, spl, *, timeout_s=None, max_bytes=None):
            return "seq,event\n"
    out = srch.RestBackend(Empty()).run("x", timeout_s=1, max_rows=5)
    assert out.ok is True and out.rows == []
