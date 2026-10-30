"""Finding -> investigation notebook -> retest comparison. Fake Splunk and fake search backend only. Live-class events are CLONES of committed specimens with new run ids
(they exist only in these tests)."""
from __future__ import annotations

import json
import re
import time
import uuid

import pytest
from flask import Flask

from agentsec import academy_investigation as AI
from agentsec.academy_assurance import AssuranceService, Dataset, recorded_events, register_assurance
from agentsec.academy_investigation import CELLS, Ctx, InvestigationService, register_investigation
from agentsec.academy_search import SearchService
from agentsec.assurance import engine as E
from agentsec.loan_desk import search as srch
from tests.test_academy_assurance import ACC, NOW, NS, FakeClient, clone, iso, recorded_by_run, svc


def pair_run_ids():
    """(attack run id, retest run id, finding) of a recorded ATTACK finding whose retest is VALIDATED."""
    ds = AssuranceService()._recorded()
    a = next(f for f in ds.findings if f["mode"] == "ATTACK" and f["retest"]["outcome"] == "VALIDATED" and f["hop"] is not None)
    return a["run_id"], a["retest"]["run_id"], a


def live_pair(*, drop_from_retest=0, extra_retest=False):
    """Cloned live attack + retest runs (+ optionally a second retest), as Splunk events."""
    a_id, r_id, _ = pair_run_ids()
    rec = recorded_by_run()
    ev = clone(rec[a_id], "live-attack", NOW - 3600) + clone(rec[r_id], "live-retest", NOW - 1800)
    if extra_retest:
        ev += clone(rec[r_id], "live-retest-2", NOW - 900)
    if drop_from_retest:
        rid = str(uuid.uuid5(NS, "live-retest"))
        gone = [e for e in ev if e["agentsec.run.id"] == rid and e.get("event.name") == "agentsec.mcp.completed"][:drop_from_retest] or \
               [e for e in ev if e["agentsec.run.id"] == rid][1:2]
        ev = [e for e in ev if not any(e is g for g in gone)]
    return ev


class FakeBackend:
    name = "fake"

    def __init__(self, outcome=None):
        self.outcome = outcome or srch.Outcome(True, ["seq", "event"], [["1", "agentsec.run.started"]], False, None, 9)
        self.calls = []

    def run(self, spl, *, timeout_s, max_rows):
        self.calls.append(spl)
        return self.outcome


def wait(inv, fid, sid):
    for _ in range(300):
        r = inv.live_result(fid, "7d", sid)
        if r and r["status"] != "PENDING":
            return r
        time.sleep(0.01)
    raise AssertionError("pending")


def make(events, backend="default"):
    a = svc(FakeClient(events))
    b = FakeBackend() if backend == "default" else backend
    s = SearchService(backend_factory=lambda env: b) if b is not None else SearchService(backend_factory=lambda env: None)
    return InvestigationService(a, s), a, b


def live_attack_fid(a: AssuranceService):
    ds = a._splunk("7d")[0]
    f = next(x for x in ds.findings if x["mode"] == "ATTACK" and x["hop"] is not None and x["run_id"] == str(uuid.uuid5(NS, "live-attack")))
    return f


def rec_inv():
    return InvestigationService(AssuranceService(), None)


# ------------------------------------------------------------------ the notebook keeps the finding's own run, control, hop and class
def test_a_live_notebook_is_bound_to_the_findings_run_control_hop_and_class_and_shows_the_exact_spl():
    inv, a, _ = make(live_pair())
    f = live_attack_fid(a)
    c = inv.context("live", f["finding_id"], "7d")
    o = c["origin"]
    assert (o["run_id"], o["control_id"], o["hop"], o["evidence_class"], o["finding_id"]) == (f["run_id"], f["control_id"], f["hop"], "LIVE", f["finding_id"])
    assert c["mode"] == "splunk" and c["search_ready"] is True and "no Splunk search runs" not in c["source"]
    for cell in c["cells"]:
        assert f'"agentsec.run.id"="{f["run_id"]}"' in cell["spl"] and cell["spl"].startswith("index=agentsec_telemetry")
        assert "agentsec.security_event" in cell["spl"]
    dec = next(x for x in c["cells"] if x["id"] == "control_decisions")["spl"]
    assert f'control="{f["control_id"]}"' in dec and f"tonumber(hop)={f['hop']}" in dec
    assert [p["name"] for p in next(x for x in c["cells"] if x["id"] == "control_decisions")["params"]] == ["control", "scope", "limit"]


def test_recorded_and_fixture_cells_are_local_and_say_that_no_search_ran():
    _, _, f = pair_run_ids()
    c = rec_inv().context("recorded", f["finding_id"], "all")
    assert c["mode"] == "local" and c["search_ready"] is False and "no Splunk search runs" in c["source"]
    assert all(x["spl"] is None for x in c["cells"]) and c["origin"]["evidence_class"] == "RECORDED" and c["origin"]["adoptable"] is False
    code, r = rec_inv().run_local("recorded", f["finding_id"], "all", "control_decisions", {})
    assert code == "OK" and r["source"] == "local" and r["spl"] is None and "No Splunk search ran" in r["note"] and r["evidence_class"] == "RECORDED"


def test_local_cells_return_exactly_the_events_of_the_findings_run():
    _, _, f = pair_run_ids()
    ds = AssuranceService()._recorded()
    ev = ds.runs[f["run_id"]]["events"]
    code, r = rec_inv().run_local("recorded", f["finding_id"], "all", "run_events", {"scope": "run", "limit": 50})
    assert code == "OK" and len(r["rows"]) == len(ev) and [row[1] for row in r["rows"]] == [e["event.name"] for e in sorted(ev, key=lambda e: e["agentsec.sequence"])]
    code, r = rec_inv().run_local("recorded", f["finding_id"], "all", "run_events", {})
    assert {row[2] for row in r["rows"]} == {str(f["hop"])}                       # default scope = the finding's hop
    code, r = rec_inv().run_local("recorded", f["finding_id"], "all", "control_decisions", {"control": "this"})
    assert r["rows"] and {row[2] for row in r["rows"]} == {f["control_id"]}
    code, r = rec_inv().run_local("recorded", f["finding_id"], "all", "execution_check", {"scope": "run"})
    assert all(len(row) == 4 for row in r["rows"])


def test_a_run_level_finding_has_no_hop_or_control_scope_to_offer():
    ds = AssuranceService()._recorded()
    f = next((x for x in ds.findings if x["control_id"] in ("(none)", "(run)") or x["hop"] is None), None)
    if f is None:
        pytest.skip("no run-level finding among the committed examples")
    c = rec_inv().context("recorded", f["finding_id"], "all")
    assert all(p["name"] == "limit" or p["name"] == "scope" and f["hop"] is not None for cell in c["cells"] for p in cell["params"])


# ------------------------------------------------------------------ only approved templates run; nothing comes from the browser but ids and bounded params
def test_parameters_are_validated_and_unknown_cells_or_fields_are_refused():
    _, _, f = pair_run_ids()
    inv = rec_inv()
    for bad in ({"limit": 0}, {"limit": 51}, {"limit": "5"}, {"limit": True}, {"scope": "x"}, {"control": "CTRL-X"}, {"spl": "search *"}, {"run_id": str(uuid.uuid4())}, "x", [1]):
        code, info = inv.run_local("recorded", f["finding_id"], "all", "control_decisions", bad)
        assert code == "BAD_REQUEST" and info["detail"], bad
    for cell in ("nope", "../x", "RUN_EVENTS", "", None, 7):
        assert inv.run_local("recorded", f["finding_id"], "all", cell, {})[0] == "UNKNOWN"


def test_the_built_spl_contains_nothing_that_was_not_validated():
    inv, a, _ = make(live_pair())
    f = live_attack_fid(a)
    ctx = AI.InvestigationService._ctx(f)
    from agentsec import spl_policy
    for cell in CELLS.values():
        for p in ({}, {"limit": 7}, {"scope": "run", "limit": 50}, {"control": "all", "scope": "run"}):
            try:
                clean = cell.clean(ctx, p)
            except ValueError:                                  # the cell does not offer that parameter
                continue
            spl = cell.spl(ctx, clean)
            assert spl_policy.check(spl) == spl and ";" not in spl and "\n" not in spl
            assert f'"agentsec.run.id"="{ctx.run}"' in spl and spl.count(ctx.run) == 1


def test_a_live_cell_runs_through_the_search_service_and_returns_the_exact_spl_and_class():
    inv, a, b = make(live_pair())
    f = live_attack_fid(a)
    code, info = inv.run_live(f["finding_id"], "7d", "run_events", {"limit": 5, "scope": "run"})
    assert code == "REQUESTED"
    r = wait(inv, f["finding_id"], info["search_id"])
    assert r["status"] == "READY" and r["evidence_class"] == "LIVE" and r["spl"] == info["spl"] == b.calls[0] and "limit" not in r["spl"] and "head 5" in r["spl"]
    assert r["window"] == AI.WINDOW_TEXT and r["finding_id"] == f["finding_id"]


def test_a_search_result_is_only_readable_through_its_own_finding():
    inv, a, _ = make(live_pair())
    f = live_attack_fid(a)
    other = next(x for x in a._splunk("7d")[0].findings if x["run_id"] != f["run_id"])
    code, info = inv.run_live(f["finding_id"], "7d", "run_events", {})
    wait(inv, f["finding_id"], info["search_id"])
    assert inv.live_result(other["finding_id"], "7d", info["search_id"]) is None
    assert inv.live_result(f["finding_id"], "7d", "0" * 16) is None and inv.live_result(f["finding_id"], "7d", "../../x") is None


def test_live_cells_fail_closed_when_search_access_is_missing_and_never_read_as_empty():
    inv, a, _ = make(live_pair(), backend=None)
    f = live_attack_fid(a)
    assert inv.context("live", f["finding_id"], "7d")["search_ready"] is False
    code, info = inv.run_live(f["finding_id"], "7d", "run_events", {})
    assert code == "UNAVAILABLE" and info["reason"]


@pytest.mark.parametrize("outcome,status", [(srch.Outcome(False, error="timeout"), "FAILED"), (srch.Outcome(False, error="backend_unavailable"), "UNAVAILABLE"),
                                            (srch.Outcome(False, error="search_failed"), "FAILED"), (srch.Outcome(True, ["seq"], [], False, None, 3), "READY")])
def test_failed_unavailable_and_empty_results_are_distinct_states(outcome, status):
    inv, a, _ = make(live_pair(), backend=FakeBackend(outcome))
    f = live_attack_fid(a)
    code, info = inv.run_live(f["finding_id"], "7d", "control_decisions", {})
    r = wait(inv, f["finding_id"], info["search_id"])
    assert r["status"] == status
    if status == "READY":
        assert r["rows"] == [] and r["row_count"] == 0
    else:
        assert "rows" not in r and r["ok"] is False


def test_a_finding_only_opens_in_its_own_evidence_class():
    inv, a, _ = make(live_pair())
    f = live_attack_fid(a)
    assert inv.context("recorded", f["finding_id"], "all") is None and inv.context("fixtures", f["finding_id"], "7d") is None
    _, _, rf = pair_run_ids()
    assert inv.context("live", rf["finding_id"], "7d") is None
    assert inv.run_local("recorded", f["finding_id"], "all", "run_events", {})[0] == "UNKNOWN"
    assert inv.run_local("live", f["finding_id"], "7d", "run_events", {})[0] == "BAD_REQUEST"


def test_an_unreadable_splunk_is_unavailable_for_the_notebook_too():
    from agentsec import splunk_client as sc
    a = svc(FakeClient(error=sc.SplunkError("connectivity", "connect_failed")))
    inv = InvestigationService(a, None)
    assert inv.context("live", "F-0123456789ab", "7d") == {"state": "unavailable", "reason": "unreachable", "tab": "live"}
    assert inv.comparison("live", "F-0123456789ab", "7d")["state"] == "unavailable"
    assert inv.run_live("F-0123456789ab", "7d", "run_events", {})[0] == "UNAVAILABLE"


# ------------------------------------------------------------------ retest comparison from validated linked runs only
def test_a_validated_retest_is_compared_per_hop_from_the_two_linked_runs():
    _, r_id, f = pair_run_ids()
    cmp = rec_inv().comparison("recorded", f["finding_id"], "all")
    assert cmp["kind"] == "linked" and cmp["outcome"] == "VALIDATED" and cmp["comparable"] is True and cmp["candidates"] >= 1
    assert cmp["attack"]["run_id"] == f["run_id"] and cmp["retest"]["run_id"] == r_id and cmp["retest"]["status"] == "VERIFIED_EFFECTIVE"
    assert cmp["rows"] and all(set(r) == {"hop", "attack", "retest"} for r in cmp["rows"]) and cmp["evidence_class"] == "RECORDED"
    row = next(r for r in cmp["rows"] if r["hop"] == f["hop"])
    assert row["retest"]["decision"] in ("DENY", "ALLOW", "OBSERVE") and row["attack"]["decision"]
    assert not {"score", "effectiveness", "effectiveness_pct", "percent"} & set(cmp) and all(not {"score", "percent"} & set(r) for r in cmp["rows"])


def test_the_comparison_opens_from_either_side_and_reports_the_same_pair():
    _, r_id, f = pair_run_ids()
    ds = AssuranceService()._recorded()
    rf = next(x for x in ds.findings if x["run_id"] == r_id and x["control_id"] == f["control_id"])
    a, b = rec_inv().comparison("recorded", f["finding_id"], "all"), rec_inv().comparison("recorded", rf["finding_id"], "all")
    assert (a["attack"]["run_id"], a["retest"]["run_id"], a["outcome"]) == (b["attack"]["run_id"], b["retest"]["run_id"], b["outcome"])


def test_no_retest_is_stated_and_nothing_is_compared_or_claimed():
    ds = AssuranceService()._recorded()
    f = next(x for x in ds.findings if x["mode"] == "ATTACK" and x["retest"]["outcome"] == "NO_RETEST")
    cmp = rec_inv().comparison("recorded", f["finding_id"], "all")
    assert cmp["kind"] == "no_retest" and "rows" not in cmp and "retest" not in cmp and cmp["outcome"] == "NO_RETEST" and "no effectiveness is claimed" in cmp["message"]


def test_a_baseline_run_has_no_comparison():
    ds = AssuranceService()._recorded()
    f = next(x for x in ds.findings if x["mode"] == "BASELINE")
    cmp = rec_inv().comparison("recorded", f["finding_id"], "all")
    assert cmp["kind"] == "none" and cmp["reason"] == "not_applicable"


def test_a_recorded_retest_never_validates_a_live_attack():
    a_id, _, _ = pair_run_ids()
    rec = recorded_by_run()
    inv, a, _ = make(clone(rec[a_id], "live-attack", NOW - 3600) + recorded_events())
    f = live_attack_fid(a)
    cmp = inv.comparison("live", f["finding_id"], "7d")
    assert cmp["kind"] == "no_retest" and cmp["outcome"] == "NO_RETEST" and "never validates a live attack" in cmp["message"]


def test_live_pair_links_and_validates_only_with_a_verified_effective_live_retest():
    inv, a, _ = make(live_pair())
    f = live_attack_fid(a)
    cmp = inv.comparison("live", f["finding_id"], "7d")
    assert cmp["kind"] == "linked" and cmp["evidence_class"] == "LIVE" and cmp["retest"]["run_id"] == str(uuid.uuid5(NS, "live-retest")) and cmp["outcome"] == f["retest"]["outcome"]


def test_an_incomplete_retest_is_not_presented_as_a_comparison():
    inv, a, _ = make(live_pair(drop_from_retest=1))
    f = live_attack_fid(a)
    cmp = inv.comparison("live", f["finding_id"], "7d")
    assert cmp["kind"] == "linked" and cmp["comparable"] is False and cmp["retest"]["complete"] is False
    assert cmp["outcome"] != "VALIDATED" and any("incomplete" in n for n in cmp["notes"]) and cmp["retest"]["status"] != "VERIFIED_EFFECTIVE"


def test_several_retests_say_which_one_is_linked_and_that_the_others_are_not_compared():
    inv, a, _ = make(live_pair(extra_retest=True))
    f = live_attack_fid(a)
    cmp = inv.comparison("live", f["finding_id"], "7d")
    assert cmp["candidates"] == 2 and any("lowest run id" in n for n in cmp["notes"])


# ------------------------------------------------------------------ routes
@pytest.fixture
def client():
    app = Flask(__name__)
    inv, a, _ = make(live_pair())
    register_assurance(app, a)
    register_investigation(app, inv)
    return app.test_client(), live_attack_fid(a)["finding_id"], app


def test_routes_read_context_and_comparison_and_never_cache(client):
    c, fid, _ = client
    r = c.get(f"/api/assurance/findings/{fid}/investigation?tab=live&window=7d")
    assert r.status_code == 200 and r.headers["Cache-Control"].startswith("no-store") and r.get_json()["origin"]["finding_id"] == fid
    assert c.get(f"/api/assurance/findings/{fid}/comparison?tab=live&window=7d").get_json()["kind"] == "linked"
    for bad in ("?tab=fixtures", "?tab=x", "?window=1y", "?tab=live&window=7d&x=1"):
        assert c.get(f"/api/assurance/findings/{fid}/investigation" + bad).status_code == 400, bad
    assert c.get("/api/assurance/findings/F-000000000000/investigation?tab=live").status_code == 404
    assert c.get("/api/assurance/findings/F-0123456789ab%0A/investigation").status_code in (400, 404)


def test_post_runs_a_live_cell_only_and_accepts_nothing_but_bounded_params(client):
    c, fid, _ = client
    r = c.post(f"/api/assurance/findings/{fid}/cells/run_events?window=7d", json={"params": {"limit": 3, "scope": "run"}})
    assert r.status_code == 202 and r.get_json()["spl"].count("head 3") == 1
    sid = r.get_json()["search_id"]
    for _ in range(200):
        g = c.get(f"/api/assurance/findings/{fid}/searches/{sid}?window=7d")
        if g.get_json().get("status") != "PENDING": break
        time.sleep(0.01)
    assert g.status_code == 200 and g.get_json()["status"] == "READY"
    for body in ({"params": {"spl": "search *"}}, {"spl": "search *"}, {"run_id": str(uuid.uuid4())}, {"params": {"limit": 999}}, {"params": "x"}):
        assert c.post(f"/api/assurance/findings/{fid}/cells/run_events?window=7d", json=body).status_code == 400, body
    assert c.post(f"/api/assurance/findings/{fid}/cells/nope?window=7d", json={}).status_code == 404
    assert c.post(f"/api/assurance/findings/F-000000000000/cells/run_events?window=7d", json={}).status_code == 404
    assert c.post(f"/api/assurance/findings/{fid}/cells/run_events?window=7d&run=1", json={}).status_code == 400
    assert c.get(f"/api/assurance/findings/{fid}/searches/zzzz?window=7d").status_code == 404


def test_explore_serves_recorded_and_fixtures_and_refuses_live(client):
    c, fid, _ = client
    assert c.get(f"/api/assurance/findings/{fid}/explore/run_events?tab=live").status_code == 400
    assert c.get(f"/api/assurance/findings/{fid}/explore/run_events").status_code == 400
    _, _, f = pair_run_ids()
    app = Flask(__name__)
    inv = rec_inv()
    register_investigation(app, inv)
    c2 = app.test_client()
    r = c2.get(f"/api/assurance/findings/{f['finding_id']}/explore/control_decisions?tab=recorded&limit=3&scope=run")
    assert r.status_code == 200 and r.get_json()["source"] == "local" and len(r.get_json()["rows"]) <= 3
    assert c2.get(f"/api/assurance/findings/{f['finding_id']}/explore/control_decisions?tab=recorded&limit=x").status_code == 400
    assert c2.get(f"/api/assurance/findings/{f['finding_id']}/explore/control_decisions?tab=recorded&spl=1").status_code == 400
    assert c2.get(f"/api/assurance/findings/{f['finding_id']}/explore/nope?tab=recorded").status_code == 404


def test_fixtures_have_their_own_operator_paths_and_no_post():
    app = Flask(__name__)
    a = svc(FakeClient([e for fx in ACC.fixtures().values() for e in fx["events"]]))
    register_assurance(app, a)
    register_investigation(app, InvestigationService(a, None))
    c = app.test_client()
    ov = c.get("/api/assurance/fixtures/overview?window=all").get_json()
    fid = ov["attention_all"][0]["finding_id"]
    ctx = c.get(f"/api/assurance/fixtures/findings/{fid}/investigation?window=all").get_json()
    assert ctx["origin"]["evidence_class"] == "TEST_FIXTURE" and ctx["mode"] == "local" and "synthetic" in ctx["source"]
    assert c.get(f"/api/assurance/fixtures/findings/{fid}/explore/run_events?window=all").status_code == 200
    assert c.get(f"/api/assurance/fixtures/findings/{fid}/comparison?window=all").status_code == 200
    assert c.post(f"/api/assurance/fixtures/findings/{fid}/cells/run_events", json={}).status_code in (404, 405)


def test_the_recorded_overview_speaks_of_findings_to_explore_not_incidents():
    o = svc(None).overview("recorded", "all")
    assert "to explore" in o["headline"]["text"] and "attention" not in o["headline"]["text"]
    live = svc(FakeClient(live_pair())).overview("live", "7d")
    assert "to explore" not in live["headline"]["text"]


def test_the_module_never_reads_a_run_id_control_hop_or_spl_from_the_request():
    src = (AI.__file__ and open(AI.__file__).read())
    routes = src[src.index("def register_investigation"):]
    assert "request.args.get(\"run" not in routes and "get_json" in routes
    for name in ("run_id", "control_id", "hop", "spl"):
        assert f'data.get("{name}")' not in routes and f'request.args["{name}"]' not in routes


# ------------------------------------------------------------------ the findings of one live run (workshop Investigate / Explain stages)
def test_run_findings_lists_the_rules_findings_of_the_learners_live_run_only():
    inv, a, _ = make(live_pair())
    rid = str(uuid.uuid5(NS, "live-attack"))
    r = inv.run_findings(rid)
    f = live_attack_fid(a)
    assert r["state"] == "ok" and r["found"] is True and r["run"]["complete"] is True
    assert f["finding_id"] in [x["finding_id"] for x in r["findings"]] and all(x["mode"] == "ATTACK" for x in r["findings"])
    assert all(set(x) >= {"finding_id", "title", "status_label", "hop", "control_id", "retest"} for x in r["findings"])


def test_a_run_splunk_does_not_hold_is_not_found_not_a_pass_and_recorded_runs_are_never_offered():
    inv, a, _ = make(live_pair())
    none = inv.run_findings(str(uuid.uuid4()))
    assert none["found"] is False and none["findings"] == []
    a_id, _, _ = pair_run_ids()
    inv2, _, _ = make(recorded_events())                  # the recorded runs arrive through Splunk too: they are RECORDED, never the learner's live run
    assert inv2.run_findings(a_id)["found"] is False
    assert inv.run_findings("not-a-uuid") == {"state": "bad_request"}


def test_run_findings_is_unavailable_when_splunk_cannot_be_read_and_the_route_validates():
    from agentsec import splunk_client as sc
    inv = InvestigationService(svc(FakeClient(error=sc.SplunkError("connectivity", "connect_failed"))), None)
    assert inv.run_findings(str(uuid.uuid4())) == {"state": "unavailable", "reason": "unreachable"}
    app = Flask(__name__)
    inv2, a, _ = make(live_pair())
    register_investigation(app, inv2)
    c = app.test_client()
    rid = str(uuid.uuid5(NS, "live-attack"))
    assert c.get(f"/api/assurance/runs/{rid}/findings").get_json()["found"] is True
    assert c.get(f"/api/assurance/runs/{rid}/findings?x=1").status_code == 400
    assert c.get("/api/assurance/runs/not-a-uuid/findings").status_code in (400, 404)
    assert c.post(f"/api/assurance/runs/{rid}/findings").status_code == 405


def test_execution_check_leaves_out_events_without_a_hop_like_splunks_stats_by_hop():
    """Found on a real Splunk: the run's start and end events carry no hop, `stats ... by hop` drops them, so the in-memory twin must too."""
    _, _, f = pair_run_ids()
    code, r = rec_inv().run_local("recorded", f["finding_id"], "all", "execution_check", {"scope": "run"})
    assert code == "OK" and r["rows"] and all(row[0] != "" for row in r["rows"])
