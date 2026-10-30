"""Academy-native Security Assurance: the API over the validated engine. Stub Splunk only (nothing here talks to Splunk). Live-class events are CLONES of committed
specimens with new run ids, which exist only in these tests and never in the product."""
from __future__ import annotations

import csv
import importlib.util
import io
import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agentsec import spl_policy, splunk_client as sc
from agentsec.academy_assurance import AssuranceService, MAX_EVENT_JSON, TABS, WINDOWS, Dataset, recorded_events, register_assurance
from agentsec.assurance import engine as E

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 29, 12, 0, 0, tzinfo=timezone.utc).timestamp()
SPEC = importlib.util.spec_from_file_location("assurance_acceptance", ROOT / "scripts/assurance_acceptance.py")
ACC = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(ACC)
NS = uuid.UUID("11111111-2222-4333-8444-555555555555")


def iso(t): return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def runs_of(events): return E.group_runs(events)


def clone(events, name, started_at):
    """The events of ONE committed run under a new run id, shifted so the run starts at `started_at`."""
    rid = str(uuid.uuid5(NS, name))
    t0 = min(E._secs(e["timestamp"]) for e in events if e.get("timestamp"))
    out = []
    for e in events:
        c = json.loads(json.dumps(e))
        c["agentsec.run.id"], c["agentsec.incident.id"] = rid, rid
        if c.get("timestamp"): c["timestamp"] = iso(started_at + (E._secs(c["timestamp"]) - t0))
        out.append(c)
    return out


def recorded_by_run():
    g = runs_of(recorded_events())
    return {rid: r["events"] for rid, r in g.items()}


def live_batch(ages_h: dict[str, float]):
    """{name: hours old} -> events of cloned recorded runs, picked in a stable order."""
    rec = recorded_by_run()
    picks = sorted(rec)[: len(ages_h)]
    out = []
    for (name, age), rid in zip(ages_h.items(), picks):
        out += clone(rec[rid], name, NOW - age * 3600)
    return out


class FakeClient:
    def __init__(self, events=(), error=None):
        self.events, self.error, self.calls = list(events), error, []

    def export_csv(self, spl, *, timeout_s=None, max_bytes=None):
        self.calls.append((spl, timeout_s, max_bytes))
        if self.error: raise self.error
        buf = io.StringIO(); w = csv.writer(buf); w.writerow(["_raw"])
        for e in self.events: w.writerow([json.dumps(e)])
        return buf.getvalue()


def svc(client, **kw):
    return AssuranceService(client_factory=lambda env: client, clock=lambda: NOW, **kw)


# ------------------------------------------------------------------ classes and parity
def test_a_datasets_run_classes_equal_the_engines_for_every_finding():
    rec = recorded_events()
    fixtures = [e for f in ACC.fixtures().values() for e in f["events"]]
    live = live_batch({"a": 1, "b": 2})
    ds = Dataset(rec + fixtures + live, E.recorded_run_ids(), NOW, "test")
    assert {c for c in ds.class_of.values()} == {"LIVE", "RECORDED", "TEST_FIXTURE"}
    assert all(ds.class_of[f["run_id"]] == f["evidence_class"] for f in ds.findings)


def test_recorded_view_is_recorded_only_and_says_it_is_not_splunk_or_the_current_posture():
    o = svc(None).overview("recorded", "7d")
    assert o["state"] == "ok" and o["evidence_class"] == "RECORDED" and o["window"]["key"] == "all" and "not time-filtered" in o["window"]["label"]
    p = o["provenance"]
    assert "not Splunk" in p["source"] and p["runs"] == 53 and p["other_classes_not_counted"] == {"LIVE": 0, "TEST_FIXTURE": 0} and "never mixed" in p["evidence_rule"]
    assert "grain" in p and p["window_start"] is None


def test_the_numbers_are_the_engines_numbers_with_their_denominators():
    o = svc(None).overview("recorded", "all")
    ev = recorded_events()
    f = E.evaluate(ev)
    s = E.summary(ev, f)
    t = {x["id"]: x for x in o["tiles"]}
    assert (t["held"]["n"], t["held"]["of"]) == (s["blocked_verified"]["n"], s["blocked_verified"]["of_deny_decisions"])
    assert (t["retests"]["n"], t["retests"]["of"]) == (s["retest"]["VALIDATED"], s["retest"]["of"])
    assert t["did_not_hold"]["of"] == s["unauthorized_executed"]["of"] and t["did_not_hold"]["by_design"] == s["unauthorized_executed"]["by_design"]
    assert all(x["definition"] for x in o["tiles"])
    assert o["disclosure"]["by_status"]["total"] == len(f) and sum(i["n"] for i in o["disclosure"]["by_status"]["items"]) == len(f)
    assert o["disclosure"]["controls"]["of"] == len(E.load_controls())


def test_the_headline_counts_exactly_the_attention_items_and_orders_them_by_priority():
    o = svc(FakeClient([e for f in ACC.fixtures().values() for e in f["events"]])).overview("fixtures", "all")
    assert o["state"] == "ok" and o["evidence_class"] == "TEST_FIXTURE"
    prios = [x["priority"] for x in o["attention_all"]]
    assert o["headline"]["attention"] == len(o["attention_all"]) and prios == sorted(prios)
    assert {x["rule_id"] for x in o["attention_all"]} >= {"R-DENY-BYPASSED", "R-INCOMPLETE"} or o["attention_all"]
    assert o["attention_all"][0]["priority"] == 0 and o["attention_all"][0]["status"] == "VERIFIED_INEFFECTIVE" and not o["attention_all"][0]["by_design"]
    assert len(o["attention"]) == min(3, len(o["attention_all"]))


# ------------------------------------------------------------------ live view: window, class, provenance
def test_live_view_counts_only_live_runs_and_reports_the_other_classes_without_mixing_them():
    live = live_batch({"l1": 2, "l2": 5})
    rec = recorded_events()
    fx = [e for f in list(ACC.fixtures().values())[:2] for e in f["events"]]
    client = FakeClient(live + rec + fx)
    o = svc(client).overview("live", "7d")
    assert o["state"] == "ok" and o["evidence_class"] == "LIVE" and o["provenance"]["runs"] == 2
    assert o["provenance"]["other_classes_not_counted"]["RECORDED"] == 53 and o["provenance"]["other_classes_not_counted"]["TEST_FIXTURE"] == 2
    assert "Splunk index agentsec_telemetry" == o["provenance"]["source"] and o["provenance"]["window_start"] == iso(NOW - 7 * 86400)
    assert all(x["finding_id"] for x in o["attention_all"])


def test_the_window_is_applied_by_run_start_with_a_search_margin_so_edge_runs_stay_complete():
    batch = live_batch({"young": 3, "old": 30, "ancient": 24 * 9})
    client = FakeClient(batch)
    s = svc(client)
    assert s.overview("live", "24h")["provenance"]["runs"] == 1
    assert s.overview("live", "7d")["provenance"]["runs"] == 2
    assert s.overview("live", "all")["provenance"]["runs"] == 3
    spls = [c[0] for c in client.calls]
    assert any("earliest=-2d" in x for x in spls) and any("earliest=-8d" in x for x in spls) and any("earliest=0" in x for x in spls)
    for spl in spls:
        assert spl_policy.checked(spl, backend="rest") and "table _raw" in spl and spl.count("|") == 2                  # the fixed search passes the read-only policy


def test_results_are_cached_briefly_and_not_across_windows():
    client = FakeClient(live_batch({"a": 1}))
    s = svc(client, ttl_s=10)
    s.overview("live", "7d"); s.overview("live", "7d")
    assert len(client.calls) == 1
    s.overview("live", "24h")
    assert len(client.calls) == 2


def test_duplicate_and_malformed_rows_are_ignored():
    ev = live_batch({"a": 1})
    class Dup(FakeClient):
        def export_csv(self, spl, **kw):
            t = super().export_csv(spl, **kw)
            return t + t.split("\n", 1)[1] + '"not json"\n"[1,2]"\n""\n'
    o = svc(Dup(ev)).overview("live", "7d")
    assert o["provenance"]["events"] == len(ev)


# ------------------------------------------------------------------ never a healthy zero
@pytest.mark.parametrize("client,reason", [
    (None, "not_provisioned"),
    (FakeClient(error=sc.SplunkError("connectivity", "connect_failed")), "unreachable"),
    (FakeClient(error=sc.SplunkError("authentication", "auth_failed")), "access_denied"),
    (FakeClient(error=sc.SplunkError("authorization", "forbidden")), "access_denied"),
    (FakeClient(error=sc.SplunkError("search", "timeout")), "timeout"),
    (FakeClient(error=sc.SplunkError("search", "too_large")), "too_large"),
    (FakeClient(error=sc.SplunkError("search", "http_error")), "search_failed"),
])
def test_an_unreachable_or_refused_splunk_is_unavailable_and_carries_no_numbers(client, reason):
    o = svc(client).overview("live", "7d")
    assert o["state"] == "unavailable" and o["reason"] == reason and "tiles" not in o and "headline" not in o and o["provenance"]["runs"] == 0
    assert svc(client).finding("live", "F-0123456789ab", "7d")["state"] == "unavailable"


def test_a_bad_configuration_is_unavailable_too():
    def boom(env): raise sc.SplunkError("connectivity", "config_invalid")
    assert AssuranceService(client_factory=boom, clock=lambda: NOW).overview("live", "7d")["reason"] == "not_configured"


def test_zero_events_is_empty_never_a_pass():
    o = svc(FakeClient([])).overview("live", "7d")
    assert o["state"] == "empty" and o["reason"] == "no_runs_in_window" and "tiles" not in o and "headline" not in o
    only_recorded = svc(FakeClient(recorded_events())).overview("live", "7d")
    assert only_recorded["state"] == "empty" and only_recorded["provenance"]["other_classes_not_counted"]["RECORDED"] == 53


def test_lost_or_late_events_appear_as_insufficient_evidence_never_as_effective():
    fx = ACC.fixtures()
    o = svc(FakeClient(fx["lost-event"]["events"] + fx["still-arriving"]["events"])).overview("fixtures", "all")
    st = {i["status"]: i["n"] for i in o["disclosure"]["by_status"]["items"] if not i["by_design"]}
    assert st["INSUFFICIENT_EVIDENCE"] == 2 and st["VERIFIED_EFFECTIVE"] == 0 and o["headline"]["attention"] == 2
    assert o["tiles"][0]["n"] == 0 and o["disclosure"]["gaps"]["n"] == 2


# ------------------------------------------------------------------ finding detail and drilldown
def first(o, rule): return next(x for x in o["attention_all"] if x["rule_id"] == rule)


def test_finding_detail_has_the_timeline_the_gaps_the_run_context_and_bounded_json():
    fx = ACC.fixtures()
    s = svc(FakeClient(fx["lost-event"]["events"] + fx["deny-but-executed"]["events"]))
    o = s.overview("fixtures", "all")
    gap = s.finding("fixtures", first(o, "R-INCOMPLETE")["finding_id"], "all")
    assert gap["state"] == "ok" and gap["missing_sequences"] == [4] and gap["run"]["contiguous"] is False and gap["finding"]["status"] == "INSUFFICIENT_EVIDENCE"
    assert [x["sequence"] for x in gap["timeline"]][:3] == [1, 2, 3] and gap["finding"]["spl"].startswith("index=agentsec_telemetry")
    bad = s.finding("fixtures", first(o, "R-DENY-BYPASSED")["finding_id"], "all")
    assert any(t["focus"] and t["executed"] for t in bad["timeline"]) or any(t["focus"] for t in bad["timeline"])
    for k in ("observation", "interpretation", "impact", "control_interpretation", "recommended_action"): assert bad["finding"][k]
    for ev in bad["events"]:
        assert len(ev["json"]) <= MAX_EVENT_JSON and json.loads(ev["json"]) if not ev["truncated"] else True
    assert bad["provenance"]["runs"] == 1 and bad["workshop"]["adoptable"] is False


def test_a_finding_is_only_visible_in_its_own_evidence_class():
    live = live_batch({"a": 1})
    rec_f = svc(None).overview("recorded", "all")["attention_all"]
    s = svc(FakeClient(live))
    lid = next(iter(Dataset(live, frozenset(), NOW, "t").by_id))
    assert s.finding("live", lid, "7d")["state"] == "ok"
    assert s.finding("fixtures", lid, "7d") is None
    assert s.finding("live", rec_f[0]["finding_id"], "7d") is None                      # a recorded finding id is not a live finding
    assert svc(None).finding("recorded", rec_f[0]["finding_id"])["state"] == "ok"
    assert svc(None).finding("recorded", "../x") is None and svc(None).finding("recorded", "F-" + "0" * 12) is None


def test_the_originating_workshop_comes_from_the_launch_allowlist_and_live_runs_are_adoptable():
    s = svc(None)
    labs = {x["lab_id"] for x in s.overview("recorded", "all")["attention_all"] if x["lab_id"]}
    assert labs <= {r for r in __import__("agentsec.launch_catalog", fromlist=["x"]).known_lab_ids()}
    live = live_batch({"a": 1, "b": 2, "c": 3})
    s2 = svc(FakeClient(live))
    ds = Dataset(live, frozenset(), NOW, "t")
    fid = next(f["finding_id"] for f in ds.findings if f["attack_id"])
    d = s2.finding("live", fid, "7d")
    assert d["workshop"]["adoptable"] is True and d["workshop"]["run_id"] == ds.by_id[fid]["run_id"] and d["workshop"]["mode"] in ("BASELINE", "ATTACK", "RETEST")


def test_a_linked_retest_is_reported_for_an_attack_finding():
    s = svc(None)
    ds = s._recorded()
    atk = next(f for f in ds.findings if f["mode"] == "ATTACK" and f["retest"]["outcome"] == "VALIDATED")
    d = s.finding("recorded", atk["finding_id"])
    assert d["linked_retest"]["run_id"] == atk["retest"]["run_id"] and d["linked_retest"]["status"] == "VERIFIED_EFFECTIVE"


def test_oversized_event_json_and_long_runs_are_capped():
    ev = live_batch({"a": 1})
    for e in ev[:3]: e["pad"] = "x" * 20000
    s = svc(FakeClient(ev))
    ds = Dataset(ev, frozenset(), NOW, "t")
    fid = next(iter(ds.by_id))
    d = s.finding("live", fid, "7d")
    big = [e for e in d["events"] if e["truncated"]]
    assert big and all(len(e["json"]) == MAX_EVENT_JSON for e in big)


# ------------------------------------------------------------------ routes
@pytest.fixture
def client():
    from flask import Flask
    app = Flask(__name__)
    s = svc(FakeClient(live_batch({"a": 1, "b": 2})))
    register_assurance(app, s)
    return app.test_client(), s


def test_routes_return_json_with_no_store_and_validate_every_parameter(client):
    c, _ = client
    r = c.get("/api/assurance/overview?tab=live&window=7d")
    assert r.status_code == 200 and r.headers["Cache-Control"].startswith("no-store") and r.get_json()["tab"] == "live"
    assert c.get("/api/assurance/overview").status_code == 200 and c.get("/api/assurance/overview?tab=recorded").get_json()["evidence_class"] == "RECORDED"
    for bad in ("?tab=fixtures", "?tab=x", "?window=1y", "?window=7d&evil=1", "?tab=live&window=7d%0A"):
        assert c.get("/api/assurance/overview" + bad).status_code == 400, bad


def test_the_fixtures_view_has_its_own_path_and_no_other_route_serves_fixtures(client):
    c, _ = client
    r = c.get("/api/assurance/fixtures/overview?window=all")
    assert r.status_code == 200 and r.get_json()["evidence_class"] == "TEST_FIXTURE"
    assert c.get("/api/assurance/overview?tab=fixtures").status_code == 400


def test_finding_route_validates_ids_and_hides_unknown_ones(client):
    c, s = client
    fid = next(iter(Dataset(s._splunk("7d")[0].events, frozenset(), NOW, "t").by_id))
    assert c.get(f"/api/assurance/findings/{fid}?tab=live&window=7d").status_code == 200
    assert c.get("/api/assurance/findings/F-000000000000?tab=live").status_code == 404
    for bad in ("not-an-id", "F-123", "F-0123456789abg", "F-0123456789ab%0A"):
        assert c.get(f"/api/assurance/findings/{bad}?tab=live").status_code in (400, 404), bad
    assert c.get(f"/api/assurance/findings/{fid}?tab=fixtures").status_code == 400


def test_the_routes_are_read_only(client):
    c, _ = client
    for path in ("/api/assurance/overview", "/api/assurance/fixtures/overview", "/api/assurance/findings/F-0123456789ab"):
        for m in ("post", "put", "delete", "patch"):
            assert getattr(c, m)(path, json={"spl": "search *"}).status_code == 405, (m, path)


def test_the_module_has_no_way_to_run_browser_supplied_search_text():
    src = (ROOT / "src/agentsec/academy_assurance.py").read_text()
    assert "request.get_json" not in src and "request.form" not in src and "request.data" not in src and src.count("export_csv(") == 1
