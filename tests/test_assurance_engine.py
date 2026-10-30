"""The assurance rules, applied to the committed telemetry and to deliberately broken copies of it: a control is never reported effective from missing,
partial or merely suggestive evidence, and nothing is linked by timestamp."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from agentsec.assurance import engine as E

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "learning/level_1/LAB-MCP-003/specimens"
ATTACK, RETEST, BASELINE = "b466ad12-72ec-44b7-be28-aacfaf2c25b1", "f638fd4f-1c4f-4ab6-8d42-4d03a4f3afd5", "5b089682-1d5a-49a7-ac43-967265fd6bc6"


def run(rid):
    return E.read_events(SPEC / f"{rid}.jsonl")


def one(events, **kw):
    return E.evaluate(events, recorded=frozenset(), **kw)


def all_specimens():
    seen = {}
    for f in (ROOT / "learning/level_1").glob("*/specimens/*.jsonl"):
        for e in E.read_events(f):
            seen[(e["agentsec.run.id"], e["agentsec.sequence"])] = e
    return list(seen.values())


def test_the_attack_and_retest_of_one_technique_give_the_expected_statuses_and_link_by_identity():
    f = one(run(ATTACK) + run(RETEST) + run(BASELINE))
    a = next(x for x in f if x["mode"] == "ATTACK")
    r = next(x for x in f if x["mode"] == "RETEST")
    assert (a["status"], a["rule_id"], a["by_design"]) == ("VERIFIED_INEFFECTIVE", "R-FAILOPEN-EXECUTED", True)
    assert (r["status"], r["rule_id"], r["confidence"]) == ("VERIFIED_EFFECTIVE", "R-DENY-HELD", "Verified")
    assert a["retest"] == {"outcome": "VALIDATED", "run_id": RETEST}
    assert not [x for x in f if x["mode"] == "BASELINE"], "an authorized baseline grant is activity, not a finding"
    assert r["executed_in_hop"] is False and a["executed_in_hop"] is True
    assert "does not establish" in r["control_interpretation"] and "vulnerable profile" in a["interpretation"]


def test_missing_events_never_become_a_pass():
    assert one([]) == []                                                    # no telemetry, no finding, and therefore no "effective"
    ev = run(RETEST)
    gap = [e for e in ev if e["agentsec.sequence"] != 4]                    # a lost event
    assert {x["status"] for x in one(gap)} == {"INSUFFICIENT_EVIDENCE"}
    no_end = [e for e in ev if e["event.name"] != "agentsec.run.completed"]  # still being ingested
    assert {x["status"] for x in one(no_end)} == {"INSUFFICIENT_EVIDENCE"}
    no_hop = copy.deepcopy(ev)
    for e in no_hop:
        e.pop("agentsec.hop.index", None)
    assert {x["status"] for x in one(no_hop)} == {"INSUFFICIENT_EVIDENCE"}


def test_a_deny_that_still_executed_is_verified_ineffective():
    ev = run(RETEST)
    hop = next(e for e in ev if e["event.name"] == "agentsec.control.decision")["agentsec.hop.index"]
    leak = copy.deepcopy(next(e for e in run(ATTACK) if e["event.name"] == "agentsec.mcp.started"))
    leak.update({"agentsec.run.id": RETEST, "agentsec.hop.index": hop, "agentsec.sequence": 4})
    bumped = [dict(e, **{"agentsec.sequence": e["agentsec.sequence"] + 1}) if e["agentsec.sequence"] >= 4 else e for e in ev] + [leak]
    f = one(bumped)
    assert [x["rule_id"] for x in f] == ["R-DENY-BYPASSED"] and f[0]["status"] == "VERIFIED_INEFFECTIVE" and not f[0]["by_design"]


def test_an_ineffective_control_in_the_defended_retest_is_reported_not_hidden():
    """A defended RETEST that executes with no enforcing denial (the control stopped working)."""
    ev = copy.deepcopy(run(ATTACK))
    for e in ev:
        e["agentsec.run.id"] = "deadbeef-0000-4000-8000-000000000001"
        e["agentsec.testbed.mode"], e["agentsec.security.profile"] = "RETEST", "defended"
        if e["event.name"] == "agentsec.control.decision":
            e["agentsec.control.reason"] = "tool_granted"                    # an ordinary ALLOW, no fail-open reason
    f = one(ev)
    assert [(x["rule_id"], x["status"]) for x in f] == [("RR-RETEST-NOT-PREVENTED", "VERIFIED_INEFFECTIVE")]


def test_an_observe_control_and_a_model_statement_are_never_verified_effective():
    for f in one(all_specimens()):
        if f["decision"] == "OBSERVE":
            assert f["status"] == "FINDING_OBSERVED" and f["confidence"] == "Inferred"
    ev = copy.deepcopy(run(ATTACK))
    for e in ev:
        if e["event.name"] == "agentsec.mcp.started":
            e["agentsec.operation.executed"] = False                         # attempted, but the handler did not run
    assert one(ev)[0]["status"] == "FINDING_OBSERVED"                        # a stated intention or an attempt is not an execution


def test_duplicates_are_counted_once_and_timestamps_decide_nothing():
    ev = run(ATTACK) + run(ATTACK)                                          # every event indexed twice
    assert len(E.group_runs(ev)[ATTACK]["events"]) == 7 and E.group_runs(ev)[ATTACK]["duplicates"] == 7
    assert len(one(ev)) == len(one(run(ATTACK)))
    base = one(run(ATTACK) + run(RETEST))
    shuffled = copy.deepcopy(run(ATTACK) + run(RETEST))
    for i, e in enumerate(shuffled):
        e["timestamp"] = f"2026-01-0{1 + i % 8}T00:00:00Z"
    again = one(shuffled)
    assert [(x["finding_id"], x["status"], x["retest"]["outcome"]) for x in base] == [(x["finding_id"], x["status"], x["retest"]["outcome"]) for x in again]


def test_retest_link_requires_the_same_attack_id_and_control_id():
    other = copy.deepcopy(run(RETEST))
    for e in other:
        if "agentsec.attack.id" in e:
            e["agentsec.attack.id"] = "MCP-004"
    a = next(x for x in one(run(ATTACK) + other) if x["mode"] == "ATTACK")
    assert a["retest"]["outcome"] == "NO_RETEST"


def test_recorded_runs_are_told_apart_from_live_runs_only_by_the_committed_list():
    f = E.evaluate(run(ATTACK), recorded=E.recorded_run_ids())
    assert f[0]["evidence_class"] == "RECORDED" and one(run(ATTACK))[0]["evidence_class"] == "LIVE"
    assert all(e["agentsec.execution.mode"] == "LIVE" for e in run(ATTACK)), "the telemetry alone says LIVE for both"


def test_findings_carry_every_field_the_dashboard_must_show_and_no_composite_score():
    f = one(run(ATTACK) + run(RETEST))
    need = {"observation", "interpretation", "impact", "evidence_refs", "spl", "control_interpretation", "confidence", "recommended_action", "retest", "status_label", "control_id", "workshops", "run_id"}
    for x in f:
        assert need <= set(x) and x["spl"].startswith("index=agentsec_telemetry") and x["run_id"] in x["spl"]
        assert x["evidence_refs"], "a finding points at its raw events"
    assert not any("score" in k or "percent" in k for k in f[0]) and "no_composite_score" in E.load_rules()


def test_the_summary_states_numerators_and_denominators_for_the_committed_telemetry():
    ev = all_specimens()
    s = E.summary(ev, one(ev))
    assert s["complete_runs"] == {"n": 53, "of": 53}
    assert s["unauthorized_executed"]["by_design"] == s["unauthorized_executed"]["n"] > 0
    assert s["blocked_verified"]["n"] <= s["blocked_verified"]["of_deny_decisions"]
    assert s["retest"]["VALIDATED"] + s["retest"]["NOT_VALIDATED"] + s["retest"]["NO_RETEST"] == s["retest"]["of"]
    assert {m["id"] for m in E.load_rules()["metrics"]} >= {"M-UNAUTH-EXECUTED", "M-BLOCKED", "M-RETEST-EFFECTIVENESS", "M-EVIDENCE-COMPLETENESS", "M-UNTESTED-CONTROLS", "M-DECISION-LATENCY"}
    for m in E.load_rules()["metrics"]:
        assert m["numerator"] and m["denominator"] and m["source"], m["id"]


def test_every_control_in_the_committed_telemetry_is_in_the_catalogue_and_has_real_boundary_values():
    cat = E.load_controls()
    seen = {}
    for e in all_specimens():
        if e.get("event.name") == "agentsec.control.decision":
            seen.setdefault(e["agentsec.control.id"], set()).add(e["agentsec.trust_boundary"])
    assert set(seen) <= set(cat), set(seen) - set(cat)
    for cid, bounds in seen.items():
        assert bounds <= set(cat[cid]["boundary_event_values"]), (cid, bounds)


def test_negative_test_fixtures_are_marked_and_the_rules_never_report_success_for_them():
    import importlib.util
    spec = importlib.util.spec_from_file_location("assurance_acceptance", ROOT / "scripts/assurance_acceptance.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    fx = mod.fixtures()
    assert set(fx) == {"lost-event", "still-arriving", "control-stopped-working", "deny-but-executed"}
    for name, f in fx.items():
        got = E.evaluate(f["events"], recorded=frozenset())
        assert [(x["rule_id"], x["status"]) for x in got] == [tuple(x) for x in f["expect"]], name
        assert {x["evidence_class"] for x in got} == {"TEST_FIXTURE"}, "fixtures are never presented as live or recorded evidence"
        assert not any(x["status"] == "VERIFIED_EFFECTIVE" for x in got), "no negative test may read as success"
        assert all(e["agentsec.lab.id"] == "assurance-test-fixture" for e in f["events"])


def test_review_fixes_unknown_decisions_are_shown_and_retests_never_cross_evidence_classes():
    ev = copy.deepcopy(run(RETEST))
    for e in ev:
        if e["event.name"] == "agentsec.control.decision":
            e["agentsec.control.decision"] = "ALLOW_WITH_WARNING"
    f = one(ev)
    assert [(x["rule_id"], x["status"]) for x in f] == [("R-UNCLASSIFIED", "INSUFFICIENT_EVIDENCE")], "an unknown decision is shown, never dropped"
    ev2 = copy.deepcopy(run(RETEST))
    for e in ev2:
        e.pop("agentsec.control.decision", None) if e["event.name"] == "agentsec.control.decision" else None
    assert one(ev2)[0]["status"] == "INSUFFICIENT_EVIDENCE"
    # a RECORDED retest must not validate a LIVE attack, and an attack with no attack id has no retest
    live_attack = copy.deepcopy(run(ATTACK))
    for e in live_attack:
        e["agentsec.run.id"] = "11111111-1111-4111-8111-111111111111"
    mixed = E.evaluate(live_attack + run(RETEST), recorded=frozenset({RETEST}))
    assert next(x for x in mixed if x["mode"] == "ATTACK")["retest"]["outcome"] == "NO_RETEST"
    no_id = copy.deepcopy(run(ATTACK))
    for e in no_id:
        e.pop("agentsec.attack.id", None)
    assert next(x for x in one(no_id + run(RETEST)) if x["mode"] == "ATTACK")["retest"]["outcome"] == "NO_RETEST"


def test_the_unauthorized_execution_metric_keeps_run_level_failures_out_of_the_hop_level_ratio():
    ev = copy.deepcopy(run(ATTACK))
    for e in ev:
        e["agentsec.run.id"] = "deadbeef-0000-4000-8000-000000000002"
        e["agentsec.testbed.mode"], e["agentsec.security.profile"] = "RETEST", "defended"
        if e["event.name"] == "agentsec.control.decision":
            e["agentsec.control.reason"] = "tool_granted"
    f = one(ev)
    s = E.summary(ev, f)
    assert s["unauthorized_executed"]["n"] == 0 and s["unauthorized_executed"]["of"] == 0 and s["unauthorized_executed"]["run_level_retest_failures"] == 1


def test_a_fixture_run_has_one_mode_and_one_profile_and_the_spl_takes_them_from_run_started():
    import importlib.util
    spec = importlib.util.spec_from_file_location("assurance_acceptance", ROOT / "scripts/assurance_acceptance.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    for name, f in mod.fixtures().items():
        assert len({e["agentsec.testbed.mode"] for e in f["events"]}) == 1 and len({e["agentsec.security.profile"] for e in f["events"]}) == 1, name
    units = (ROOT / "splunk_app/agentsec/default/macros.conf").read_text(encoding="utf-8")
    assert 'if(ev="agentsec.run.started",mode,null())' in units and "coalesce(mvindex(start_mode,0),mvindex(all_mode,0))" in units, "run mode comes from run.started, like the reference evaluator"
