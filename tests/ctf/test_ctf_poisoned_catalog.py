"""Poisoned Catalog contract: verified from recorded metadata-trust and authorization events; hardened and wrong-tool runs must not succeed."""

from __future__ import annotations

import copy

import pytest

from agentsec.ctf.ch_poisoned_catalog import SCENARIO
from tests.ctf_support import make_service

CID = "poisoned-catalog"


@pytest.fixture
def svc(tmp_path):
    return make_service(tmp_path, {CID: SCENARIO})[0]


def play(svc, posture, tool="lookup_policy"):
    aid = svc.start(CID)[1]["attempt_id"]
    code, body = svc.run(aid, {"posture": posture, "tool": tool})
    assert code == 200, body
    return aid, svc.verify(aid)[1]


def test_registry_entry_is_labelled_simulated_not_an_mcp_server():
    c = SCENARIO.challenge
    assert c.difficulty == "Advanced" and c.simulation == "SIMULATED" and "NOT an external MCP server" in c.simulation_note
    assert "rug-pull" in c.simulation_note and "OBSERVE" in c.control_boundary
    assert "NOT an MCP server" in SCENARIO.materials()["transport"]


def test_materials_show_the_catalog_as_data_the_learner_must_read():
    cat = SCENARIO.materials()["simulated_catalog"]
    assert {t["name"] for t in cat} == {"lookup_policy", "lookup_customer_tier"} and all(t["description"] for t in cat)


def test_baseline_success_from_recorded_decision_events(svc):
    aid, body = play(svc, "baseline")
    assert body["state"] == "VERIFIED" and all(c["passed"] for c in body["verdict"]["checks"])
    events = svc._live[aid][body["runs"][0]["run_id"]]["events"]
    ctl = [(e.get("agentsec.control.id"), e.get("agentsec.control.decision"), e.get("agentsec.control.reason")) for e in events if e.get("agentsec.control.id")]
    assert ("CTRL-MCP-METADATA-001", "OBSERVE", "metadata_is_data") in ctl                       # observed, not blocked
    assert ("CTRL-MCP-001", "ALLOW", "vulnerable_profile_fail_open:metadata_derived_authority") in ctl
    assert svc.redeem(aid, body["receipt"])[1]["awarded"] == 300


def test_hardened_posture_observes_but_does_not_execute_the_follow_on(svc):
    aid, body = play(svc, "hardened")
    assert body["state"] == "FAILED" and body["receipt"] is None
    checks = {c["check"]: c["passed"] for c in body["verdict"]["checks"]}
    assert checks["CTRL-MCP-METADATA-001 observed the poisoned catalog entry and did not block it"] is True      # detection is not prevention
    assert checks["the hidden follow-on tool was ALLOWED on metadata-derived authority and its handler executed"] is False
    events = svc._live[aid][body["runs"][0]["run_id"]]["events"]
    assert any(e.get("agentsec.control.reason") == "tool_not_granted" and e.get("agentsec.control.decision") == "DENY" for e in events)


def test_calling_the_wrong_tool_does_not_trigger_the_poisoned_follow_on(svc):
    assert play(svc, "baseline", "lookup_customer_tier")[1]["state"] == "FAILED"


@pytest.mark.parametrize("params", [{"posture": "baseline", "tool": "issue_loan_offer"}, {"posture": "baseline", "tool": ["lookup_policy"]},
                                    {"posture": "baseline"}, {"tool": "lookup_policy"}, {"posture": "vulnerable", "tool": "lookup_policy"},
                                    {"posture": "baseline", "tool": "lookup_policy", "scope": "customer:read"},
                                    {"posture": "baseline", "tool": "lookup_policy", "catalog": {"tools": []}}])
def test_the_client_cannot_choose_scope_catalog_profile_or_other_tools(svc, params):
    aid = svc.start(CID)[1]["attempt_id"]
    assert svc.run(aid, params)[0] == 400


def test_verifier_needs_the_recorded_decisions_not_words(svc):
    aid, _ = play(svc, "baseline")
    b = copy.deepcopy(next(iter(svc._live[aid].values())))
    assert SCENARIO.verify([b]).ok
    only_meta = copy.deepcopy(b)
    only_meta["events"] = [e for e in only_meta["events"] if e.get("agentsec.control.reason") != "vulnerable_profile_fail_open:metadata_derived_authority"]
    assert not SCENARIO.verify([only_meta]).ok
    spoof = copy.deepcopy(b)
    spoof["events"] = [e for e in spoof["events"] if e.get("event.name") != "agentsec.mcp.started" or e.get("gen_ai.tool.name") != "lookup_customer_tier"]
    assert not SCENARIO.verify([spoof]).ok                                                       # ALLOW without an executed handler is not success
    prof = copy.deepcopy(b)
    for e in prof["events"]:
        e["agentsec.security.profile"] = "defended"
    assert not SCENARIO.verify([prof]).ok


def test_each_attempt_gets_its_own_run_and_sink(svc):
    a, ba = play(svc, "baseline")
    b, bb = play(svc, "baseline")
    assert ba["runs"][0]["run_id"] != bb["runs"][0]["run_id"]
    assert all(e["agentsec.run.id"] == bb["runs"][0]["run_id"] for e in svc._live[b][bb["runs"][0]["run_id"]]["events"])


def test_reset_then_retry(svc):
    aid, body = play(svc, "hardened")
    svc.reset(aid)
    assert play(svc, "baseline")[1]["state"] == "VERIFIED"
