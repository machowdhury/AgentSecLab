"""Confused Deputy Relay contract: two server-sequenced runs verified from recorded delegation/authorization events; defended mode denies."""

from __future__ import annotations

import copy

import pytest

from agentsec.ctf.ch_confused_deputy import SCENARIO
from tests.ctf_support import make_service

CID = "confused-deputy-relay"


@pytest.fixture
def svc(tmp_path):
    return make_service(tmp_path, {CID: SCENARIO})[0]


def play(svc, posture="baseline", second=None):
    aid = svc.start(CID)[1]["attempt_id"]
    assert svc.run(aid, {"posture": posture, "step": "claim"})[0] == 200
    assert svc.run(aid, {"posture": second or posture, "step": "relay"})[0] == 200
    return aid, svc.verify(aid)[1]


def test_registry_entry_is_labelled_not_a2a():
    c = SCENARIO.challenge
    assert c.difficulty == "Advanced" and c.max_steps == 2 and "NOT A2A" in c.simulation_note and c.simulation == "SIMULATED"
    assert "not one cryptographic chain" in c.simulation_note and "NOT A2A" in SCENARIO.materials()["model"]


def test_baseline_chain_success_from_recorded_events(svc):
    aid, body = play(svc)
    assert body["state"] == "VERIFIED" and all(c["passed"] for c in body["verdict"]["checks"]) and len(body["runs"]) == 2
    assert [r["step"] for r in body["runs"]] == ["claim", "relay"] and len(body["receipt"]["run_ids"]) == 2
    relay = svc._live[aid][body["runs"][1]["run_id"]]["events"]
    assert any(e.get("agentsec.control.reason") == "vulnerable_profile_fail_open:ambient_deputy_authority" for e in relay)
    assert svc.redeem(aid, body["receipt"])[1]["awarded"] == 300
    assert [s["run_id"] for s in body["splunk"]["runs"]] == body["receipt"]["run_ids"]


def test_defended_mode_denies_at_both_steps(svc):
    aid, body = play(svc, "hardened")
    assert body["state"] == "FAILED" and body["receipt"] is None
    claim = svc._live[aid][body["runs"][0]["run_id"]]["events"]
    relay = svc._live[aid][body["runs"][1]["run_id"]]["events"]
    assert any(e.get("agentsec.control.decision") == "DENY" and e.get("agentsec.control.reason") == "tool_not_granted" for e in claim)
    assert any(e.get("agentsec.control.id") == "CTRL-DELEGATION-001" and e.get("agentsec.control.decision") == "DENY"
               and e.get("agentsec.control.reason") == "delegated_authority_not_granted" for e in relay)
    assert not any(e.get("event.name") == "agentsec.mcp.started" and e.get("gen_ai.tool.name") == "lookup_customer_tier" for e in claim + relay)


def test_mixed_postures_do_not_score(svc):
    assert play(svc, "baseline", "hardened")[1]["state"] == "FAILED"
    assert play(svc, "hardened", "baseline")[1]["state"] == "FAILED"


def test_steps_must_be_run_in_order_once_and_verification_waits_for_both(svc):
    aid = svc.start(CID)[1]["attempt_id"]
    assert svc.run(aid, {"posture": "baseline", "step": "relay"})[1] == {"error": "wrong_step_order"}
    assert svc.run(aid, {"posture": "baseline", "step": "claim"})[0] == 200
    assert svc.run(aid, {"posture": "baseline", "step": "claim"})[1] == {"error": "wrong_step_order"}
    assert svc.verify(aid)[1]["error"] == "steps_incomplete"
    svc.run(aid, {"posture": "baseline", "step": "relay"})
    assert svc.run(aid, {"posture": "baseline", "step": "relay"})[1]["error"] == "all_steps_done"
    assert svc.verify(aid)[1]["state"] == "VERIFIED"


@pytest.mark.parametrize("params", [{"posture": "baseline", "step": "both"}, {"posture": "baseline"}, {"step": "claim"},
                                    {"posture": "baseline", "step": "claim", "principal": "admin"},
                                    {"posture": "baseline", "step": "claim", "delegation_claim": {"claimed_scope": "x"}}, {"posture": 1, "step": "claim"}])
def test_the_client_cannot_supply_principals_claims_or_grants(svc, params):
    aid = svc.start(CID)[1]["attempt_id"]
    assert svc.run(aid, params)[0] == 400


def test_claim_run_alone_or_swapped_runs_do_not_verify(svc):
    aid, _ = play(svc)
    bs = [copy.deepcopy(b) for b in svc._live[aid].values()]
    assert SCENARIO.verify(bs).ok
    assert not SCENARIO.verify(bs[::-1]).ok                                       # the steps are not interchangeable
    assert not SCENARIO.verify([bs[0], bs[0]]).ok
    no_exec = copy.deepcopy(bs)
    no_exec[1]["events"] = [e for e in no_exec[1]["events"] if e.get("event.name") != "agentsec.mcp.started"]
    assert not SCENARIO.verify(no_exec).ok                                        # an ALLOW decision without execution is not success
    wrong_agent = copy.deepcopy(bs)
    for e in wrong_agent[1]["events"]:
        if e.get("agentsec.control.id") == "CTRL-DELEGATION-001":
            e["gen_ai.agent.id"] = "someone-else"
    assert not SCENARIO.verify(wrong_agent).ok


def test_run_isolation_and_reset_midway(svc):
    a = svc.start(CID)[1]["attempt_id"]
    svc.run(a, {"posture": "baseline", "step": "claim"})
    rid = svc.get(a)[1]["runs"][0]["run_id"]
    svc.reset(a)
    assert a not in svc._live
    b = svc.start(CID)[1]["attempt_id"]
    assert svc.get(b)[1]["runs"] == []                                            # a fresh attempt starts from step 1 with no carried state
    svc.run(b, {"posture": "baseline", "step": "claim"})
    svc.run(b, {"posture": "baseline", "step": "relay"})
    assert svc.verify(b, [rid])[1]["error"] == "run_not_owned"                     # a's claim run cannot be presented in b
    assert svc.verify(b)[1]["state"] == "VERIFIED"
