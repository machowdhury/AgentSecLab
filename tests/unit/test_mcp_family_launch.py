"""LAB-MCP-003/004/005/CATALOG launch through the same allowlisted /api/launch path as LAB-MCP-001 (in-process AcmeBank, no Docker, no model)."""
import pytest

from tests.unit.test_phase14b_attack_service import _wired_app

CASES = {  # lab -> (attack specimen, attacked decision, defended decision/reason evidence in the hops)
    "LAB-MCP-003": ("MCP-003", "MCP-003-BASELINE"),
    "LAB-MCP-004": ("MCP-004", "MCP-004-BASELINE"),
    "LAB-MCP-005": ("MCP-005", "MCP-005-BASELINE"),
    "LAB-MCP-CATALOG": ("MCP-CATALOG-001", "MCP-CATALOG-001-BASELINE"),
    "LAB-MCP-006": ("MCP-006", "MCP-006-BASELINE"),
}


def launch(client, lab, specimen, mode):
    r = client.post("/api/launch", json={"lab_id": lab, "specimen_id": specimen, "mode": mode, "execution": "live"})
    assert r.status_code == 200, r.get_json()
    return r.get_json()


@pytest.mark.parametrize("lab", sorted(CASES))
def test_each_lab_runs_baseline_attack_and_retest_with_fresh_run_ids(acme_client, counting_llm, lab):
    attack_spec, base_spec = CASES[lab]
    client, _ = _wired_app(acme_client)
    base, attack, retest = (launch(client, lab, base_spec, "BASELINE"), launch(client, lab, attack_spec, "ATTACK"), launch(client, lab, attack_spec, "RETEST"))
    assert len({base["run_id"], attack["run_id"], retest["run_id"]}) == 3
    assert (base["profile"], attack["profile"], retest["profile"]) == ("defended", "vulnerable", "defended")
    assert attack["intentionally_vulnerable"] is True and not base.get("intentionally_vulnerable") and not retest.get("intentionally_vulnerable")
    assert all(x["lab_id"] == lab and x["runtime_status"] == "COMPLETED" for x in (base, attack, retest))
    assert counting_llm.calls == []                      # MCP labs call no language model
    assert all(x["evidence_state"] == "WAITING_FOR_EVIDENCE" and x["splunk_verified"] is False for x in (base, attack, retest))


def hops(b):
    return {h["hop.index"]: h for h in b["runtime"]["hops"]}


def test_mcp_003_and_004_defended_retest_denies_what_the_vulnerable_attack_allowed(acme_client, counting_llm):
    client, _ = _wired_app(acme_client)
    for lab, spec, reason in (("LAB-MCP-003", "MCP-003", "scope_not_granted"), ("LAB-MCP-004", "MCP-004", "resource_not_granted")):
        a, r = launch(client, lab, spec, "ATTACK"), launch(client, lab, spec, "RETEST")
        ha, hr = hops(a)[max(hops(a))], hops(r)[max(hops(r))]
        assert ha["control.decision"] == "ALLOW" and ha["operation.executed"] is True      # labelled fail-open on the vulnerable profile
        assert hr["control.decision"] == "DENY" and hr["control.reason"] == reason and hr["operation.executed"] is False
        assert a["input_fingerprint"] == r["input_fingerprint"]                           # same request, only the server-owned profile differs


def test_the_browser_cannot_choose_the_profile_or_an_unlisted_specimen(acme_client, counting_llm):
    client, _ = _wired_app(acme_client)
    assert client.post("/api/launch", json={"lab_id": "LAB-MCP-003", "specimen_id": "MCP-003", "mode": "ATTACK", "execution": "live", "profile": "defended"}).status_code == 400
    assert client.post("/api/launch", json={"lab_id": "LAB-MCP-003", "specimen_id": "MCP-004", "mode": "ATTACK", "execution": "live"}).status_code in (400, 404)


def follow_on(b):
    return [(h["tool.name"], h["control.decision"], h["control.reason"], h["operation.executed"]) for h in b["runtime"]["hops"]][1:]


@pytest.mark.parametrize("lab,spec,base,reason", [("LAB-MCP-005", "MCP-005", "MCP-005-BASELINE", "result_derived_grant"), ("LAB-MCP-CATALOG", "MCP-CATALOG-001", "MCP-CATALOG-001-BASELINE", "metadata_derived_authority")])
def test_result_and_metadata_trust_labs_show_the_follow_on_grant_only_on_the_vulnerable_profile(acme_client, counting_llm, lab, spec, base, reason):
    client, _ = _wired_app(acme_client)
    assert follow_on(launch(client, lab, base, "BASELINE")) == []
    assert follow_on(launch(client, lab, spec, "ATTACK")) == [("lookup_customer_tier", "ALLOW", f"vulnerable_profile_fail_open:{reason}", True)]
    assert follow_on(launch(client, lab, spec, "RETEST")) == [("lookup_customer_tier", "DENY", "tool_not_granted", False)]


def test_every_hunt_named_for_a_launchable_lab_exists_as_a_committed_search_and_the_starter_search_names_the_run_id():
    from pathlib import Path
    from agentsec.search_handoff import HUNTS_BY_LAB, handoff_doc
    root = Path(__file__).resolve().parents[2] / "learning" / "level_1"
    have = {p.stem for p in root.glob("*/searches/*.spl")}
    run = "0e6ca4b1-2e9b-4a8e-9a9b-6a3c2f0c9d11"
    for lab in CASES:
        assert set(HUNTS_BY_LAB[lab]) <= have, (lab, set(HUNTS_BY_LAB[lab]) - have)
        assert f'"agentsec.run.id"="{run}"' in handoff_doc(run, lab_id=lab)["starter_spl"]


def test_mcp_006_confused_deputy_launch_shows_ambient_authority_only_on_the_vulnerable_profile(acme_client, counting_llm):
    client, _ = _wired_app(acme_client)
    base, attack, retest = (launch(client, "LAB-MCP-006", "MCP-006-BASELINE", "BASELINE"), launch(client, "LAB-MCP-006", "MCP-006", "ATTACK"), launch(client, "LAB-MCP-006", "MCP-006", "RETEST"))
    assert attack["runtime"]["lookup_customer_tier_handler_count"] == 1 and retest["runtime"]["lookup_customer_tier_handler_count"] == 0
    assert base["runtime"]["lookup_policy_handler_count"] == 1 and base["runtime"]["lookup_customer_tier_handler_count"] == 0
    assert "ambient_deputy_authority" in str([h["control.reason"] for h in attack["runtime"]["hops"]])
    assert any(h["control.decision"] == "DENY" and h["control.reason"] == "delegated_authority_not_granted" for h in retest["runtime"]["hops"])
    assert attack["input_fingerprint"] == retest["input_fingerprint"]


def test_the_delegate_route_refuses_a_request_without_a_closed_experiment(acme_client):
    r = acme_client.post("/mcp/delegate", json={"tool": "lookup_customer_tier", "requested_scope": "customer:read", "arguments": {"customer_id": "cust-001"}, "user_id": "applicant-web"})
    assert r.status_code == 400 and r.get_json()["error"] == "experiment_required"
    r = acme_client.post("/mcp/delegate", json={"tool": "lookup_policy", "requested_scope": "policy:read", "arguments": {"policy_id": "lending-basics"}, "user_id": "applicant-web", "experiment_id": "LAB-MCP-001:BASELINE"})
    assert r.status_code == 400


def test_a_delegate_experiment_id_is_refused_on_the_invoke_route(acme_client):
    r = acme_client.post("/mcp/invoke", json={"tool": "lookup_policy", "requested_scope": "policy:read", "arguments": {"policy_id": "lending-basics"}, "user_id": "applicant-web", "experiment_id": "LAB-MCP-006:BASELINE"})
    assert r.status_code == 400 and "unknown_experiment" in str(r.get_json())
