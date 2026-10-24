"""MCP recorded-evidence workbench (LAB-MCP-003/004/005): every event shown to a learner is an event in a committed specimen pack.

The exporter embeds the packs at build time; these tests re-read the packs and fail on any difference, any invented event and any invented claim.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("export_curriculum", ROOT / "scripts" / "export_curriculum.py")
EXP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXP)
DATA = json.loads((ROOT / "academy-ui" / "src" / "content" / "curriculum.json").read_text(encoding="utf-8"))
LABS = {l["id"]: l for l in DATA["labs"]}
RECORDED = ("LAB-MCP-003", "LAB-MCP-004", "LAB-MCP-005")
EXPECTED_RUNS = {
    "LAB-MCP-003": {"BASELINE": "5b089682-1d5a-49a7-ac43-967265fd6bc6", "ATTACK": "b466ad12-72ec-44b7-be28-aacfaf2c25b1", "RETEST": "f638fd4f-1c4f-4ab6-8d42-4d03a4f3afd5", "UNKNOWN": "6ce19813-6cb5-4aae-a3a0-aa59386a82dd"},
    "LAB-MCP-004": {"BASELINE": "fb50dcaf-8e84-4a3f-a55b-997c72edbd04", "ATTACK": "5ab59fc7-303e-4eea-84e7-ae0b2f405146", "RETEST": "0726a0ff-a551-41a8-bfbb-ab2ceca4c0dd", "UNKNOWN": "0e4e0051-528d-4bf3-8773-d1fb55a5864f"},
    "LAB-MCP-005": {"BASELINE": "3013aa39-fe08-4b58-9898-f3abb092ac06", "ATTACK": "f3f48182-df57-4b38-b069-17a199dc4939", "RETEST": "0ab10594-a7fc-48b6-81bf-4cbca54a64c6"},
}


def rec(lab):
    return LABS[lab]["explainer"]["recorded"]


@pytest.mark.parametrize("lab", RECORDED)
def test_exactly_the_documented_runs_are_shown_with_their_roles(lab):
    assert {r["role"]: r["run_id"] for r in rec(lab)["runs"]} == EXPECTED_RUNS[lab]


@pytest.mark.parametrize("lab", RECORDED)
def test_every_event_equals_the_committed_pack_event_for_event(lab):
    for run in rec(lab)["runs"]:
        pack = ROOT / run["pack"]
        raw = pack.read_bytes()
        assert pack.parent == ROOT / "learning" / "level_1" / lab / "specimens"
        assert hashlib.sha256(raw).hexdigest() == run["sha256"], "the pack changed after export"
        source = [json.loads(l) for l in raw.decode("utf-8").splitlines() if l.strip()]
        assert len(source) == len(run["events"]) == run["meta"]["event_count"]
        for src, shown in zip(source, run["events"]):
            for k, v in shown.items():
                assert src[k] == v, (run["run_id"], src["agentsec.sequence"], k)          # original values, unedited
            dropped = set(src) - set(shown)
            assert dropped <= set(EXP.RUN_CONSTANT), (run["run_id"], dropped)              # only run-wide constants are moved to meta
            for k in dropped:
                assert src[k] == source[0][k], "a dropped field must be identical on every event"
        assert [e["agentsec.sequence"] for e in run["events"]] == list(range(1, len(source) + 1))
        for mk, sk in EXP.RUN_META.items():
            assert run["meta"][mk] == source[0].get(sk)
        assert run["meta"]["started"] == source[0]["timestamp"] and run["meta"]["ended"] == source[-1]["timestamp"]
        assert all(e.get("agentsec.run.id", run["run_id"]) == run["run_id"] for e in source)


@pytest.mark.parametrize("lab", RECORDED)
def test_the_documented_text_of_each_run_is_the_labs_own_line_and_roles_match_the_packs(lab):
    for run in rec(lab)["runs"]:
        doc = EXP.clean((ROOT / run["documented_as"]["source"]).read_text(encoding="utf-8"))
        assert run["documented_as"]["text"] in doc and run["run_id"] in run["documented_as"]["text"] and run["role"] in run["documented_as"]["text"]
        mode = run["meta"]["mode"]
        assert mode == run["role"] or (run["role"] == "UNKNOWN" and mode == "ATTACK"), "the pack's own testbed mode must agree with the role shown"
        assert run["events"][run["decisive"] - 1]["event.name"] == "agentsec.control.decision"


@pytest.mark.parametrize("lab", RECORDED)
def test_decisions_reasons_and_handler_evidence_are_what_the_labs_documents_say(lab):
    runs = {r["role"]: r for r in rec(lab)["runs"]}
    def dec(role):
        e = runs[role]["events"][runs[role]["decisive"] - 1]
        return e["agentsec.control.decision"], e["agentsec.control.reason"]
    def started(role):
        return sum(1 for e in runs[role]["events"] if e["event.name"] == "agentsec.mcp.started" and e["agentsec.operation.executed"] is True)
    if lab == "LAB-MCP-005":
        assert dec("BASELINE") == ("OBSERVE", "result_is_data") and dec("RETEST") == ("DENY", "tool_not_granted")
        assert dec("ATTACK") == ("ALLOW", "vulnerable_profile_fail_open:result_derived_grant")
        assert (started("BASELINE"), started("ATTACK"), started("RETEST")) == (1, 2, 1)   # README: policy handler=1; follow-on handler=1 / 0
        assert "result-derived overlay" in runs["ATTACK"]["events"][8]["agentsec.content.preview"]
    else:
        reason = "scope_not_granted" if lab == "LAB-MCP-003" else "resource_not_granted"
        unknown = "unknown_scope" if lab == "LAB-MCP-003" else "unknown_resource"
        assert dec("BASELINE") == ("ALLOW", "tool_granted") and dec("RETEST") == ("DENY", reason)
        assert dec("ATTACK") == ("ALLOW", f"vulnerable_profile_fail_open:{reason}") and dec("UNKNOWN") == ("ERROR", unknown)
        assert (started("BASELINE"), started("ATTACK"), started("RETEST"), started("UNKNOWN")) == (1, 1, 0, 0)   # README: handler=1,1,0,0
        # an ALLOW decision event records executed=false: execution is evidenced only by mcp.started
        assert runs["ATTACK"]["events"][2]["agentsec.operation.executed"] is False


@pytest.mark.parametrize("lab", RECORDED)
def test_spl_is_the_labs_own_text_unchanged_and_the_prediction_options_cover_every_recorded_decision(lab):
    r = rec(lab)
    for q in r["spl"]:
        assert q["text"] == (ROOT / q["source"]).read_text(encoding="utf-8").strip() and "__RUN_ID__" in q["text"]
    seen = {e["agentsec.control.decision"] for run in r["runs"] for e in run["events"] if "agentsec.control.decision" in e}
    assert seen <= set(r["options"])


def test_these_labs_stay_replay_and_are_not_described_as_native_live_or_verified():
    for lab in RECORDED:
        l = LABS[lab]
        assert l["availability"] == "replay" and l["integrated"] is False and l["launchable"] is False and l["native"] is None
    ui = (ROOT / "academy-ui" / "src" / "workbench")
    code = (ui / "RecordedWorkbench.tsx").read_text(encoding="utf-8") + (ui / "recorded.ts").read_text(encoding="utf-8")
    assert "RECORDED — NOT RE-RUN" in code and "makes no claim that they are Splunk-verified" in code
    for forbidden in ("launchLab", "fetch(", "/api/", "SPLUNK-VERIFIED", "splunk_verified"):
        assert forbidden not in code, forbidden


def test_the_other_replay_labs_keep_the_generic_page():
    assert [l["id"] for l in DATA["labs"] if l["explainer"] and "recorded" in l["explainer"]] == list(RECORDED)
