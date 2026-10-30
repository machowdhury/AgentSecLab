"""All 33 workshops (the Orientation plus the 32 registered labs and checkpoints) are complete against what their tier promises:
LIVE workshops launch BASELINE, ATTACK and RETEST through a closed allowlist; recorded and packet workshops ship committed evidence and say they are not executable."""
import json
from pathlib import Path

import pytest

from agentsec.launch_catalog import LAUNCH_ALLOWLIST
from agentsec.lab_registry import load_registry

ROOT = Path(__file__).resolve().parents[1]
LEVEL1 = ROOT / "learning/level_1"
ENTRIES = {e["lab_id"]: e for e in load_registry()["entries"]}
GUIDES = json.loads((ROOT / "learning/academy/workshop_guides.json").read_text())["guides"]
MODES = {}
for row in LAUNCH_ALLOWLIST:
    MODES.setdefault(row.lab_id, set()).add(row.mode)
LIVE = {k for k, e in ENTRIES.items() if e["mode"] == "LIVE"}
NATIVE_LIVE = {"LAB-LOANDESK-001"}                 # launched through its own mission API (/api/missions/loan-desk/runs), not the allowlist
EVIDENCE = ("evidence.packet.json", "inventory.packet.json", "specimens", "searches", "splunk-evidence", "incident.json", "architecture.json", "data-map.json", "workshop.md", "evidence.md")


def test_there_are_33_workshops_and_the_orientation_is_the_start():
    cur = json.loads((ROOT / "learning/academy/curriculum.json").read_text())
    assert len(ENTRIES) == 32 and cur["levels"][0]["id"] == "L0" and cur["start_view"] and cur["start_lab_id"]
    assert (ROOT / "src/agentsec/templates/academy/home.html").exists()


def test_every_live_workshop_launches_all_three_modes_or_has_its_own_mission_launcher():
    assert len(LIVE) == 13
    for lab in LIVE - NATIVE_LIVE:
        assert MODES.get(lab) == {"BASELINE", "ATTACK", "RETEST"}, lab
    assert NATIVE_LIVE <= LIVE and not (NATIVE_LIVE & set(MODES))
    assert set(MODES) <= LIVE, "nothing is on the allowlist that the curriculum calls REPLAY"


@pytest.mark.parametrize("lab", sorted(LIVE - NATIVE_LIVE))
def test_live_workshops_have_a_prediction_before_launch_a_guided_investigation_and_a_finish_guide(lab):
    m = json.loads((LEVEL1 / lab / "lab-manifest.json").read_text())
    assert m["not_authorization"] is True and m["security_question"]
    for mode in ("BASELINE", "ATTACK", "RETEST"):
        assert m["prediction"][mode]["predict_before_launch"], (lab, mode)
    inv = json.loads((LEVEL1 / lab / "investigations.json").read_text())
    assert inv["path_a"] and inv["path_b"] and len(inv["investigations"]) >= 5
    assert GUIDES[lab]["kind"] == "live" and len(GUIDES[lab]["completion"]) >= 3


@pytest.mark.parametrize("lab", sorted(set(ENTRIES) - LIVE))
def test_recorded_and_packet_workshops_ship_committed_evidence_and_never_claim_execution(lab):
    d = LEVEL1 / lab
    assert any((d / n).exists() for n in EVIDENCE), f"{lab} has no committed evidence"
    g = GUIDES[lab]
    assert g["kind"] in ("recorded", "simulated packet")
    ex = json.loads((ROOT / "learning/academy/explainers" / f"{lab}.json").read_text())
    assert ex["status"] == "full" and ex["summary"]["text"]
    text = json.dumps(g).lower()
    assert "runtime enforcement" not in text and "we enforce" not in text
    if g["kind"] == "simulated packet":
        packet = [p for p in d.glob("*packet.json")] or [d / "incident.json", d / "architecture.json", d / "data-map.json"]
        assert any(p.exists() for p in packet)


def test_the_three_ctf_challenges_exist_and_are_each_tied_to_a_workshop():
    from agentsec.ctf.challenges import default_scenarios
    ids = set(default_scenarios())
    assert ids == {"note-smuggler", "poisoned-catalog", "confused-deputy-relay"}
    page = (ROOT / "academy-ui/src/pages/Lab.tsx").read_text()
    for cid, lab in (("note-smuggler", "LAB-LOANDESK-001"), ("poisoned-catalog", "LAB-MCP-CATALOG"), ("confused-deputy-relay", "LAB-MCP-006")):
        assert f'"{lab}": {{ id: "{cid}"' in page
