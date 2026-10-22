"""LAB-LOANDESK-001 is registered once, consistently, and is not a classic /api/launch lab."""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

from agentsec.attack_app import create_app
from agentsec.lab_manifest import validate_lab_manifest

ROOT = Path(__file__).resolve().parents[1]
LAB = "LAB-LOANDESK-001"
VIEW = "ws_lab_loandesk_001"


def _cur():
    return json.loads((ROOT / "learning/academy/curriculum.json").read_text(encoding="utf-8"))


def test_curriculum_ids_are_unique_and_the_mission_appears_once():
    cur = _cur()
    ids = [l["lab_id"] for lv in cur["levels"] for l in lv["labs"]] + [c["lab_id"] for c in cur["checkpoints"]]
    assert not [k for k, n in Counter(ids).items() if n > 1]
    assert ids.count(LAB) == 1 and len(ids) == 32
    views = [l["view"] for lv in cur["levels"] for l in lv["labs"]]
    assert not [k for k, n in Counter(views).items() if n > 1] and views.count(VIEW) == 1


def test_every_artifact_of_the_registration_exists_and_agrees():
    base = ROOT / "learning/level_1" / LAB
    for rel in ("README.md", "lab-manifest.json", "workshop.json", "knowledge-check.md", "dashboard.definition.json"):
        assert (base / rel).is_file(), rel
    assert validate_lab_manifest(LAB)["workshop_view"] == VIEW
    assert (ROOT / f"splunk_app/agentsec/default/data/ui/views/{VIEW}.xml").is_file()
    assert f'name="{VIEW}"' in (ROOT / "splunk_app/agentsec/default/data/ui/nav/default.xml").read_text(encoding="utf-8")
    assert VIEW in (ROOT / "splunk_app/agentsec/appserver/static/agentsec_learner_path.js").read_text(encoding="utf-8")
    assert VIEW in [v for c in _cur()["nav_collections"] for v in c["views"]]
    assert (ROOT / "splunk_app/agentsec/appserver/static/flows/flow-lab-loandesk-001.svg").is_file()


def test_the_view_binds_every_panel_to_one_run_id_and_covers_the_six_questions():
    x = (ROOT / f"splunk_app/agentsec/default/data/ui/views/{VIEW}.xml").read_text(encoding="utf-8")
    d = json.loads(re.search(r"CDATA\[(.*)\]\]>", x, re.S).group(1))
    queries = {k: v["options"]["query"] for k, v in d["dataSources"].items()}
    for key in ("ds_proposed", "ds_decisions", "ds_executed", "ds_denied", "ds_evidence", "ds_business", "ds_queue"):
        assert '"agentsec.run.id"="$live_run_id$"' in queries[key], key
    assert "agentsec.agent.action.proposed" in queries["ds_proposed"] and "agentsec.control.decision" in queries["ds_decisions"]
    assert "agentsec.mcp.started" in queries["ds_executed"] and 'decision="DENY"' in queries["ds_denied"]
    assert "gaps" in queries["ds_evidence"] and "business_task" in queries["ds_business"] and "security_outcome" in queries["ds_business"]
    assert d["inputs"]["input_live_run"]["options"]["defaultValue"] == "none"  # empty until a run.id is pasted
    # every search is the committed file, with the same multivalue-safe field handling
    for spl in (ROOT / "learning/level_1" / LAB / "searches").glob("Q-*.spl"):
        text = spl.read_text(encoding="utf-8")
        assert "__RUN_ID__" in text and "mvdedup" in text, spl.name


def test_registry_entry_is_a_guided_mission_with_a_verbatim_quote():
    reg = {e["lab_id"]: e for e in json.loads((ROOT / "learning/academy/lab_registry_data.json").read_text(encoding="utf-8"))["entries"]}
    e = reg[LAB]
    assert e["tier"] == "GUIDED MISSION" and e["primary_domain"] == "D02"
    readme = (ROOT / e["evidence"][0]["file"]).read_text(encoding="utf-8")
    assert " ".join(e["evidence"][0]["quote"].split()) in " ".join(readme.split())


def test_academy_links_the_mission_and_the_launcher_does_not_know_it():
    c = create_app().test_client()
    path = c.get("/academy/path").get_data(as_text=True)
    assert 'href="/academy/missions/loan-desk"' in path and "Loan Desk: Agent-Authored Content" in path
    home = c.get("/academy").get_data(as_text=True)
    assert home.count('href="/academy/missions/loan-desk"') >= 1 and home.count("data-progress-for=\"LAB-LOANDESK-001\"") == 1
    r = c.post("/api/launch", json={"lab_id": LAB, "specimen_id": "LOANDESK-ATTACK", "mode": "ATTACK", "execution": "live"})
    assert r.status_code in (400, 404, 422) and "run_id" not in (r.get_json() or {})
