"""Visual learning presentation contracts. No live Splunk paint."""

from __future__ import annotations

import json
from pathlib import Path

from agentsec.workshop_flows import (
    EVIDENCE_TABLE_COLUMN_FORMAT,
    FLOWS,
    LAB_TO_VIEW,
    LEARNING,
    STATIC,
    VIEWS,
    asset_name,
    inventory,
    render_flow_svg,
)

ROOT = Path(__file__).resolve().parents[2]


def test_workshop_flow_inventory_covers_every_lab_dashboard():
    labs = sorted(path.name for path in LEARNING.iterdir() if path.is_dir() and path.name.startswith("LAB-"))
    flow_labs = [row["lab"] for row in FLOWS]
    assert sorted(flow_labs) == labs
    assert all(row["diagram"] == "YES" for row in inventory())
    leaked = ("this ATTACK will ALLOW", "this RETEST will DENY", "expected ALLOW", "expected DENY")
    for flow in FLOWS:
        blob = " ".join(label for _kind, label in flow["steps"]).lower() + " " + flow["desc"].lower()
        assert not any(phrase in blob for phrase in leaked)


def test_flow_svgs_are_valid_and_packaged():
    for flow in FLOWS:
        svg = render_flow_svg(flow)
        assert svg.startswith("<svg ")
        assert flow["title"] in svg
        assert flow["desc"] in svg
        assert "this ATTACK will ALLOW" not in svg
        path = STATIC / "flows" / asset_name(flow["lab"])
        assert path.is_file()
        assert path.read_text(encoding="utf-8").startswith("<svg ")


def test_dashboards_reference_flow_images_and_table_format():
    for flow in FLOWS:
        definition = json.loads((LEARNING / flow["lab"] / "dashboard.definition.json").read_text(encoding="utf-8"))
        viz = definition["visualizations"]["viz_flow_diagram"]
        assert viz["type"] == "splunk.image"
        assert viz["options"]["src"].endswith(asset_name(flow["lab"]))
        assert viz["options"]["preserveAspectRatio"] is True
        assert viz["options"]["src"].startswith("/en-US/static/app/agentsec/flows/")
        first = definition["layout"]["tabs"]["items"][0]["layoutId"]
        structure = definition["layout"]["layoutDefinitions"][first]["structure"]
        assert structure[0]["item"] == "viz_flow_diagram"
        assert structure[0]["position"]["h"] == 200
        assert structure[0]["position"]["w"] == 1440
        xml = (VIEWS / f"{LAB_TO_VIEW[flow['lab']]}.xml").read_text(encoding="utf-8")
        assert "viz_flow_diagram" in xml
        assert "stylesheet=" not in xml
        if "viz_guide_events" in definition["visualizations"]:
            events = definition["visualizations"]["viz_guide_events"]
            assert events["options"]["columnFormat"]["decision"] == EVIDENCE_TABLE_COLUMN_FORMAT["decision"]
            assert events["options"]["columnFormat"]["executed"] == EVIDENCE_TABLE_COLUMN_FORMAT["executed"]
            assert events["context"]["decisionText"][0]["match"] == "ALLOW"
            assert events["context"]["decisionText"][0]["value"] == "#3568A8"
            assert events["context"]["decisionText"][1]["value"] == "#B7791F"
            assert "#2E7D32" not in json.dumps(events["context"])


def test_prediction_controls_stay_browser_only():
    attack = (ROOT / "src/agentsec/templates/attack.html").read_text(encoding="utf-8")
    mcp = (ROOT / "src/agentsec/templates/attack_mcp.html").read_text(encoding="utf-8")
    css = (ROOT / "src/agentsec/static/agentsec.css").read_text(encoding="utf-8")
    for html in (attack, mcp):
        assert 'name="predict-control"' in html
        assert 'name="predict-execution"' in html
        assert "choice-card" in html
        assert "PREDICTION RECORDED" in html or "prediction-recorded" in html
        assert "not sent to Splunk" in html
        assert "not graded" in html
        assert "not a control decision" in html
        launch = html.split("JSON.stringify({", 1)[1].split("})", 1)[0]
        assert "predict-control" not in launch
    assert ".choice-card" in css
    assert "min-height: 2.75rem" in css


def test_studio_injection_remains_absent():
    for path in VIEWS.glob("ws_*.xml"):
        text = path.read_text(encoding="utf-8")
        assert "stylesheet=" not in text
        assert "agentsec_studio_focus.css" not in text
        assert "<script" not in text.lower()
    assert not (STATIC / "agentsec_studio_focus.css").exists()


def test_your_path_style_hooks_exist():
    script = (ROOT / "splunk_app/agentsec/appserver/static/agentsec_learner_path.js").read_text(encoding="utf-8")
    assert "agentsec-path-card" in script
    assert "agentsec-path-summary" in script
    assert "INVESTIGATED means you marked the workshop" in script
    assert "agentsec.learner.progress.v1" in script
    assert '["NOT STARTED", "IN PROGRESS", "INVESTIGATED"]' in script
