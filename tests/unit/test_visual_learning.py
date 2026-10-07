"""Visual learning presentation contracts. No live Splunk paint."""

from __future__ import annotations

import json
import re
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


def _luminance(hex_colour: str) -> float:
    r, g, b = (int(hex_colour.lstrip("#")[i:i + 2], 16) / 255 for i in (0, 2, 4))

    def lin(c: float) -> float:
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4

    return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)


def _contrast(fg: str, bg: str) -> float:
    hi, lo = sorted((_luminance(fg), _luminance(bg)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def test_decision_text_pairs_meet_normal_text_contrast():
    """MEASURED from the shipped constants, not asserted from a design file."""
    from agentsec.workshop_flows import EVIDENCE_TABLE_CONTEXT  # noqa: PLC0415

    background = {row["match"]: row["value"] for row in EVIDENCE_TABLE_CONTEXT["decisionBackgrounds"]}
    for row in EVIDENCE_TABLE_CONTEXT["decisionText"]:
        assert _contrast(row["value"], background[row["match"]]) >= 4.5, row["match"]
    for row in EVIDENCE_TABLE_CONTEXT["executedText"]:
        background_for = {r["match"]: r["value"] for r in EVIDENCE_TABLE_CONTEXT["executedBackgrounds"]}
        assert _contrast(row["value"], background_for[row["match"]]) >= 4.5, row["match"]


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
            # CONTRACT CHANGE: P1 learner-experience redesign (D-4)
            # OLD CONTRACT: DENY text was #B7791F, MEASURED at 3.08:1 on its #F6EBD8 row
            #   background (below the 4.5:1 minimum for normal text).
            # NEW CONTRACT: DENY text is #7A4F0B (MEASURED 6.03:1 on the same background).
            #   The word DENY is still the cell content, so colour is not the only carrier.
            # WHY: readability; the semantic mapping (ALLOW informational, DENY amber,
            #   ERROR red, no success green) is unchanged.
            assert events["context"]["decisionText"][1]["value"] == "#7A4F0B"
            assert _contrast("#7A4F0B", "#F6EBD8") >= 4.5
            assert "#2E7D32" not in json.dumps(events["context"])


def test_prediction_controls_stay_browser_only():
    attack = (ROOT / "src/agentsec/templates/attack.html").read_text(encoding="utf-8")
    mcp = (ROOT / "src/agentsec/templates/attack_mcp.html").read_text(encoding="utf-8")
    css = (ROOT / "src/agentsec/static/agentsec.css").read_text(encoding="utf-8")
    for html in (attack, mcp):
        assert 'name="predict-control"' in html
        assert 'name="predict-execution"' in html
        # CONTRACT CHANGE: P1 learner-experience redesign
        # OLD CONTRACT: both lab pages used the shared "choice-card" markup for prediction radios.
        # NEW CONTRACT: LAB-MCP-001 uses the approved academy "opt" cards (agentsec-academy.css);
        #   the other lab keeps "choice-card". Both remain radio inputs with no default selection.
        # WHY: the approved P1 design replaces the MCP prediction layout; other labs are out of scope.
        assert ("choice-card" in html) or ('class="opt"' in html)
    inputs = re.findall(r'<input[^>]*name="predict-(?:control|execution)"[^>]*>', mcp, re.S)
    assert inputs and not any(" checked" in tag for tag in inputs), "MCP: no pre-selected prediction"
    for html in (attack, mcp):
        assert "PREDICTION RECORDED" in html or "prediction-recorded" in html or "Prediction locked" in html
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
