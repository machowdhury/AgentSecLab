"""Regression guard: regenerating a workshop must not destroy learner surface.

Three pieces of every workshop are stamped on after the build script runs:

  * viz_flow_diagram        the architecture image pinned to the top of tab one
  * viz_guide_events        semantic ALLOW/DENY and executed column formatting
  * viz_guide_summary       the same formatting on the summary table

The logic lives in agentsec.workshop_flows, but nothing in the pipeline called
it, so every scripts/build_lab_*_dashboard.py silently deleted the image and
the colour semantics from its view and the loss was invisible until an
unrelated test happened to read them. scripts/apply_workshop_flows.py now gives
that work a named stage.

Pipeline order, enforced here:

    build_lab_*_dashboard.py -> apply_workshop_flows.py -> apply_guided_learning.py
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from agentsec.workshop_flows import FLOWS, LAB_TO_VIEW, LEARNING, VIEWS, asset_name

ROOT = Path(__file__).resolve().parents[2]
VIEW = VIEWS / "ws_lab_mcp_001.xml"
DEFINITION = LEARNING / "LAB-MCP-001" / "dashboard.definition.json"

BUILD = ROOT / "scripts/build_lab_mcp_001_dashboard.py"
FLOWS_STAGE = ROOT / "scripts/apply_workshop_flows.py"
GUIDED = ROOT / "scripts/apply_guided_learning.py"
PIPELINE = (BUILD, FLOWS_STAGE, GUIDED)


def _run(script: Path) -> None:
    result = subprocess.run(
        [sys.executable, str(script)], cwd=ROOT, capture_output=True, text=True
    )
    assert result.returncode == 0, f"{script.name} failed: {result.stderr}"


def _definition(text: str) -> dict:
    match = re.search(r"<definition><!\[CDATA\[(.*?)\]\]></definition>", text, re.S)
    assert match, "view is missing its Studio definition"
    return json.loads(match.group(1))


def _all_artifacts() -> list[Path]:
    paths = []
    for flow in FLOWS:
        paths.append(LEARNING / flow["lab"] / "dashboard.definition.json")
        paths.append(VIEWS / f"{LAB_TO_VIEW[flow['lab']]}.xml")
    return paths


@pytest.fixture(scope="module")
def regenerated(tmp_path_factory) -> dict:
    """Run the real pipeline, then restore the working tree."""
    backup = tmp_path_factory.mktemp("baseline")
    for path in (VIEW, DEFINITION):
        shutil.copy2(path, backup / path.name)
    try:
        for script in PIPELINE:
            _run(script)
        produced = {
            "view": VIEW.read_text(encoding="utf-8"),
            "definition": json.loads(DEFINITION.read_text(encoding="utf-8")),
        }
    finally:
        for path in (VIEW, DEFINITION):
            shutil.copy2(backup / path.name, path)
    produced["view_definition"] = _definition(produced["view"])
    return produced


def test_regeneration_is_byte_identical_to_the_committed_artifacts(regenerated):
    """The committed artifacts are reproducible, so review sees real diffs."""
    assert regenerated["view"] == VIEW.read_text(encoding="utf-8")
    assert regenerated["definition"] == json.loads(DEFINITION.read_text(encoding="utf-8"))


def test_architecture_flow_survives_regeneration(regenerated):
    definition = regenerated["view_definition"]
    assert "viz_flow_diagram" in definition["visualizations"]
    viz = definition["visualizations"]["viz_flow_diagram"]
    assert viz["type"] == "splunk.image"
    assert viz["options"]["src"].endswith("flow-lab-mcp-001.svg")

    first_tab = definition["layout"]["tabs"]["items"][0]["layoutId"]
    structure = definition["layout"]["layoutDefinitions"][first_tab]["structure"]
    assert structure[0]["item"] == "viz_flow_diagram", "flow image must stay first"
    assert structure[0]["position"] == {"x": 0, "y": 0, "w": 1440, "h": 200}


def test_guided_shell_survives_regeneration(regenerated):
    """apply_guided_learning.py running last keeps the START tab authored, not generic.

    CONTRACT CHANGE: P1 learner-experience redesign
    OLD CONTRACT: viz_guide_shell (the generic ten-section guide) was present on LAB-MCP-001.
    NEW CONTRACT: LAB-MCP-001 is in AUTHORED_START_LABS. Its first tab is the generator's own
      short START panel and the generic guide must NOT be re-injected on top of it.
    WHY: ONE SCREEN -> ONE LEARNING OBJECTIVE -> ONE DOMINANT NEXT ACTION. Every other lab
      still receives the generic guide (tests/splunk/test_guided_learning.py).
    """
    visualizations = regenerated["view_definition"]["visualizations"]
    assert "viz_guide_shell" not in visualizations
    assert "viz_guide_events" not in visualizations
    assert "viz_workbench_mission" in visualizations


@pytest.mark.parametrize("viz_id", ["viz_nb1_r", "viz_nb1_fb"])
def test_semantic_evidence_formatting_survives_regeneration(regenerated, viz_id):
    """CONTRACT CHANGE: P1. The formatted tables are now the INVESTIGATE decision readouts
    (the generic guide tables no longer exist on this lab). The semantic rules are unchanged."""
    viz = regenerated["view_definition"]["visualizations"][viz_id]
    assert set(viz["options"]["columnFormat"]) == {"decision", "executed"}

    context = viz["context"]
    decision_text = {row["match"]: row["value"] for row in context["decisionText"]}
    assert decision_text["ALLOW"] == "#3568A8"
    assert decision_text["DENY"] == "#7A4F0B"  # CONTRACT CHANGE (P1 D-4): was #B7791F, 3.08:1
    assert decision_text["ERROR"] == "#C62828"

    # ALLOW is a control decision, never a safe outcome, so no success green.
    assert "#2E7D32" not in json.dumps(context)

    executed_background = {row["match"]: row["value"] for row in context["executedBackgrounds"]}
    assert executed_background["true"] == "#0B1F33"
    assert executed_background["false"] == "#EEF1F4"


def test_every_workshop_currently_carries_its_flow_image():
    """All 31, not just the one this phase touched."""
    for flow in FLOWS:
        definition = json.loads(
            (LEARNING / flow["lab"] / "dashboard.definition.json").read_text(encoding="utf-8")
        )
        viz = definition["visualizations"].get("viz_flow_diagram")
        assert viz is not None, f"{flow['lab']} lost its architecture flow"
        assert viz["options"]["src"].endswith(asset_name(flow["lab"]))


def test_flow_stage_restores_every_workshop_after_a_build_script_wipes_it(tmp_path):
    """The debt this stage exists to close.

    Simulates what any build_lab_*_dashboard.py does: rebuild a definition with
    no flow image. The stage must put all 31 back without being told which.
    """
    artifacts = _all_artifacts()
    backup = tmp_path / "artifacts"
    backup.mkdir()
    saved = {}
    for index, path in enumerate(artifacts):
        copy = backup / f"{index}-{path.name}"
        shutil.copy2(path, copy)
        saved[path] = copy
    try:
        stripped = []
        for flow in FLOWS:
            path = LEARNING / flow["lab"] / "dashboard.definition.json"
            definition = json.loads(path.read_text(encoding="utf-8"))
            if definition["visualizations"].pop("viz_flow_diagram", None) is None:
                continue
            first = definition["layout"]["tabs"]["items"][0]["layoutId"]
            canvas = definition["layout"]["layoutDefinitions"][first]
            canvas["structure"] = [
                item for item in canvas["structure"] if item["item"] != "viz_flow_diagram"
            ]
            for item in canvas["structure"]:
                item["position"]["y"] = int(item["position"]["y"]) - 208
            canvas["options"]["height"] = int(canvas["options"]["height"]) - 208
            path.write_text(
                json.dumps(definition, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
            )
            stripped.append(flow["lab"])

        assert len(stripped) == len(FLOWS), "expected every workshop to have one to strip"

        _run(FLOWS_STAGE)

        for flow in FLOWS:
            definition = json.loads(
                (LEARNING / flow["lab"] / "dashboard.definition.json").read_text(encoding="utf-8")
            )
            viz = definition["visualizations"].get("viz_flow_diagram")
            assert viz is not None, f"{flow['lab']} was not restored"
            assert viz["options"]["src"].endswith(asset_name(flow["lab"]))
            first = definition["layout"]["tabs"]["items"][0]["layoutId"]
            structure = definition["layout"]["layoutDefinitions"][first]["structure"]
            assert structure[0]["item"] == "viz_flow_diagram", flow["lab"]
            xml = (VIEWS / f"{LAB_TO_VIEW[flow['lab']]}.xml").read_text(encoding="utf-8")
            assert "viz_flow_diagram" in xml, flow["lab"]
    finally:
        for path, copy in saved.items():
            shutil.copy2(copy, path)


def test_flow_stage_is_idempotent():
    """Running it twice must not shift the canvas or duplicate the block."""
    before = {path: path.read_bytes() for path in _all_artifacts()}
    _run(FLOWS_STAGE)
    try:
        after = {path: path.read_bytes() for path in _all_artifacts()}
        drifted = [path.name for path in before if before[path] != after[path]]
        assert not drifted, f"apply_workshop_flows.py is not idempotent: {drifted}"
    finally:
        for path, data in before.items():
            path.write_bytes(data)
