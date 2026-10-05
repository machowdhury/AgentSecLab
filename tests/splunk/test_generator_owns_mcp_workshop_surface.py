"""Regression guard: regenerating LAB-MCP-001 must not destroy learner surface.

Three pieces of the Tool Authorization workshop used to exist only inside the
generated artifacts, with no generator producing them:

  * viz_flow_diagram        the architecture image pinned to the top of MISSION
  * viz_guide_events        semantic ALLOW/DENY and executed column formatting
  * viz_guide_summary       the same formatting on the summary table

Running scripts/build_lab_mcp_001_dashboard.py silently deleted all three, and
nothing failed until a later test happened to read them. These tests run the
real generators into a scratch copy of the repository artifacts and assert the
surface survives, so the generators stay the owners.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
VIEW = ROOT / "splunk_app/agentsec/default/data/ui/views/ws_lab_mcp_001.xml"
DEFINITION = ROOT / "learning/level_1/LAB-MCP-001/dashboard.definition.json"
BUILD = ROOT / "scripts/build_lab_mcp_001_dashboard.py"
GUIDED = ROOT / "scripts/apply_guided_learning.py"

# apply_guided_learning.py must run last; the build scripts rebuild definitions
# from scratch and drop viz_guide_shell.
GENERATOR_ORDER = (BUILD, GUIDED)


def _definition(text: str) -> dict:
    match = re.search(r"<definition><!\[CDATA\[(.*?)\]\]></definition>", text, re.S)
    assert match, "view is missing its Studio definition"
    return json.loads(match.group(1))


@pytest.fixture(scope="module")
def regenerated(tmp_path_factory) -> dict:
    """Run the real generators, then restore the working tree."""
    backup = tmp_path_factory.mktemp("baseline")
    for path in (VIEW, DEFINITION):
        shutil.copy2(path, backup / path.name)
    try:
        for script in GENERATOR_ORDER:
            result = subprocess.run(
                [sys.executable, str(script)],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            assert result.returncode == 0, f"{script.name} failed: {result.stderr}"
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
    """apply_guided_learning.py running last is what keeps this present."""
    assert "viz_guide_shell" in regenerated["view_definition"]["visualizations"]


@pytest.mark.parametrize("viz_id", ["viz_guide_events", "viz_guide_summary"])
def test_semantic_evidence_formatting_survives_regeneration(regenerated, viz_id):
    viz = regenerated["view_definition"]["visualizations"][viz_id]
    column_format = viz["options"]["columnFormat"]
    assert set(column_format) == {"decision", "executed"}

    context = viz["context"]
    decision_text = {row["match"]: row["value"] for row in context["decisionText"]}
    assert decision_text["ALLOW"] == "#3568A8"
    assert decision_text["DENY"] == "#B7791F"
    assert decision_text["ERROR"] == "#C62828"

    # ALLOW is a control decision, never a safe outcome, so no success green.
    assert "#2E7D32" not in json.dumps(context)

    executed_background = {row["match"]: row["value"] for row in context["executedBackgrounds"]}
    assert executed_background["true"] == "#0B1F33"
    assert executed_background["false"] == "#EEF1F4"
