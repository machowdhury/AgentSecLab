"""P1.3 guard: LAB-MCP-001 lab-boundary statements must stay visible.

The dashboard description carries the lab-boundary statements (DET-MCP-001 is
packaged disabled and not enabled by this dashboard, not a notable-event pack,
Splunk does not ALLOW or DENY). P1.3 evaluated hiding the title/description
(``showTitleAndDescription: false``) to recover vertical space at 400% zoom.
That is only safe if the same statements are moved onto the START tab first.

This guard holds for the accepted dashboard (title/description shown) and for
the P1.3 candidate (title hidden, statements on START). It fails if anyone
hides the description without moving the statements.

Deterministic file checks only: no Splunk, no browser.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DEFINITION_PATH = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "dashboard.definition.json"
VIEW_XML = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views" / "ws_lab_mcp_001.xml"
SAVEDSEARCHES = ROOT / "splunk_app" / "agentsec" / "default" / "savedsearches.conf"
START_LAYOUT = "layout_mission"

#: Statement name -> phrase that must be readable (markdown emphasis ignored).
REQUIRED_STATEMENTS = {
    "det_mcp_001_disabled": "DET-MCP-001 is packaged disabled",
    "dashboard_does_not_enable": "this dashboard does not enable it",
    "not_a_notable_pack": "Not a notable-event pack",
    "splunk_does_not_enforce": "Splunk does not ALLOW or DENY a tool",
}


def _plain(text: str) -> str:
    """Drop markdown emphasis and collapse whitespace so wording, not styling, is compared."""
    return re.sub(r"\s+", " ", re.sub(r"[*_`]", "", text)).strip()


def _start_markdown(definition: dict) -> str:
    layout = definition["layout"]["layoutDefinitions"].get(START_LAYOUT, {})
    items = [row["item"] for row in layout.get("structure", [])]
    visualizations = definition.get("visualizations", {})
    parts = []
    for item in items:
        viz = visualizations.get(item, {})
        if viz.get("type") == "splunk.markdown":
            parts.append(viz.get("options", {}).get("markdown", ""))
    return _plain("\n".join(parts))


def missing_safety_statements(definition: dict) -> list[str]:
    """Return the names of required statements a learner cannot see.

    Studio shows the title/description unless ``showTitleAndDescription`` is
    explicitly False, so a missing key counts as shown (fail-safe direction:
    the description must then hold the statements).
    """
    shown = definition.get("layout", {}).get("options", {}).get("showTitleAndDescription", True) is not False
    visible = _plain(definition.get("description", "")) if shown else _start_markdown(definition)
    return [name for name, phrase in REQUIRED_STATEMENTS.items() if _plain(phrase) not in visible]


def _without_start_statements(definition: dict) -> dict:
    """Copy with any START markdown panel that carries a required statement removed."""
    out = copy.deepcopy(definition)
    layout = out["layout"]["layoutDefinitions"][START_LAYOUT]
    keep = []
    for row in layout["structure"]:
        viz = out["visualizations"].get(row["item"], {})
        text = _plain(viz.get("options", {}).get("markdown", "")) if viz.get("type") == "splunk.markdown" else ""
        if not any(_plain(p) in text for p in REQUIRED_STATEMENTS.values()):
            keep.append(row)
    layout["structure"] = keep
    return out


def _xml_definition() -> dict:
    xml = VIEW_XML.read_text(encoding="utf-8")
    match = re.search(r"<!\[CDATA\[(.*)\]\]>", xml, re.S)
    assert match, "ws_lab_mcp_001.xml has no CDATA definition"
    return json.loads(match.group(1))


@pytest.fixture(scope="module")
def shipped() -> dict:
    return json.loads(DEFINITION_PATH.read_text(encoding="utf-8"))


def test_shipped_definition_shows_all_safety_statements(shipped: dict) -> None:
    assert missing_safety_statements(shipped) == []


def test_shipped_view_xml_shows_all_safety_statements() -> None:
    assert missing_safety_statements(_xml_definition()) == []


def test_view_xml_embeds_the_shipped_definition(shipped: dict) -> None:
    assert _xml_definition() == shipped


def test_hiding_description_without_moving_statements_is_caught(shipped: dict) -> None:
    """Bypass attempt: win vertical space by hiding the description and nothing else."""
    hidden = _without_start_statements(shipped)
    hidden["layout"]["options"]["showTitleAndDescription"] = False
    assert sorted(missing_safety_statements(hidden)) == sorted(REQUIRED_STATEMENTS)


def test_statements_on_start_satisfy_guard_when_description_hidden(shipped: dict) -> None:
    """The P1.3 candidate shape: description hidden, statements in a START markdown panel."""
    moved = _without_start_statements(shipped)
    moved["layout"]["options"]["showTitleAndDescription"] = False
    moved["visualizations"]["viz_start_boundaries"] = {
        "type": "splunk.markdown",
        "options": {
            "markdown": "# Lab boundaries\n\n- Saved search **DET-MCP-001** is packaged disabled; "
            "this dashboard does not enable it.\n- **Splunk does not ALLOW or DENY a tool.**\n"
            "- Not a notable-event pack."
        },
    }
    moved["layout"]["layoutDefinitions"][START_LAYOUT]["structure"].append(
        {"item": "viz_start_boundaries", "type": "block", "position": {"x": 0, "y": 0, "w": 1440, "h": 330}}
    )
    assert missing_safety_statements(moved) == []


def test_statements_on_a_non_start_tab_do_not_count(shipped: dict) -> None:
    """Boundary: the statements must be on START, not buried on a REFERENCE tab."""
    moved = _without_start_statements(shipped)
    moved["layout"]["options"]["showTitleAndDescription"] = False
    moved["visualizations"]["viz_ref_boundaries"] = {
        "type": "splunk.markdown",
        "options": {"markdown": " ".join(REQUIRED_STATEMENTS.values())},
    }
    moved["layout"]["layoutDefinitions"]["layout_evidence"]["structure"].append(
        {"item": "viz_ref_boundaries", "type": "block", "position": {"x": 0, "y": 0, "w": 1440, "h": 200}}
    )
    assert sorted(missing_safety_statements(moved)) == sorted(REQUIRED_STATEMENTS)


def test_missing_show_title_option_is_treated_as_shown(shipped: dict) -> None:
    """Malformed/absent option: Studio default is to show; the description must hold the statements."""
    absent = copy.deepcopy(shipped)
    absent["layout"]["options"].pop("showTitleAndDescription", None)
    assert missing_safety_statements(absent) == []
    absent["description"] = "Tool Authorization workshop."
    assert sorted(missing_safety_statements(absent)) == sorted(REQUIRED_STATEMENTS)


def test_det_mcp_001_saved_search_is_packaged_disabled() -> None:
    """The statement is only true while the packaged saved search stays disabled."""
    text = SAVEDSEARCHES.read_text(encoding="utf-8")
    stanzas = re.split(r"(?m)^\[", text)
    det = [s for s in stanzas if "DET-MCP-001" in s.split("\n", 1)[0] or "Lab id DET-MCP-001" in s]
    assert det, "no DET-MCP-001 stanza in savedsearches.conf"
    for stanza in det:
        assert re.search(r"(?m)^disabled\s*=\s*1\s*$", stanza), stanza.split("\n", 1)[0]
