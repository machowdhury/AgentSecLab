"""Simulated positive-control rows must always be labeled SIMULATED, in the data and in every panel title."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_every_positive_control_search_is_marked_simulated_with_a_simulated_run_id():
    packs = sorted((ROOT / "learning/level_1").glob("*/searches/*POSITIVE-CONTROL.spl"))
    assert packs
    for spl in packs:
        text = spl.read_text(encoding="utf-8")
        assert 'evidence_class="SIMULATED"' in text, spl.name
        assert re.search(r'run\.id"="simulated-', text), spl.name  # can never collide with a real run.id
        assert "makeresults" in text, spl.name  # generated in the search, never read from the index


def test_every_positive_control_panel_title_says_simulated():
    titled = 0
    for path in (ROOT / "learning/level_1").glob("*/dashboard.definition.json"):
        for viz in json.loads(path.read_text(encoding="utf-8")).get("visualizations", {}).values():
            title = viz.get("title", "")
            if "POSITIVE-CONTROL" in title:
                titled += 1
                assert "SIMULATED" in title, (path.parent.name, title)
    assert titled >= 13  # the panels present when this guard was added
