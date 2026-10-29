"""Workstream C (UI sprint) compatibility guards for the Splunk app.

Presentation changes only: every view must stay well-formed, every Dashboard Studio
definition must reference only ids it defines, nav targets must exist, and no SPL,
saved search, macro, index or props content may differ from baseline commit 687c7cc.
"""

from __future__ import annotations

import json
import re
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
APP = ROOT / "splunk_app" / "agentsec"
VIEWS = APP / "default" / "data" / "ui" / "views"
NAV = APP / "default" / "data" / "ui" / "nav" / "default.xml"
BASELINE = "687c7cc"
CONFS = ("savedsearches.conf", "macros.conf", "indexes.conf", "props.conf")


def _git_show(rel: str) -> str | None:
    r = subprocess.run(["git", "show", f"{BASELINE}:{rel}"], cwd=ROOT, capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else None


def _definition(path: Path) -> dict | None:
    m = re.search(r"<!\[CDATA\[(.*?)\]\]>", path.read_text(encoding="utf-8"), re.S)
    return json.loads(m.group(1)) if m else None


def _queries(definition: dict | None) -> dict:
    return {k: v.get("options", {}).get("query") for k, v in (definition or {}).get("dataSources", {}).items()}


@pytest.mark.parametrize("path", sorted(VIEWS.glob("*.xml")), ids=lambda p: p.name)
def test_view_is_well_formed_and_self_consistent(path):
    ET.parse(path)
    d = _definition(path)
    if d is None:
        return  # Simple XML view (learner_path, open_attack)
    viz, ds = d.get("visualizations", {}), d.get("dataSources", {})
    for vid, v in viz.items():
        for src in (v.get("dataSources") or {}).values():
            assert src in ds, f"{path.name}:{vid} -> missing data source {src}"
    layouts = d["layout"].get("layoutDefinitions", {})
    for t in d["layout"].get("tabs", {}).get("items", []):
        assert t["layoutId"] in layouts
    for lid, lay in layouts.items():
        for row in lay.get("structure", []):
            known = viz if row["type"] == "block" else d.get("inputs", {})
            assert row["item"] in known, f"{path.name}:{lid} -> missing {row['type']} {row['item']}"
    for gi in d["layout"].get("globalInputs", []):
        assert gi in d.get("inputs", {})


def test_nav_targets_exist():
    names = {p.stem for p in VIEWS.glob("*.xml")} | {"search"}
    for v in ET.parse(NAV).getroot().iter("view"):
        assert v.get("name") in names, v.get("name")


def test_baseline_view_ids_still_exist():
    out = subprocess.run(["git", "ls-tree", "--name-only", f"{BASELINE}:splunk_app/agentsec/default/data/ui/views"],
                         cwd=ROOT, capture_output=True, text=True)
    if out.returncode:
        pytest.skip("baseline commit not available")
    for name in out.stdout.split():
        assert (VIEWS / name).is_file(), f"view removed: {name}"


def test_spl_and_detection_config_unchanged_vs_baseline():
    for conf in CONFS:
        base = _git_show(f"splunk_app/agentsec/default/{conf}")
        if base is None:
            pytest.skip("baseline commit not available")
        now = (APP / "default" / conf).read_text(encoding="utf-8").split("# ---- AI Security Assurance")[0].rstrip()
        assert now == base.rstrip(), conf          # the generated AI Security Assurance macro block is appended and checked by tests/test_assurance_app.py
    for path in VIEWS.glob("*.xml"):
        base = _git_show(f"splunk_app/agentsec/default/data/ui/views/{path.name}")
        if base is None:
            continue
        m = re.search(r"<!\[CDATA\[(.*?)\]\]>", base, re.S)
        before = _queries(json.loads(m.group(1))) if m else {}
        assert _queries(_definition(path)) == before, f"SPL changed in {path.name}"
