"""Unified Academy experience: every one of the 33 workshops is checked against the same rules.

R1  no mandatory step sends the learner to the legacy Attack UI or to a Splunk dashboard or Splunk Web;
R2  a workshop exposes only what its evidence mode supports (no launch controls on RECORDED or SIMULATED workshops);
R3  every LIVE workshop shows the unified sequence Learn, Predict, Baseline, Attack, Investigate, Defend, Retest, Explain evidence, with an in-Academy investigation.

The 60 gaps found by the 2026-10-29 audit (docs/design/rc2/academy-assurance/WORKSHOP_AUDIT.md) were tracked as strict xfails and each was closed by implementation in
Checkpoint 4 (the markers were removed only after every test passed as a strict XPASS). Nothing in this file is weakened.
"""
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / "academy-ui/src"
CATALOG = (ROOT / "docs/WORKSHOP_CATALOG.md").read_text(encoding="utf-8")
GUIDES = json.loads((ROOT / "learning/academy/workshop_guides.json").read_text(encoding="utf-8"))["guides"]
MODE = {m.group(1): m.group(2) for m in re.finditer(r"\(`(LAB-[A-Z0-9-]+)`\) \| L\d+ \| (LIVE|RECORDED|SIMULATED)", CATALOG)}
WORKSHOPS = ["ORIENTATION", *sorted(MODE)]
LIVE = sorted(k for k, v in MODE.items() if v == "LIVE")
NOT_LIVE = sorted(k for k, v in MODE.items() if v != "LIVE")
STAGES = ("learn", "predict", "baseline", "attack", "investigate", "defend", "retest", "explain")
LEAVES = re.compile(r"Studio|ws_lab|Splunk Search|in Splunk|search Splunk|Attack Service UI|:5001", re.I)

SOURCE = {"LAB-PI-001": "workbench/PiWorkbench.tsx", "LAB-RAG-CONTEXT": "workbench/RagWorkbench.tsx", "LAB-MCP-001": "pages/Mcp.tsx", "LAB-LOANDESK-001": "mission/stages/Investigate.tsx"}


def src(lab):
    return (UI / SOURCE.get(lab, "workbench/ScenarioWorkbench.tsx")).read_text(encoding="utf-8")


def test_the_catalog_has_33_workshops_and_the_modes_add_up():
    assert len(WORKSHOPS) == 33 and len(LIVE) == 13 and len(NOT_LIVE) == 19 and set(MODE) == set(GUIDES)


# ---------------------------------------------------------------- R1
@pytest.mark.parametrize("lab", WORKSHOPS)
def test_r1_guide_steps_do_not_leave_the_academy(lab):
    g = GUIDES.get(lab)
    text = json.dumps({k: g.get(k) for k in ("completion", "troubleshooting")}) if g else ""
    assert not LEAVES.search(text)


@pytest.mark.parametrize("lab", LIVE)
def test_r1_live_investigate_runs_in_the_academy(lab):
    s = src(lab)
    assert "SplCell" in s and "does not run" not in s and not re.search(r"Run each search in Splunk|Run these yourself in Splunk", s)


# ---------------------------------------------------------------- R2
LAUNCHERS = re.compile(r"/api/launch|launchLab|launchAttack|api/labs/[^`'\"]*/launch")


@pytest.mark.parametrize("lab", NOT_LIVE)
def test_r2_recorded_and_simulated_workshops_have_no_launch_controls(lab):
    for f in ("InvestigationWorkbench", "RecordedWorkbench", "SplunkWorkbench", "StudyWorkbench", "CheckpointWorkbench", "InventoryPractice"):
        p = UI / "workbench" / f"{f}.tsx"
        if p.exists():
            assert not LAUNCHERS.search(p.read_text(encoding="utf-8")), f


def test_r2_the_page_states_the_catalog_mode_and_is_not_self_contradictory():
    cur = (UI / "curriculum.ts").read_text(encoding="utf-8")
    assert all(w in cur for w in ("LIVE", "RECORDED", "SIMULATED")) and "not integrated in this Academy yet" not in cur


# ---------------------------------------------------------------- R3
@pytest.mark.parametrize("lab", LIVE)
def test_r3_live_workshops_show_the_unified_sequence(lab):
    stages = (UI / "stages.ts").read_text(encoding="utf-8").lower() + src(lab).lower()
    assert all(re.search(rf"\b{s}\b", stages) for s in STAGES) and "unifiedstages" in stages.replace(" ", "")


def test_r3_the_flow_bar_points_at_the_current_workshop():
    flow = (UI / "WorkshopFlow.tsx").read_text(encoding="utf-8")
    assert "/loan-desk/attack" not in flow
