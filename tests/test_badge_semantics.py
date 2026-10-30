"""Badge semantics in the React Academy: the evidence-LIVE treatment is reserved for genuinely live runs, models and environment."""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "academy-ui/src"
# Every place the live tone is used, with why each is genuinely live.
LIVE_OK = {
    "LIVE ENVIRONMENT": "service checks passed (shell.tsx, shown only when the environment reports ready)",
    "LIVE LAB": "the Loan Desk mission runs a live agent",
    "LIVE, NEW RUNS": "runs started now through the Attack Service (three workbenches)",
    "LIVE": "curriculum mode of a lab that launches live runs (Home table)",
    "REAL MODEL": "AgentTrace: only when the trace came from a real model",
}


def _live_badges():
    found = []
    for p in SRC.rglob("*.tsx"):
        for m in re.finditer(r'<Badge tone=(?:"live"|\{real \? "live" : "[a-z]+"\})>(.*?)</Badge>', p.read_text(encoding="utf-8")):
            found.append(re.sub(r"<span[^>]*/>|\{real \? \"REAL MODEL\" : \"TEST DOUBLE\"\}", lambda x: "REAL MODEL" if "real" in x.group(0) else "", m.group(1)).strip())
    return found


def test_only_genuinely_live_labels_use_the_live_tone():
    assert set(_live_badges()) <= set(LIVE_OK), sorted(set(_live_badges()) - set(LIVE_OK))


def test_teaching_labels_are_not_styled_as_live_evidence():
    lab = (SRC / "pages/Lab.tsx").read_text(encoding="utf-8")
    assert 'tone="live">EXPLANATION' not in lab and 'tone="live">NATIVE' not in lab
    assert lab.count('<Badge tone="info">EXPLANATION</Badge>') == 2 and '<Badge tone="info">NATIVE IN THIS ACADEMY</Badge>' in lab


def test_a_test_double_is_simulated_not_live():
    assert '"live" : "simulated"}>{real ? "REAL MODEL" : "TEST DOUBLE"}' in (SRC / "mission/AgentTrace.tsx").read_text(encoding="utf-8")


def test_unverified_and_simulated_and_recorded_never_use_the_live_tone():
    for p in SRC.rglob("*.tsx"):
        t = p.read_text(encoding="utf-8")
        assert not re.search(r'tone="live">[^<]*(RECORDED|SIMULATED|REPLAY|NOT VERIFIED|NOT_VERIFIED)', t), p.name


def test_the_live_environment_chip_has_no_second_glyph():
    css = (SRC / "index.css").read_text(encoding="utf-8")
    assert ".badge--live:has(.pulse)::before { content: none; }" in css


def test_the_react_sidebar_has_no_attack_service_link_until_the_gateway_routes_it():
    assert 'aria-label="Attack Service"' not in (SRC / "shell.tsx").read_text(encoding="utf-8")
