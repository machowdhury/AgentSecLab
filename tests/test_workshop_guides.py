"""Every workshop says what you should see, what the defense teaches, how you know you are done and what to do when it does not look right."""
import importlib.util
import json
from pathlib import Path

from agentsec.lab_registry import load_registry

ROOT = Path(__file__).resolve().parents[1]
GUIDES = json.loads((ROOT / "learning/academy/workshop_guides.json").read_text(encoding="utf-8"))["guides"]


def _builder():
    spec = importlib.util.spec_from_file_location("build_workshop_guides", ROOT / "scripts/build_workshop_guides.py")
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m


def test_every_registered_workshop_has_a_complete_guide():
    ids = {e["lab_id"] for e in load_registry()["entries"]}
    assert set(GUIDES) == ids and len(ids) == 32
    for lab, g in GUIDES.items():
        assert g["kind"] in ("live", "recorded", "simulated packet"), lab
        assert len(g["expected"]) >= 2 and len(g["defensive"]) >= 1 and len(g["completion"]) >= 2 and len(g["troubleshooting"]) >= 2, lab
        for t in g["troubleshooting"]:
            assert t["symptom"].strip() and t["fix"].strip(), lab
        assert all(isinstance(x, str) and x.strip() for k in ("expected", "defensive", "completion") for x in g[k]), lab


def test_the_committed_file_is_exactly_what_the_builder_writes():
    assert json.loads(json.dumps(_builder().build()["guides"])) == GUIDES


def test_live_guides_quote_the_labs_own_prediction_and_the_other_kinds_claim_no_execution():
    for lab, g in GUIDES.items():
        pred = json.loads((ROOT / "learning/level_1" / lab / "lab-manifest.json").read_text())["prediction"] if (ROOT / "learning/level_1" / lab / "lab-manifest.json").exists() else None
        if g["kind"] == "live" and pred and "BASELINE" in pred and pred["BASELINE"].get("expected_evidence_defended"):
            assert any(pred["ATTACK"]["expected_evidence_vulnerable"] in x for x in g["expected"]), lab
        if g["kind"] == "simulated packet":
            assert any("By design" in t["fix"] and "enforces nothing" in t["fix"] for t in g["troubleshooting"]), lab


def test_the_guide_reaches_the_academy_content_and_the_page_renders_it():
    data = json.loads((ROOT / "academy-ui/src/content/curriculum.json").read_text(encoding="utf-8"))
    assert {l["id"]: l["guide"] for l in data["labs"]} == GUIDES
    page = (ROOT / "academy-ui/src/pages/Lab.tsx").read_text(encoding="utf-8")
    for needle in ("What you should see", "What the defense teaches", "You are done when", "If something does not look right"):
        assert needle in page


def test_the_ctf_challenges_are_reachable_from_the_academy():
    root = ROOT / "academy-ui/src"
    assert "CHALLENGES_PATH" in (root / "router.tsx").read_text() and "CTF Challenges" in (root / "shell.tsx").read_text()
    page = (root / "pages/Challenges.tsx").read_text(encoding="utf-8")
    assert "/api/ctf/challenges" in page and "SIMULATED" in page or "simulation" in page
    assert "not multi-user" in page.lower()
