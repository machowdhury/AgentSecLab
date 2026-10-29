"""The MAESTRO threat-modeling workbench: the content is grounded in the repository and in CSA's article, the worked example satisfies its own rubric, and the
rubric and the report behave (the pure TypeScript the Academy runs is executed in Node)."""
import copy
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from agentsec.lab_registry import load_registry

ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / "learning/level_1/LAB-THREAT-MODELING-001"
M = json.loads((LAB / "maestro.json").read_text(encoding="utf-8"))
RISK = json.loads((ROOT / "learning/academy/risk/methodology.json").read_text(encoding="utf-8"))
ARCH = json.loads((LAB / "architecture.json").read_text(encoding="utf-8"))
DATA = {**M, "risk": {k: RISK[k] for k in ("impact", "likelihood", "matrix")}}
OFFICIAL_LAYERS = ["Foundation Models", "Data Operations", "Agent Frameworks", "Deployment and Infrastructure", "Evaluation and Observability", "Security and Compliance", "Agent Ecosystem"]
LEVELS = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
lvl = lambda j: RISK["matrix"][j["impact"]][j["likelihood"]]


def test_layers_are_the_seven_of_the_csa_article_and_cite_primary_sources():
    fw = M["framework"]
    assert [(l["n"], l["name"]) for l in fw["layers"]] == list(enumerate(OFFICIAL_LAYERS, 1))
    assert [l["n"] for l in fw["layers"] if l["vertical"]] == [6]
    assert [len(l["official_threats"]) for l in fw["layers"]] == [7, 5, 6, 6, 6, 7, 13]
    assert len(fw["method"]) == 6 and fw["cross_layer_threats"][-1] == "Goal Misalignment Cascades"
    urls = {s["url"] for s in fw["sources"]}
    assert "https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro" in urls and "https://github.com/CloudSecurityAlliance/MAESTRO" in urls
    assert "NOT RUN" in M["analyzer"]["status_here"] and "no version" not in json.dumps(fw).lower() or fw["version"] == "none stated by CSA"


def test_every_element_is_placed_on_a_real_layer_and_points_at_files_that_exist():
    ids = {c["id"] for c in ARCH["components"]}
    els = M["acmebank"]["elements"]
    assert {e["layer"] for e in els} == set(range(1, 8)), "every layer has an element"
    for e in els:
        assert 1 <= e["layer"] <= 7 and all(1 <= a <= 7 for a in e["also"]), e["id"]
        for f in e["evidence"]:
            assert (ROOT / f).exists(), (e["id"], f)
        if e["id"].startswith("CMP-"):
            assert e["id"] in ids, e["id"]          # the architecture file's own component
    assert ids <= {e["id"] for e in els}, "every architecture component is decomposed"
    ab = {b["id"] for b in ARCH["trust_boundaries"]}
    assert ab <= {b["id"] for b in M["acmebank"]["boundaries"]}
    flows = {f["id"] for f in ARCH["data_flows"]}
    assert flows <= {i["id"] for i in M["acmebank"]["interactions"]}
    known = {e["id"] for e in els}
    for i in M["acmebank"]["interactions"]:
        assert i["from"] in known and i["to"] in known, i["id"]


def test_controls_and_scenarios_exist_in_the_repository_and_the_registry():
    src = "\n".join(p.read_text(errors="ignore") for p in (ROOT / "src/agentsec").rglob("*.py"))
    for c in M["acmebank"]["controls"]:
        if c["id"].startswith("CTRL-"):
            assert c["id"] in src, c["id"]
    reg = {e["lab_id"]: e for e in load_registry()["entries"]}
    for s in M["acmebank"]["scenarios"]:
        assert s["lab_id"] in reg, s["lab_id"]
        layers = {l["n"]: l for l in M["framework"]["layers"]}
        for label in s["labels"]:
            assert any(label in l["official_threats"] for l in layers.values()), (s["lab_id"], label)
    assert {s["family"] for s in M["acmebank"]["scenarios"]} >= set(M["families"])


def test_the_worked_example_is_internally_consistent():
    layers = {l["n"]: l for l in M["framework"]["layers"]}
    reg = M["example"]["register"]
    ctrl = {c["id"] for c in M["acmebank"]["controls"]}
    scen = {s["lab_id"] for s in M["acmebank"]["scenarios"]}
    elements = {e["id"] for e in M["acmebank"]["elements"]}
    assert len({t["id"] for t in reg}) == len(reg) and {t["layer"] for t in reg} == set(range(1, 8))
    for t in reg:
        assert (t["label"] in layers[t["layer"]]["official_threats"]) != t["custom"], t["id"]
        assert set(t["controls"]) <= ctrl and set(t["scenarios"]) <= scen and set(t["elements"]) <= elements, t["id"]
        assert LEVELS[lvl(t["residual"])] <= LEVELS[lvl(t["inherent"])], t["id"]
        assert t["evidence"] in ("DEMONSTRATED", "DOCUMENTED", "ASSUMED") and (t["evidence"] != "DEMONSTRATED" or t["scenarios"]), t["id"]
        assert t["inherent"]["rationale"] and t["residual"]["rationale"] and t["mitigation"], t["id"]
    for p in M["example"]["paths"]:
        assert len(p["steps"]) >= 3 and len({s["layer"] for s in p["steps"]}) >= 3, p["id"]
        by = {t["id"]: t for t in reg}
        assert all(by[s["threat"]]["layer"] == s["layer"] for s in p["steps"]), p["id"]
    assert "NOT PROVEN" in json.dumps(reg) and "NOT MODELED" in M["example"]["scope"]


def test_the_academy_content_is_exported_from_the_source_with_the_risk_centers_matrix():
    assert json.loads((ROOT / "academy-ui/src/content/maestro.json").read_text(encoding="utf-8")) == DATA


node = pytest.mark.skipif(shutil.which("node") is None, reason="needs Node (type stripping) to run the Academy's TypeScript")


def run_node(cases):
    p = subprocess.run(["node", str(ROOT / "tests/maestro_check.mjs")], input=json.dumps({"data": DATA, "cases": cases}), capture_output=True, text=True, cwd=ROOT, timeout=60)
    assert p.returncode == 0, p.stderr
    return json.loads(p.stdout)


def example_model():
    return {"scope": M["example"]["scope"], "placements": {e["id"]: e["layer"] for e in M["acmebank"]["elements"]},
            "boundaries": {b["id"]: {"found": True, "layers": b["layers"]} for b in M["acmebank"]["boundaries"]}, "threats": copy.deepcopy(M["example"]["register"]),
            "paths": [{k: p[k] for k in ("id", "name", "narrative", "steps")} for p in copy.deepcopy(M["example"]["paths"])]}


def states(out):
    return {r["id"]: r["state"] for r in out["assess"]["results"]}


@node
def test_the_worked_example_meets_every_criterion_and_a_blank_model_meets_none():
    out = run_node({"example": "example", "empty": "empty"})
    assert out["example"]["assess"]["applied"] is True and set(states(out["example"]).values()) == {"MET"} and len(states(out["example"])) == 8
    assert out["empty"]["assess"]["applied"] is False and set(states(out["empty"]).values()) == {"NOT MET"}


@node
def test_each_criterion_fails_for_the_defect_it_names():
    base = example_model()
    c = {}
    m = copy.deepcopy(base); m["placements"] = {k: 1 for k in m["placements"]}; c["layers_wrong"] = m
    m = copy.deepcopy(base); m["boundaries"] = {k: v for k, v in list(m["boundaries"].items())[:3]}; c["few_boundaries"] = m
    m = copy.deepcopy(base); m["threats"] = [t for t in m["threats"] if t["layer"] != 5]; c["no_layer5"] = m
    m = copy.deepcopy(base); m["threats"][0]["label"] = "Not An Official Label"; c["bad_label"] = m
    m = copy.deepcopy(base); m["paths"] = m["paths"][:1]; c["one_path"] = m
    m = copy.deepcopy(base); [pp["steps"][0].update(layer=5) for pp in m["paths"]]; c["path_layer_mismatch"] = m
    m = copy.deepcopy(base); m["threats"][0]["residual"] = {"impact": "HIGH", "likelihood": "LIKELY", "rationale": "worse than before somehow"}; m["threats"][0]["inherent"] = {"impact": "LOW", "likelihood": "UNLIKELY", "rationale": "start low then end high"}; c["residual_above_inherent"] = m
    m = copy.deepcopy(base); [t.update(scenarios=[]) for t in m["threats"]]; c["no_scenarios"] = m
    m = copy.deepcopy(base); m["threats"][1]["evidence"] = ""; c["no_evidence_status"] = m
    out = run_node(c)
    s = lambda k: states(out[k])
    assert s("layers_wrong")["R1"] != "MET" and s("few_boundaries")["R2"] != "MET" and s("no_layer5")["R3"] != "MET" and s("bad_label")["R3"] != "MET"
    assert s("one_path")["R4"] == "PARTIAL" and s("path_layer_mismatch")["R4"] != "MET" and s("residual_above_inherent")["R5"] != "MET"
    assert s("no_scenarios")["R7"] == "NOT MET" and s("no_scenarios")["R6"] != "MET" and s("no_evidence_status")["R6"] != "MET"
    for k in c:
        assert out[k]["assess"]["applied"] is False or k in ("no_evidence_status",), k    # a defect in R6 only advises


@node
def test_a_custom_threat_needs_a_reason_and_the_ranking_is_inherent_then_residual():
    m = example_model()
    m["threats"][11]["description"] = "short"          # EX-T12 is custom
    out = run_node({"custom": m, "example": "example"})
    assert states(out["custom"])["R3"] != "MET"
    rank = out["example"]["rank"]
    first = lambda i: LEVELS[lvl(next(t for t in M["example"]["register"] if t["id"] == i)["inherent"])]
    assert [first(i) for i in rank] == sorted((first(i) for i in rank), reverse=True)


@node
def test_the_report_is_plain_escaped_text_with_every_section_the_method_asks_for():
    m = example_model()
    m["threats"][0]["description"] = "bad | pipe\nnewline <script>alert(1)</script> `tick`"
    m["scope"] = "# injected heading\n<img src=x onerror=alert(1)>\n```\n---\n   ## indented"
    m["threats"][1]["inherent"]["impact"] = "HIGH\n| x |"
    out = run_node({"x": m})
    md = out["x"]["md"]
    for h in ("# MAESTRO threat model", "## 1. Scope", "## 2. Decomposition by layer", "## 3. Trust boundaries", "## 4. Threat register", "## 5. Cross-layer attack paths", "## 6. Residual risk summary", "## 7. Self-check", "## 8. Compare with the official MAESTRO Threat Analyzer", "## 9. Limits"):
        assert h in md, h
    assert "<script>" not in md and "<img" not in md and "\n# injected heading" not in md and "bad \\| pipe" in md
    assert "\n```\n---" not in md and "\n   ## indented" not in md and "HIGH\n| x |" not in md
    assert "LOCAL_DRAFT_NOT_APPROVED" in md and "not a certification" in md and "Cloud Security Alliance" in md and "NOT RUN" in md
    doc = out["x"]["doc"]
    assert doc["status"] == "LOCAL_DRAFT_NOT_APPROVED" and doc["schema"] == "agentsec.maestro_threat_model.v1" and doc["integrity"]["algorithm"] == "sha256"
    assert out["__cell"] == ["a\\|b c&lt;script&gt;", "—"]
