"""Phase 12C: the Risk Center's source-backed seed, qualitative method and assessment schema.

The seed is rebuilt from the threat catalog, the architecture, the asset inventory and the EVAL Center data by code that is separate from the exporter. The
validator tests prove that impact, likelihood, owners, treatment and review are human inputs, that a control test result never sets a residual level, and that no
document can claim an approval it does not record.
"""
from __future__ import annotations

import copy
import itertools
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT))
import export_risk as X  # noqa: E402
import risk_model as R  # noqa: E402
from tests.risk_corpus import CASES, IDS, SEED, SEED_IDS, assessed, blank_all, doc  # noqa: E402

J = lambda p: json.loads((ROOT / p).read_text(encoding="utf-8"))
CAT = J("learning/level_1/LAB-THREAT-MODELING-001/threat-catalog.json")
ARCH = J("learning/level_1/LAB-THREAT-MODELING-001/architecture.json")
EV = ROOT / "academy-ui/src/content/evals"
codes = lambda d: sorted({c for c, _, _ in R.validate_assessment(d, SEED_IDS)})


def test_seed_is_valid_deterministic_and_self_hashed():
    assert (ROOT / "academy-ui/src/content/risk/seed.json").read_text(encoding="utf-8") == json.dumps(X.build(), ensure_ascii=False, indent=1) + "\n"
    assert R.validate_seed(SEED) == [] and SEED["canonical_sha256"] == X.seed_hash(SEED)
    assert IDS == [t["id"] for t in CAT["threats"]] and len(IDS) == 9


def test_source_facts_are_the_catalog_and_architecture_verbatim():
    comps = {x["id"]: x for x in ARCH["components"] + ARCH["actors"]}
    for c, t in zip(SEED["candidates"], CAT["threats"]):
        assert (c["title"], c["threat_scenario"], c["documented_gap"], c["documented_residual_risk"], c["telemetry_required"]) == (t["category"], t["question"], t["gap"], t["residual_risk"], t["telemetry_required"])
        assert [a["id"] for a in c["assets"]] == t["assets"] and all(a in ARCH["assets"] for a in c["assets"])
        assert [b["id"] for b in c["boundaries"]] == t["boundaries"]
        want = {cid for b in t["boundaries"] for x in ARCH["trust_boundaries"] if x["id"] == b for cid in x["between"]}
        assert {x["id"] for x in c["system"]["components"]} == want and all(x["name"] == comps[x["id"]]["name"] for x in c["system"]["components"])
        assert [x["id"] for x in c["controls"]] == [x["id"] for x in t["existing_controls"]] and [x["class"] for x in c["controls"]] == [x["class"] for x in t["existing_controls"]]
        for s in c["sources"]:
            assert s["sha256"] == R.A.sha256_file(s["file"])


def test_no_analyst_field_is_prefilled_anywhere_in_the_seed():
    text = json.dumps(SEED)
    for c in SEED["candidates"]:
        assert not ({"impact", "likelihood", "owner", "treatment", "residual", "inherent", "approval", "severity", "review"} & set(c))
        assert all("effectiveness" not in k for k in c["controls"])
    assert SEED["field_origins"]["analyst"] == ["assessment", "owner", "treatment", "review"]
    assert not re.search(r"\d\s*%|risk score:|risk rating:", text, re.I)


def test_evidence_links_are_recomputed_from_the_eval_data():
    idx = J("academy-ui/src/content/evals/index.json")
    exps = {e["id"]: json.loads((EV / f"exp-{e['id']}.json").read_text(encoding="utf-8")) for e in idx["experiments"]}
    for c in SEED["candidates"]:
        linked = [e for e in exps.values() if e["threat"]["id"] == c["id"]]
        assert [e["id"] for e in c["evidence"]["experiments"]] == [e["id"] for e in linked]
        want_f = [f["id"] for f in idx["findings"] if exps[f["experiment"]]["threat"]["id"] == c["id"]]
        assert [f["id"] for f in c["evidence"]["findings"]] == want_f and c["derived"]["has_linked_findings"] == bool(want_f) and c["derived"]["has_linked_evidence"] == bool(linked)
        assert [k["id"] for k in c["evidence"]["cases"]] == [k["id"] for e in linked for k in e["cases"]]
        for ctl in c["controls"]:
            rec = [(e["id"], k["role"], d["decision"]) for e in linked for k in e["cases"] for d in k["facts"].get("decisions", []) if d["control"] == ctl["id"]]
            assert [(x["experiment"], x["role"], x["decision"]) for x in ctl["recorded_decisions"]] == rec
            assert (ctl["id"] in c["derived"]["controls_without_recorded_evidence"]) == (not rec)
        assert all(k["verification"]["status"] == "NOT_VERIFIED" for k in c["evidence"]["cases"])
    assert [c["id"] for c in SEED["candidates"] if not c["derived"]["has_linked_evidence"]] == ["TM-T02", "TM-T03", "TM-T06", "TM-T08", "TM-T09"]
    assert [c["id"] for c in SEED["candidates"] if c["derived"]["has_linked_findings"]] == ["TM-T01", "TM-T04", "TM-T05", "TM-T07"]
    t07 = next(c for c in SEED["candidates"] if c["id"] == "TM-T07")
    inv = J("learning/level_1/LAB-ASSET-INVENTORY/inventory.packet.json")
    assert t07["inventory"]["owner_not_recorded"] == [x["name"] for x in inv["components"] if x["owner"] == "NOT RECORDED"] and t07["inventory"]["components"] == len(inv["components"])


def test_the_method_is_qualitative_complete_and_monotonic():
    m = R.METHOD
    assert set(m["matrix"]) == set(R.IMPACT) and all(set(v) == set(R.LIKELIHOOD) for v in m["matrix"].values()) and all(x in R.LEVELS for v in m["matrix"].values() for x in v.values())
    rk = lambda l: R.LEVELS.index(l)
    for i, l in itertools.product(range(3), range(3)):
        if i: assert rk(R.level(R.IMPACT[i], R.LIKELIHOOD[l])) >= rk(R.level(R.IMPACT[i - 1], R.LIKELIHOOD[l]))
        if l: assert rk(R.level(R.IMPACT[i], R.LIKELIHOOD[l])) >= rk(R.level(R.IMPACT[i], R.LIKELIHOOD[l - 1]))
    assert R.level(None, "POSSIBLE") is None and R.level("HIGH", None) is None and R.level("HIGH", "CERTAIN") is None and R.level("HIGH", "POSSIBLE") == "HIGH"
    assert not re.search(r"\d", json.dumps({k: m[k] for k in ("impact", "likelihood", "matrix", "levels", "treatment")}))
    q = m["source_rule"]
    assert q["text"] in (ROOT / q["file"]).read_text(encoding="utf-8")
    assert any("never lowers" in x or "never proposes" in x for x in m["rules"]) and "does not implement any standard" in m["statement"]


def test_levels_come_only_from_analyst_entries_never_from_control_evidence():
    rs = blank_all()
    for r in rs:
        assert R.derive(r) == {"inherent_level": None, "residual_level": None}
    t04 = next(c for c in SEED["candidates"] if c["id"] == "TM-T04")
    assert any(x["recorded_decisions"] for x in t04["controls"]), "recorded control evidence exists for this risk"
    assert R.derive(rs[3]) == {"inherent_level": None, "residual_level": None}, "...and it sets no level"
    src = (ROOT / "scripts/export_risk.py").read_text(encoding="utf-8")
    assert "R.level(" not in src and "derive(" not in src
    bad = copy.deepcopy(rs); bad[3]["derived"]["residual_level"] = "LOW"
    assert "DERIVED" in codes(doc(bad)), "a level that does not follow from the entries is rejected"


def test_the_two_blank_and_assessed_documents_are_valid():
    assert R.validate_assessment(doc(blank_all()), SEED_IDS) == [] and R.validate_assessment(doc(assessed()), SEED_IDS) == []


@pytest.mark.parametrize("name,d", [c for c in CASES if not c[0].startswith("valid")], ids=[c[0] for c in CASES if not c[0].startswith("valid")])
def test_every_invalid_document_is_rejected(name, d):
    assert codes(d), name


EXPECT = {
    "schema": "SCHEMA", "status-approved": "STATUS", "method-version": "METHOD_VERSION", "bad-seed-hash": "TYPE", "extra-top-key": "UNKNOWN_KEY", "integrity-mismatch": "INTEGRITY", "risks-not-list": "TYPE",
    "unknown-seed": "UNKNOWN_SEED", "duplicate-id": "DUPLICATE", "reserved-id": "ID", "bad-id": "ID", "origin": "ORIGIN", "seed-with-custom": "ORIGIN", "custom-no-title": "TITLE", "scale-impact": "SCALE",
    "scale-likelihood": "SCALE", "pair": "PAIR", "no-rationale": "RATIONALE", "residual-without-inherent": "RESIDUAL_NEEDS_INHERENT", "derived-tamper": "DERIVED", "derived-score": "DERIVED", "controls-type": "TYPE",
    "owner-type": "TYPE", "strategy": "STRATEGY", "approval-on-mitigate": "APPROVAL", "approval-incomplete": "APPROVAL", "action-status": "ACTION_STATUS", "action-completed-no-evidence": "ACTION_EVIDENCE",
    "action-duplicate": "DUPLICATE", "review-approved": "REVIEW_STATUS", "review-reviewed-incomplete": "REVIEW_FIELDS", "history-type": "TYPE", "missing-key": "MISSING_KEY", "extra-risk-key": "UNKNOWN_KEY",
    "text-too-long": "LIMIT", "treatment-claims-complete": "UNKNOWN_KEY",
}


@pytest.mark.parametrize("name,code", sorted(EXPECT.items()))
def test_each_rule_fires_with_its_own_code(name, code):
    d = dict(CASES)[name]
    assert code in codes(d), (name, codes(d))


def test_no_approval_or_completion_can_be_claimed_without_its_record():
    for name in ("status-approved", "review-approved", "review-reviewed-incomplete", "action-completed-no-evidence", "approval-on-mitigate", "approval-incomplete", "treatment-claims-complete", "action-status"):
        assert codes(dict(CASES)[name]), name
    ok = copy.deepcopy(assessed())
    ok[0]["treatment"] = {"strategy": "ACCEPT", "notes": "", "actions": [], "approval": {"by": "A. Reviewer", "role": "CISO", "at": "2026-10-27T10:00:00Z", "note": "Accepted for the lab"}}
    ok[1]["review"] = {"status": "REVIEWED", "reviewer": "B", "note": "read", "at": "2026-10-27T10:00:00Z", "history": []}
    ok[2]["treatment"]["actions"] = [{"id": "A1", "text": "t", "owner": None, "status": "COMPLETED", "evidence_note": "ticket 1"}]
    assert R.validate_assessment(doc(ok), SEED_IDS) == []


def test_integrity_checksum_detects_edits_and_is_the_canonical_json_hash():
    d = doc(assessed())
    assert d["integrity"]["risks_sha256"] == R.risks_sha256(d["risks"]) == __import__("hashlib").sha256(json.dumps(d["risks"], sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    d2 = copy.deepcopy(d); d2["risks"][3]["owner"] = "someone else"
    assert "INTEGRITY" in codes(d2)
    assert "not a signature" in (ROOT / "academy-ui/src/risk/store.ts").read_text(encoding="utf-8")


def test_risk_center_is_on_demand_and_the_code_calls_no_backend():
    assets = ROOT / "src/agentsec/static/learn/assets"
    main = next(assets.glob("index-*.js")).read_text(encoding="utf-8")
    assert "LOCAL_DRAFT_NOT_APPROVED" not in main and "Workshop qualitative risk method" not in main
    assert "LOCAL_DRAFT_NOT_APPROVED" in next(assets.glob("RiskCenter-*.js")).read_text(encoding="utf-8")
    assert len(list(assets.glob("seed-*.js"))) == 1
    for f in ("pages/RiskCenter.tsx", "risk/store.ts", "risk/validate.ts", "risk/parts.tsx", "risk/sha256.ts"):
        t = (ROOT / "academy-ui/src" / f).read_text(encoding="utf-8")
        for bad in ("fetch(", "XMLHttpRequest", "/api/", "WebSocket"):
            assert bad not in t, (f, bad)
