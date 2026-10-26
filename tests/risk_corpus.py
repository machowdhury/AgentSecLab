"""Documents shared by the Python and browser tests: the same file must get the same error codes from both validators."""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import risk_model as R  # noqa: E402

SEED = json.loads((ROOT / "academy-ui/src/content/risk/seed.json").read_text(encoding="utf-8"))
IDS = [c["id"] for c in SEED["candidates"]]
SEED_IDS = set(IDS)


def doc(risks, **over):
    d = {"schema": R.SCHEMA, "methodology_version": R.METHOD["version"], "status": R.STATUS, "seed_sha256": SEED["canonical_sha256"],
         "integrity": {"algorithm": "sha256", "risks_sha256": R.risks_sha256(risks), "note": "checksum"}, "risks": risks}
    d.update(over)
    if "risks" in over:
        d["integrity"]["risks_sha256"] = R.risks_sha256(d["risks"])
    return d


def derived(r):
    r["derived"] = R.derive(r)
    return r


def blank_all():
    return [R.blank_risk(i) for i in IDS]


def assessed():
    rs = blank_all()
    a = rs[3]
    a["assessment"]["inherent"] = {"impact": "HIGH", "likelihood": "POSSIBLE", "rationale": "Four recorded vulnerable runs executed; no production data."}
    a["assessment"]["residual"] = {"impact": "HIGH", "likelihood": "UNLIKELY", "rationale": "Defended retests denied; one recorded run each.", "controls_considered": ["CTRL-MCP-001"]}
    a["owner"] = "Platform security lead"
    a["treatment"] = {"strategy": "MITIGATE", "notes": "Model downstream authorization.", "actions": [{"id": "A1", "text": "Add row-level checks", "owner": None, "status": "PROPOSED", "evidence_note": ""}], "approval": None}
    a["review"] = {"status": "AWAITING_REVIEW", "reviewer": None, "note": "", "at": None, "history": [{"at": "2026-10-27T10:00:00Z", "event": "Marked awaiting review", "note": ""}]}
    derived(a)
    c = R.blank_risk("custom-1", "custom")
    c["origin"] = "custom"; c["custom"] = {"title": "Plugin supply risk", "category": "Supply chain", "system": "Assistant plugins", "scenario": "A plugin changes behaviour.", "assets": "Customer data"}
    return rs + [c]


def mutate(f, base=None):
    rs = copy.deepcopy(base or assessed())
    f(rs)
    return doc(rs)


def _acc(rs):
    rs[0]["treatment"]["strategy"] = "ACCEPT"


CASES: list[tuple[str, dict]] = [
    ("valid-blank", doc(blank_all())),
    ("valid-assessed", doc(assessed())),
    ("schema", doc(blank_all(), schema="other")),
    ("status-approved", doc(blank_all(), status="APPROVED")),
    ("method-version", doc(blank_all(), methodology_version=2)),
    ("bad-seed-hash", doc(blank_all(), seed_sha256="xyz")),
    ("extra-top-key", doc(blank_all(), approved=True)),
    ("integrity-mismatch", {**doc(blank_all()), "integrity": {"algorithm": "sha256", "risks_sha256": "0" * 64, "note": "x"}}),
    ("risks-not-list", {**doc(blank_all()), "risks": {}}),
    ("unknown-seed", mutate(lambda rs: rs[0].update(id="TM-T99"))),
    ("duplicate-id", mutate(lambda rs: rs[1].update(id=rs[0]["id"]))),
    ("reserved-id", mutate(lambda rs: rs[-1].update(id="register"))),
    ("bad-id", mutate(lambda rs: rs[-1].update(id="bad id!"))),
    ("origin", mutate(lambda rs: rs[0].update(origin="other"))),
    ("seed-with-custom", mutate(lambda rs: rs[0].update(custom={"title": "x", "category": "", "system": "", "scenario": "", "assets": ""}))),
    ("custom-no-title", mutate(lambda rs: rs[-1]["custom"].update(title="  "))),
    ("scale-impact", mutate(lambda rs: rs[3]["assessment"]["inherent"].update(impact="SEVERE"))),
    ("scale-likelihood", mutate(lambda rs: rs[3]["assessment"]["inherent"].update(likelihood="CERTAIN"))),
    ("pair", mutate(lambda rs: rs[3]["assessment"]["inherent"].update(likelihood=None))),
    ("no-rationale", mutate(lambda rs: rs[3]["assessment"]["inherent"].update(rationale="  "))),
    ("residual-without-inherent", mutate(lambda rs: rs[3]["assessment"]["inherent"].update(impact=None, likelihood=None, rationale=""))),
    ("derived-tamper", mutate(lambda rs: rs[3]["derived"].update(inherent_level="LOW"))),
    ("derived-score", mutate(lambda rs: rs[3]["derived"].update(inherent_level=7))),
    ("controls-type", mutate(lambda rs: rs[3]["assessment"]["residual"].update(controls_considered="all"))),
    ("owner-type", mutate(lambda rs: rs[3].update(owner=5))),
    ("strategy", mutate(lambda rs: rs[3]["treatment"].update(strategy="IGNORE"))),
    ("approval-on-mitigate", mutate(lambda rs: rs[3]["treatment"].update(approval={"by": "A", "role": "B", "at": "2026-10-27T10:00:00Z", "note": "ok"}))),
    ("approval-incomplete", mutate(lambda rs: rs[3]["treatment"].update(strategy="ACCEPT", approval={"by": "A", "role": " ", "at": "x", "note": "ok"}))),
    ("action-status", mutate(lambda rs: rs[3]["treatment"]["actions"][0].update(status="APPROVED"))),
    ("action-completed-no-evidence", mutate(lambda rs: rs[3]["treatment"]["actions"][0].update(status="COMPLETED"))),
    ("action-duplicate", mutate(lambda rs: rs[3]["treatment"]["actions"].append(dict(rs[3]["treatment"]["actions"][0])))),
    ("review-approved", mutate(lambda rs: rs[3]["review"].update(status="APPROVED"))),
    ("review-reviewed-incomplete", mutate(lambda rs: rs[3]["review"].update(status="REVIEWED"))),
    ("history-type", mutate(lambda rs: rs[3]["review"].update(history="none"))),
    ("missing-key", mutate(lambda rs: rs[3].pop("owner"))),
    ("extra-risk-key", mutate(lambda rs: rs[3].update(severity="HIGH"))),
    ("text-too-long", mutate(lambda rs: rs[3]["treatment"].update(notes="x" * 2001))),
    ("treatment-claims-complete", mutate(lambda rs: rs[3]["treatment"].update(completed=True))),
]
