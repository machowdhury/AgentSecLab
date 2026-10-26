#!/usr/bin/env python3
"""Build the Risk Center's source-backed seed from the threat catalog, the architecture, the asset inventory and the EVAL Center data.

Only source-backed and derived fields are produced. Impact, likelihood, owner, treatment and review are analyst fields and are never written here.
Run with PYTHONPATH=src after scripts/export_evals.py, then rebuild the UI.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import assurance_model as A  # noqa: E402
import risk_model as R  # noqa: E402

OUT = ROOT / "academy-ui" / "src" / "content" / "risk" / "seed.json"
EV = "academy-ui/src/content/evals/"
TM = "learning/level_1/LAB-THREAT-MODELING-001/"
J = lambda p: json.loads((ROOT / p).read_text(encoding="utf-8"))
src = lambda f, loc: {"file": f, "sha256": A.sha256_file(f), "locator": loc}


def seed_hash(seed: dict) -> str:
    return R.risks_sha256({k: v for k, v in seed.items() if k != "canonical_sha256"})


def build() -> dict:
    cat, arch = J(TM + "threat-catalog.json"), J(TM + "architecture.json")
    idx = J(EV + "index.json")
    exps = {e["id"]: J(EV + f"exp-{e['id']}.json") for e in idx["experiments"]}
    inv = J("learning/level_1/LAB-ASSET-INVENTORY/inventory.packet.json")
    names = {x["id"]: {"id": x["id"], "name": x["name"], "status": x["status"]} for x in arch["components"] + arch["actors"]}
    assets = {a["id"]: a for a in arch["assets"]}
    bounds = {b["id"]: b for b in arch["trust_boundaries"]}
    findings = {f["id"]: f for f in idx["findings"]}
    method = J("learning/academy/risk/methodology.json")
    for q in (method["source_rule"],):
        from export_assurance import quote
        quote(q["file"], q["text"])
    cands = []
    for t in cat["threats"]:
        linked = [e for e in exps.values() if e["threat"]["id"] == t["id"]]
        cases = [c for e in linked for c in e["cases"]]
        fids = [f for e in linked for f in e["findings"]]
        controls = []
        for c in t["existing_controls"]:
            rec = [{"experiment": e["id"], "case": k["id"], "role": k["role"], "decision": d["decision"], "reason": d["reason"]}
                   for e in linked for k in e["cases"] for d in k["facts"].get("decisions", []) if d.get("control") == c["id"]]
            controls.append({"id": c["id"], "class": c["class"], "placement": c["placement"], "code_reference": c["evidence"], "recorded_decisions": rec,
                             "evidence_note": ("These are decision events recorded in committed runs. They are not an assessment of how well the control works." if rec else "No recorded decision for this control appears in the linked experiments.")})
        comps = {}
        for b in t["boundaries"]:
            for cid in bounds[b]["between"]:
                comps[cid] = names[cid]
        lim = list(dict.fromkeys([x for e in linked for x in e["limitations"]] + [x for k in cases for x in k["limitations"]]))
        maps = {}
        for e in linked:
            for m in e["mappings"]:
                maps[(m["framework"], m["id"])] = m
        gaps = []
        if not linked: gaps.append("No evaluation experiment is linked to this threat, so there is no recorded test evidence for it.")
        elif not fids: gaps.append("Experiments are linked but no finding was derived from them.")
        gaps += [f"{c['id']}: no recorded decision in the linked experiments." for c in controls if not c["recorded_decisions"]]
        if linked and not any(k["verification"]["status"] == "VERIFIED" for k in cases): gaps.append("No linked test case has a verifier receipt.")
        if linked and all(e["evidence_class"] == "SIMULATED" for e in linked): gaps.append("The only linked evidence is simulated.")
        gaps.append(t["gap"])
        cand = {"id": t["id"], "origin": "seed", "title": t["category"], "threat_scenario": t["question"],
                "system": {"name": arch["scenario"], "components": list(comps.values())},
                "assets": [assets[a] for a in t["assets"]],
                "boundaries": [{"id": b, "name": bounds[b]["name"], "question": bounds[b]["question"]} for b in t["boundaries"]],
                "controls": controls, "telemetry_required": t["telemetry_required"], "documented_gap": t["gap"], "documented_residual_risk": t["residual_risk"],
                "evidence": {"experiments": [{"id": e["id"], "title": e["title"], "evidence_class": e["evidence_class"], "status": e["status"]} for e in linked],
                             "findings": [{k: findings[f][k] for k in ("id", "title", "rule", "observed", "expected", "matches_documented", "match_basis", "evidence", "limitations", "verification")} | {"experiment": findings[f]["experiment"]} for f in fids],
                             "cases": [{"id": k["id"], "role": k["role"], "evidence_class": k["evidence_class"], "verification": k["verification"], "statement": k["statement"]} for k in cases],
                             "limitations": lim, "mappings": list(maps.values())},
                "derived": {"has_linked_evidence": bool(linked), "has_linked_findings": bool(fids), "controls_without_recorded_evidence": [c["id"] for c in controls if not c["recorded_decisions"]], "gaps": gaps},
                "sources": [src(TM + "threat-catalog.json", f"threats[{t['id']}]"), src(TM + "architecture.json", "assets, trust_boundaries, components")] + [src(EV + f"exp-{e['id']}.json", "linked experiment") for e in linked]}
        if t["id"] == "TM-T07":
            comp = inv["components"]
            cand["inventory"] = {"note": "From the documented component list. It was not measured, and it is not an AI-BOM.", "components": len(comp), "owner_not_recorded": [c["name"] for c in comp if c["owner"] == "NOT RECORDED"],
                                 "source": src("learning/level_1/LAB-ASSET-INVENTORY/inventory.packet.json", "components")}
            cand["sources"].append(cand["inventory"]["source"])
        cands.append(cand)
    seed = {"schema": "agentsec.risk_seed.v1", "title": "Source-backed risk candidates", "methodology": method, "candidates": cands,
            "field_origins": {"source": ["id", "title", "threat_scenario", "system", "assets", "boundaries", "controls", "telemetry_required", "documented_gap", "documented_residual_risk", "evidence", "inventory"],
                              "derived": ["derived", "controls[].recorded_decisions", "evidence.findings", "evidence.cases"], "analyst": ["assessment", "owner", "treatment", "review"]},
            "note": "No candidate carries an impact, likelihood, owner, treatment or review. Those are entered by a person."}
    errs = R.validate_seed(seed)
    if errs:
        raise SystemExit("risk seed is not valid:\n  " + "\n  ".join(errs))
    seed["canonical_sha256"] = seed_hash(seed)
    return seed


def main() -> None:
    data = json.dumps(build(), ensure_ascii=False, indent=1) + "\n"
    if "--check" in sys.argv:
        raise SystemExit(0 if OUT.is_file() and OUT.read_text(encoding="utf-8") == data else "the committed risk seed differs from its sources; re-run scripts/export_risk.py")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(data, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}: {len(data)} bytes")


if __name__ == "__main__":
    main()
