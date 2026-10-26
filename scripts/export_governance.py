#!/usr/bin/env python3
"""Build the Governance Center data from the framework reference file, the threat catalog, the EVAL data and the Risk seed. Nothing is invented: a relationship
exists only where learning/academy/framework_refs.json records one, a control's evidence is only the decisions recorded in committed runs, and owner, review,
attestation, verification and compliance are shown as not assigned or not made. Run with PYTHONPATH=src after export_evals.py and export_risk.py."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import assurance_model as A  # noqa: E402
import governance_model as V  # noqa: E402

OUT = ROOT / "academy-ui" / "src" / "content" / "governance" / "index.json"
J = lambda p: json.loads((ROOT / p).read_text(encoding="utf-8"))
src = lambda f, loc: {"file": f, "sha256": A.sha256_file(f), "locator": loc}
REFS = "learning/academy/framework_refs.json"
DISTINCTIONS = [
    ("Framework relevance", "A framework names a risk or technique the scenario resembles. It says nothing about whether anything was done.", "relationships"),
    ("Proposed control mapping", "A person or the lab proposes that a control relates to a framework item. The reference file marks each relationship PROPOSED or RELATED.", "relationships"),
    ("Observed technical evidence", "A decision or event recorded in a committed run.", "controls[].recorded_decisions"),
    ("Evaluation outcome", "What an EVAL Center experiment produced. One recorded run, not a rate.", "findings"),
    ("Analyst assessment", "A person's impact, likelihood and treatment. It lives in the Risk Center's local draft and is never held or shown here.", None),
    ("Control attestation", "A named owner stating a control operates. None is recorded for any control.", None),
    ("Independent verification", "A verifier receipt for the evidence. None applies to any run.", None),
    ("Formal compliance or certification", "A conclusion by a qualified assessor against a framework. None exists and none is claimed.", None),
]


def build() -> dict:
    refs, cat = J(REFS), J("learning/level_1/LAB-THREAT-MODELING-001/threat-catalog.json")
    seed, evals = J("academy-ui/src/content/risk/seed.json"), J("academy-ui/src/content/evals/index.json")
    exps = {e["id"]: J(f"academy-ui/src/content/evals/exp-{e['id']}.json") for e in evals["experiments"]}
    items = {(i["framework"], i["id"]): i for i in refs["items"]}
    cands = {c["id"]: c for c in seed["candidates"]}
    rel_by_threat: dict[str, dict] = {}
    for e in exps.values():
        for m in e["mappings"]:
            rel_by_threat.setdefault(e["threat"]["id"], {})[(m["framework"], m["id"])] = {**m, "via_experiment": e["id"]}
    relationships = {}
    for t, d in rel_by_threat.items():
        for k, m in d.items():
            relationships.setdefault(k, m)
    controls: dict[str, dict] = {}
    threats = []
    for t in cat["threats"]:
        c = cands[t["id"]]
        rels = [rel_by_threat.get(t["id"], {})[k] for k in sorted(rel_by_threat.get(t["id"], {}))]
        findings = [{"id": f["id"], "title": f["title"], "experiment": f["experiment"]} for f in c["evidence"]["findings"]]
        threats.append({"id": t["id"], "title": t["category"], "question": t["question"], "mapped": bool(rels),
                        "relationships": [{k: r[k] for k in ("framework", "id", "name", "relationship", "rationale", "via_experiment")} for r in rels],
                        "controls": [{"id": x["id"], "class": x["class"]} for x in c["controls"]], "findings": findings, "experiments": [e["id"] for e in c["evidence"]["experiments"]],
                        "evidence_classes": sorted({e["evidence_class"] for e in c["evidence"]["experiments"]}), "gaps": c["derived"]["gaps"],
                        "risk": {"id": c["id"], "note": "Impact, likelihood and treatment are entered in the Risk Center's local draft and are not held here."}})
        for x in c["controls"]:
            k = controls.setdefault(x["id"], {"id": x["id"], "class": x["class"], "placement": x["placement"], "code_reference": x["code_reference"], "threats": [], "recorded_decisions": [], "findings": []})
            k["threats"].append(t["id"])
            k["recorded_decisions"] += [d for d in x["recorded_decisions"] if d not in k["recorded_decisions"]]
            k["findings"] += [f["id"] for f in c["evidence"]["findings"] if f["id"] not in k["findings"]]
    for k in controls.values():
        k["evidence_state"] = "RECORDED_DECISIONS_EXIST" if k["recorded_decisions"] else "NO_RECORDED_EVIDENCE"
        k.update(V.NOT_ASSERTED)
    by_fw: dict[str, list] = {}
    for i in refs["items"]:
        by_fw.setdefault(i["framework"], []).append({k: i[k] for k in ("id", "name", "status", "source_url", "version_or_date", "limits")})
    mapped_ids = set(relationships)
    fws = [{"name": n, "status": "REFERENCED", "items": v, "mapped_relationships": sum(1 for (f, _) in mapped_ids if f == n)} for n, v in by_fw.items()]
    fws.append({"name": "NIST AI RMF", "status": "NOT_VERIFIED_IN_THIS_REPOSITORY", "items": [], "mapped_relationships": 0,
                "reason": "The repository's mapping model allows it as educational tags only, and the framework claim audit records NIST as unmapped on every Academy surface. No identifier is verified here, so none is listed and none is mapped.",
                "sources": [src("docs/FRAMEWORK_MAPPING_MODEL.md", "allowed frameworks table"), src("docs/AGENTSEC_FRAMEWORK_CLAIM_AUDIT.md", "NIST row")]})
    rel_list = [{**{k: m[k] for k in ("framework", "id", "name", "verification_status", "relationship", "rationale", "limits", "version_or_date", "source_url", "claims_compliance")}, "threats": sorted(t for t, d in rel_by_threat.items() if (m["framework"], m["id"]) in d)} for m in relationships.values()]
    unm = [t["id"] for t in threats if not t["mapped"]]
    g = {"schema": "agentsec.governance.v1", "title": "Governance and Compliance Center", "distinctions": [{"name": a, "meaning": b, "where": c} for a, b, c in DISTINCTIONS],
         "frameworks": fws, "relationships": rel_list, "threats": threats, "controls": sorted(controls.values(), key=lambda c: c["id"]),
         "gaps": {"unmapped_threats": unm, "controls_without_recorded_evidence": [c["id"] for c in controls.values() if c["evidence_state"] == "NO_RECORDED_EVIDENCE"], "threats_without_evaluation_evidence": [t["id"] for t in threats if not t["experiments"]],
                  "frameworks_not_mapped": [f["name"] for f in fws if f["mapped_relationships"] == 0], "owners_assigned": 0, "controls_attested": 0, "independently_verified_runs": 0,
                  "statement": "No control has an owner, a review, an attestation or independent verification on record, and no compliance assertion exists."},
         "sources": [src(REFS, "items, lab_references"), src("learning/level_1/LAB-THREAT-MODELING-001/threat-catalog.json", "threats"), src("academy-ui/src/content/risk/seed.json", "candidates"), src("academy-ui/src/content/evals/index.json", "experiments, findings")]}
    errs = V.validate(g, refs)
    if errs:
        raise SystemExit("governance data is not valid:\n  " + "\n  ".join(errs))
    return g


def main() -> None:
    data = json.dumps(build(), ensure_ascii=False, indent=1) + "\n"
    if "--check" in sys.argv:
        raise SystemExit(0 if OUT.is_file() and OUT.read_text(encoding="utf-8") == data else "the committed governance data differs from its sources")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(data, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}: {len(data)} bytes")


if __name__ == "__main__":
    main()
