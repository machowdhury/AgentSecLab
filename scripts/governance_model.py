"""Validation for the Governance Center data, on top of the assurance and risk models.

Six things are kept apart and none is turned into another: framework relevance, a proposed control mapping, observed technical evidence, an evaluation outcome,
an analyst assessment (local to the Risk Center, so never held here) and an attestation or certification (none exists, so none is shown).
"""
from __future__ import annotations

import assurance_model as A

RELATIONSHIPS = ("PROPOSED", "RELATED")
NOT_ASSERTED = {"owner": "NOT ASSIGNED", "review": "NOT REVIEWED", "attestation": "NONE RECORDED", "independent_verification": "NONE", "compliance": "NO ASSERTION"}


def validate(g: dict, refs: dict) -> list[str]:
    errs = [f"{p}: a score, percentage or compliance-status field is not allowed" for p, k, _ in A._walk_keys(g) if A.FORBIDDEN_KEYS.search(k) or k in ("compliant", "compliance_status", "certified", "effectiveness")]
    known = {(i["framework"], i["id"]): i for i in refs["items"]}
    for m in g["relationships"]:
        i = known.get((m["framework"], m["id"]))
        if not i or (m["name"], m["verification_status"], m["limits"], m["source_url"]) != (i["name"], i["status"], i["limits"], i["source_url"]): errs.append(f"relationship {m['framework']} {m['id']} is not the reference file's")
        if m["relationship"] not in RELATIONSHIPS: errs.append(f"{m['id']}: relationship must be PROPOSED or RELATED")
        if m.get("claims_compliance") is not False: errs.append(f"{m['id']}: a relationship never claims compliance")
    tids = {t["id"] for t in g["threats"]}
    if {t["id"] for t in g["threats"] if t["mapped"]} | {t["id"] for t in g["threats"] if not t["mapped"]} != tids: errs.append("threat partition is inconsistent")
    for t in g["threats"]:
        if t["mapped"] != bool(t["relationships"]): errs.append(f"{t['id']}: mapped does not follow from its relationships")
        if not t["mapped"] and t["relationships"]: errs.append(f"{t['id']}: unmapped threat carries relationships")
        for c in t["controls"]:
            if c["id"] not in {x["id"] for x in g["controls"]}: errs.append(f"{t['id']}: unknown control {c['id']}")
    for c in g["controls"]:
        for k, v in NOT_ASSERTED.items():
            if c.get(k) != v: errs.append(f"{c['id']}: {k} may not be invented (must be {v})")
        if c["evidence_state"] not in ("RECORDED_DECISIONS_EXIST", "NO_RECORDED_EVIDENCE"): errs.append(f"{c['id']}: unknown evidence state")
        if (c["evidence_state"] == "RECORDED_DECISIONS_EXIST") != bool(c["recorded_decisions"]): errs.append(f"{c['id']}: evidence state does not follow from the recorded decisions")
    for f in g["frameworks"]:
        if f["status"] not in ("REFERENCED", "NOT_VERIFIED_IN_THIS_REPOSITORY"): errs.append(f"{f['name']}: unknown status")
        if f["status"] == "NOT_VERIFIED_IN_THIS_REPOSITORY" and (f["items"] or f["mapped_relationships"]): errs.append(f"{f['name']}: an unverified framework carries no items or mappings")
    return errs
