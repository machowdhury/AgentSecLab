"""Validation for the EVAL Center data, built on the Phase 12A assurance model.

An experiment holds recorded test cases (observations). A finding is derived from a test case by a stated rule, never typed in, and keeps severity, owner and
remediation as NOT ASSESSED / NOT ASSIGNED until someone with the evidence sets them. No metric is a rate or a score: each carries its numerator, denominator and scope.
"""
from __future__ import annotations

import assurance_model as A

CAP_STATUS = ("AVAILABLE_WITH_EVIDENCE", "DOCUMENTED_ONLY", "NOT_IMPLEMENTED")
KINDS = ("pack_triple", "garak", "scanner", "packet")
FINDING_RULES = ("fail_open_allow_then_execution", "scanner_native_finding")


def _forbidden(o) -> list[str]:
    return [f"{p}: a score, percentage or rating field is not allowed" for p, k, _ in A._walk_keys(o) if A.FORBIDDEN_KEYS.search(k)]


def validate_experiment(e: dict, refs: dict | None = None) -> list[str]:
    errs = _forbidden(e)
    eid = e.get("id", "?")
    if e.get("kind") not in KINDS: errs.append(f"{eid}: unknown kind")
    if e.get("evidence_class") not in A.EVIDENCE_CLASSES: errs.append(f"{eid}: unknown evidence class")
    if not e.get("cases"): errs.append(f"{eid}: an experiment needs at least one test case")
    seen = set()
    for c in e.get("cases", []):
        cid = c.get("id")
        if cid in seen: errs.append(f"{eid}: duplicate case {cid}")
        seen.add(cid)
        if c.get("evidence_class") != e.get("evidence_class"): errs.append(f"{cid}: case class differs from the experiment's")
        if c.get("verification", {}).get("status") not in A.VERIFICATION: errs.append(f"{cid}: verification status missing")
        if c.get("verification", {}).get("status") == "VERIFIED" and not c["verification"].get("receipt"): errs.append(f"{cid}: VERIFIED needs a receipt")
        if not c.get("limitations"): errs.append(f"{cid}: a test case must state its limitations")
        if not c.get("sources"): errs.append(f"{cid}: a test case needs a source")
        for s in c.get("sources", []):
            if not (A.ROOT / s["file"]).is_file(): errs.append(f"{cid}: {s['file']} does not exist")
            elif A.sha256_file(s["file"]) != s["sha256"]: errs.append(f"{cid}: sha256 of {s['file']} does not match")
        ex = c.get("expected", {})
        if ex.get("documented") and not ex.get("quote"): errs.append(f"{cid}: a documented expectation needs its quote")
        if ex.get("documented") is False and ex.get("quote"): errs.append(f"{cid}: an undocumented expectation cannot carry a quote")
    cmp_ = e.get("comparison")
    if cmp_ is not None and cmp_.get("kind") == "attack_retest":
        eq = cmp_.get("same_request_fields", {})
        if cmp_.get("controlled_pair") != (bool(eq) and all(eq.values()) and bool(cmp_.get("signature_has_value"))): errs.append(f"{eid}: controlled_pair does not follow from the compared fields")
    if e.get("comparison") is None and not e.get("comparison_unavailable"): errs.append(f"{eid}: no comparison needs a stated reason")
    for m in e.get("mappings", []):
        if m.get("claims_compliance") is not False: errs.append(f"{eid}: mapping {m.get('id')} claims compliance")
        if refs is not None:
            known = {(i["framework"], i["id"]): i for i in refs["items"]}
            i = known.get((m.get("framework"), m.get("id")))
            if not i or (m["name"], m["verification_status"], m["limits"]) != (i["name"], i["status"], i["limits"]): errs.append(f"{eid}: mapping {m.get('id')} is not the reference file's")
    return errs


def validate_finding(f: dict, cases: dict[str, dict]) -> list[str]:
    errs = _forbidden(f)
    fid = f.get("id", "?")
    if f.get("rule") not in FINDING_RULES: errs.append(f"{fid}: a finding needs a stated rule")
    for k in ("experiment", "target", "conditions", "observed", "expected", "evidence", "verification", "limitations"):
        if k not in f: errs.append(f"{fid}: missing {k}")
    if f.get("severity") != "NOT ASSESSED": errs.append(f"{fid}: severity may not be invented")
    if f.get("owner") != "NOT ASSIGNED" or f.get("remediation_status") != "NOT ASSIGNED": errs.append(f"{fid}: owner and remediation status may not be invented")
    if f.get("verification", {}).get("status") != "NOT_VERIFIED": errs.append(f"{fid}: no receipt exists, so a finding is NOT_VERIFIED")
    if not f.get("limitations"): errs.append(f"{fid}: limitations missing")
    for ref in f.get("evidence", []):
        c = cases.get(ref)
        if not c: errs.append(f"{fid}: unknown evidence {ref}")
        elif c["evidence_class"] == "SIMULATED": errs.append(f"{fid}: a finding is never derived from simulated evidence")
    if f.get("expected", {}).get("documented") and not f["expected"].get("quote"): errs.append(f"{fid}: documented expectation needs its quote")
    return errs


def validate_metrics(metrics: list[dict]) -> list[str]:
    errs = []
    for m in metrics:
        for k in ("id", "label", "numerator", "denominator", "unit", "scope", "derivation"):
            if k not in m: errs.append(f"metric {m.get('id')}: missing {k}")
        if isinstance(m.get("numerator"), int) and isinstance(m.get("denominator"), int) and not (0 <= m["numerator"] <= m["denominator"]):
            errs.append(f"metric {m['id']}: numerator is outside 0..denominator")
        if "rate" in m or "percent" in m or "score" in m: errs.append(f"metric {m['id']}: no rate, percentage or score")
    return errs
