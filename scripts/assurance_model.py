"""The shared assurance evidence model: types as constants and one validator.

Four layers are kept apart and never merged into a score:
  observations           what a committed source recorded (a decision, a result, a hash match)
  assessments / risks    judgments over observations, each with a basis; missing evidence is NOT_ASSESSED, never passing
  mappings               framework relationships copied from learning/academy/framework_refs.json, never a compliance claim
  compliance_assertions  must stay empty until a real assessment exists
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "agentsec.assurance_journey.v1"
EVIDENCE_CLASSES = ("LIVE", "RECORDED", "SIMULATED", "DOCUMENTED")
OBSERVATION_KINDS = ("runtime_decision", "provenance_check", "evaluation_result")
ASSESSMENT_STATUS = ("SUPPORTED", "PARTLY_SUPPORTED", "NOT_SUPPORTED", "NOT_ASSESSED")
VERIFICATION = ("NOT_VERIFIED", "VERIFIED")
RELATIONSHIPS = ("PROPOSED", "RELATED")
FORBIDDEN_KEYS = re.compile(r"(^|_)(score|scores|percent|percentage|rating|pass_rate|compliance_pct|likelihood_value|impact_value)$", re.I)
STEPS = ("learn", "practice", "evaluate", "risk", "controls", "prove")


def sha256_file(rel: str) -> str:
    return hashlib.sha256((ROOT / rel).read_bytes()).hexdigest()


def _walk_keys(o, path=""):
    if isinstance(o, dict):
        for k, v in o.items():
            yield f"{path}.{k}", k, v
            yield from _walk_keys(v, f"{path}.{k}")
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from _walk_keys(v, f"{path}[{i}]")


def validate(j: dict, refs: dict | None = None) -> list[str]:
    """Every problem found, as a list of messages. An empty list means the journey is well formed and makes no unsupported claim."""
    errs: list[str] = []
    if j.get("schema") != SCHEMA:
        errs.append(f"schema must be {SCHEMA}")
    for p, k, v in _walk_keys(j):
        if FORBIDDEN_KEYS.search(k):
            errs.append(f"{p}: a score, percentage or rating field is not allowed")
        if isinstance(v, (int, float)) and not isinstance(v, bool) and k in ("risk", "severity", "impact", "likelihood"):
            errs.append(f"{p}: risk, severity, impact and likelihood are never numbers")
    ids: set[str] = set()
    def ident(kind: str, x: dict):
        if x.get("id") in ids:
            errs.append(f"duplicate id {x.get('id')}")
        ids.add(x.get("id"))
    obs = {o["id"]: o for o in j.get("observations", [])}
    for o in j.get("observations", []):
        ident("observation", o)
        if o.get("kind") not in OBSERVATION_KINDS: errs.append(f"{o['id']}: unknown observation kind")
        if o.get("evidence_class") not in EVIDENCE_CLASSES: errs.append(f"{o['id']}: unknown evidence class")
        if o.get("verification", {}).get("status") not in VERIFICATION: errs.append(f"{o['id']}: verification status missing")
        if o.get("verification", {}).get("status") == "VERIFIED" and not o["verification"].get("receipt"):
            errs.append(f"{o['id']}: VERIFIED needs a receipt")
        if not o.get("limitations"): errs.append(f"{o['id']}: an observation must state its limitations")
        if not o.get("sources"): errs.append(f"{o['id']}: an observation needs a source")
        for s in o.get("sources", []):
            if not (ROOT / s["file"]).is_file(): errs.append(f"{o['id']}: {s['file']} does not exist")
            elif sha256_file(s["file"]) != s["sha256"]: errs.append(f"{o['id']}: sha256 of {s['file']} does not match")
    for a in j.get("assessments", []):
        ident("assessment", a)
        if a.get("status") not in ASSESSMENT_STATUS: errs.append(f"{a['id']}: unknown assessment status")
        if a.get("status") in ("SUPPORTED", "PARTLY_SUPPORTED") and not [x for x in a.get("about", []) if x in obs]:
            errs.append(f"{a['id']}: {a['status']} needs at least one observation (missing evidence is never passing evidence)")
        for x in a.get("about", []):
            if x not in obs: errs.append(f"{a['id']}: unknown observation {x}")
        if not a.get("basis"): errs.append(f"{a['id']}: an assessment needs a basis")
    for r in j.get("risks", []):
        ident("risk", r)
        for f in ("impact", "likelihood"):
            if r.get(f, {}).get("status") not in ("NOT_ASSESSED",) and r.get(f, {}).get("status") not in ASSESSMENT_STATUS:
                errs.append(f"{r['id']}: {f} needs a status")
            if r.get(f, {}).get("status") != "NOT_ASSESSED" and not r.get(f, {}).get("basis"):
                errs.append(f"{r['id']}: an assessed {f} needs a basis")
        for x in r.get("observed_in", []):
            if x not in obs: errs.append(f"{r['id']}: unknown observation {x}")
    if refs is not None:
        known = {(i["framework"], i["id"]): i for i in refs["items"]}
        for m in j.get("mappings", []):
            i = known.get((m.get("framework"), m.get("id")))
            if not i: errs.append(f"mapping {m.get('framework')} {m.get('id')} is not in framework_refs.json"); continue
            if (m["name"], m["verification_status"], m["limits"]) != (i["name"], i["status"], i["limits"]): errs.append(f"mapping {m['id']} differs from framework_refs.json")
            if m.get("relationship") not in RELATIONSHIPS: errs.append(f"mapping {m['id']}: relationship must be PROPOSED or RELATED")
            if m.get("claims_compliance") is not False: errs.append(f"mapping {m['id']}: a mapping never claims compliance")
    if j.get("compliance_assertions"):
        errs.append("compliance_assertions must be empty: no compliance assessment exists")
    if not j.get("compliance_statement"): errs.append("compliance_statement must say why there are no assertions")
    for x in j.get("remediation", []):
        ident("remediation", x)
        if x.get("owner") != "NOT_ASSIGNED": errs.append(f"{x['id']}: an owner may not be invented")
        if not x.get("basis_quote"): errs.append(f"{x['id']}: a remediation needs the source line that states the gap")
    for s in j.get("steps", []):
        if s.get("id") not in STEPS: errs.append(f"unknown step {s.get('id')}")
    if [s["id"] for s in j.get("steps", [])] != list(STEPS): errs.append("steps must be learn, practice, evaluate, risk, controls, prove in order")
    return errs
