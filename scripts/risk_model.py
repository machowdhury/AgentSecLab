"""The Risk Center's schema, qualitative method and validator, built on the Phase 12A assurance model.

Fields have four origins that are never mixed: SOURCE (read from a committed file), DERIVED (fixed rules), ANALYST (a person's judgment) and MISSING (shown as
NOT ASSESSED or NOT ASSIGNED). A risk level is looked up in a table from an analyst's impact and likelihood; it is never computed from a control test result.
The browser validator in academy-ui/src/risk/validate.ts mirrors validate_assessment and returns the same error codes.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import assurance_model as A

ROOT = Path(__file__).resolve().parents[1]
METHOD = json.loads((ROOT / "learning/academy/risk/methodology.json").read_text(encoding="utf-8"))
SCHEMA = "agentsec.risk_assessment.v1"
STATUS = "LOCAL_DRAFT_NOT_APPROVED"
IMPACT = [x["id"] for x in METHOD["impact"]]
LIKELIHOOD = [x["id"] for x in METHOD["likelihood"]]
LEVELS = METHOD["levels"]
STRATEGIES = [x["id"] for x in METHOD["treatment"]]
ACTION_STATUS = ("PROPOSED", "IN_PROGRESS", "COMPLETED")
REVIEW_STATUS = ("DRAFT", "AWAITING_REVIEW", "REVIEWED")
LIMITS = {"risks": 200, "text": 2000, "short": 200, "actions": 50, "history": 100, "controls": 50}
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,63}$")
RESERVED = {"register", "method", "new"}


def level(impact: str | None, likelihood: str | None) -> str | None:
    """The table lookup. None means NOT ASSESSED, because a level needs both entries."""
    if impact in IMPACT and likelihood in LIKELIHOOD:
        return METHOD["matrix"][impact][likelihood]
    return None


def canonical(o) -> str:
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def risks_sha256(risks: list) -> str:
    return hashlib.sha256(canonical(risks).encode("utf-8")).hexdigest()


def blank_risk(rid: str, origin: str = "seed", custom: dict | None = None) -> dict:
    return {"id": rid, "origin": origin, "custom": custom,
            "assessment": {"inherent": {"impact": None, "likelihood": None, "rationale": ""}, "residual": {"impact": None, "likelihood": None, "rationale": "", "controls_considered": []}},
            "owner": None, "treatment": {"strategy": None, "notes": "", "actions": [], "approval": None},
            "review": {"status": "DRAFT", "reviewer": None, "note": "", "at": None, "history": []},
            "derived": {"inherent_level": None, "residual_level": None}}


def derive(r: dict) -> dict:
    a = r["assessment"]
    return {"inherent_level": level(a["inherent"]["impact"], a["inherent"]["likelihood"]), "residual_level": level(a["residual"]["impact"], a["residual"]["likelihood"])}


# ---- strict shapes: every key must be known, and every value of the right type ------------------------------------------------------------
def _keys(o, allowed, path, errs):
    if not isinstance(o, dict):
        errs.append(("TYPE", path, "must be an object"))
        return False
    for k in o:
        if k not in allowed:
            errs.append(("UNKNOWN_KEY", f"{path}.{k}", "is not a field of the schema"))
    for k in allowed:
        if k not in o:
            errs.append(("MISSING_KEY", f"{path}.{k}", "is missing"))
    return True


def _text(v, path, errs, limit=LIMITS["text"], nullable=False):
    if v is None and nullable:
        return
    if not isinstance(v, str):
        errs.append(("TYPE", path, "must be text"))
    elif len(v) > limit:
        errs.append(("LIMIT", path, f"is longer than {limit} characters"))


def validate_assessment(doc, seed_ids: set[str]) -> list[tuple[str, str, str]]:
    """(code, path, message) for every problem. An empty list means the document is well formed, internally consistent and claims no approval."""
    errs: list[tuple[str, str, str]] = []
    if not _keys(doc, ("schema", "methodology_version", "status", "seed_sha256", "integrity", "risks"), "$", errs):
        return errs
    if doc.get("schema") != SCHEMA: errs.append(("SCHEMA", "$.schema", f"must be {SCHEMA}"))
    if doc.get("methodology_version") != METHOD["version"]: errs.append(("METHOD_VERSION", "$.methodology_version", f"must be {METHOD['version']}"))
    if doc.get("status") != STATUS: errs.append(("STATUS", "$.status", f"must be {STATUS}: a local draft is never approved"))
    if not isinstance(doc.get("seed_sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", doc.get("seed_sha256", "")): errs.append(("TYPE", "$.seed_sha256", "must be a SHA-256"))
    integ = doc.get("integrity")
    _keys(integ, ("algorithm", "risks_sha256", "note"), "$.integrity", errs)
    risks = doc.get("risks")
    if not isinstance(risks, list):
        errs.append(("TYPE", "$.risks", "must be a list"))
        return errs
    if len(risks) > LIMITS["risks"]: errs.append(("LIMIT", "$.risks", f"has more than {LIMITS['risks']} risks"))
    if isinstance(integ, dict) and integ.get("algorithm") == "sha256" and integ.get("risks_sha256") != risks_sha256(risks):
        errs.append(("INTEGRITY", "$.integrity.risks_sha256", "does not match the risks: the file was edited after it was exported"))
    elif isinstance(integ, dict) and integ.get("algorithm") != "sha256":
        errs.append(("INTEGRITY", "$.integrity.algorithm", "must be sha256"))
    seen: set[str] = set()
    for i, r in enumerate(risks):
        p = f"$.risks[{i}]"
        if not _keys(r, ("id", "origin", "custom", "assessment", "owner", "treatment", "review", "derived"), p, errs):
            continue
        rid = r.get("id")
        if not isinstance(rid, str) or not ID_RE.match(rid) or rid.lower() in RESERVED: errs.append(("ID", f"{p}.id", "is not a valid risk id"))
        elif rid in seen: errs.append(("DUPLICATE", f"{p}.id", "appears twice"))
        seen.add(str(rid))
        if r.get("origin") not in ("seed", "custom"): errs.append(("ORIGIN", f"{p}.origin", "must be seed or custom"))
        if r.get("origin") == "seed":
            if rid not in seed_ids: errs.append(("UNKNOWN_SEED", f"{p}.id", "is not a source-backed risk in the current evidence"))
            if r.get("custom") is not None: errs.append(("ORIGIN", f"{p}.custom", "a source-backed risk carries no analyst-defined facts"))
        if r.get("origin") == "custom":
            c = r.get("custom")
            if _keys(c, ("title", "category", "system", "scenario", "assets"), f"{p}.custom", errs):
                for f in ("title", "category", "system", "scenario", "assets"):
                    _text(c.get(f), f"{p}.custom.{f}", errs, LIMITS["short"] if f != "scenario" else LIMITS["text"])
                if isinstance(c.get("title"), str) and not c["title"].strip(): errs.append(("TITLE", f"{p}.custom.title", "a custom risk needs a title"))
            else:
                pass
        a = r.get("assessment")
        if _keys(a, ("inherent", "residual"), f"{p}.assessment", errs):
            for which in ("inherent", "residual"):
                s = a.get(which)
                extra = ("controls_considered",) if which == "residual" else ()
                if not _keys(s, ("impact", "likelihood", "rationale") + extra, f"{p}.assessment.{which}", errs):
                    continue
                sp = f"{p}.assessment.{which}"
                if s.get("impact") not in (None, *IMPACT): errs.append(("SCALE", f"{sp}.impact", f"must be one of {IMPACT} or null"))
                if s.get("likelihood") not in (None, *LIKELIHOOD): errs.append(("SCALE", f"{sp}.likelihood", f"must be one of {LIKELIHOOD} or null"))
                _text(s.get("rationale"), f"{sp}.rationale", errs)
                if (s.get("impact") is None) != (s.get("likelihood") is None): errs.append(("PAIR", sp, "impact and likelihood must be entered together"))
                if s.get("impact") is not None and s.get("likelihood") is not None and not str(s.get("rationale", "")).strip(): errs.append(("RATIONALE", f"{sp}.rationale", "a judgment needs a written rationale"))
                if which == "residual":
                    cc = s.get("controls_considered")
                    if not isinstance(cc, list) or not all(isinstance(x, str) and len(x) <= LIMITS["short"] for x in cc) or len(cc) > LIMITS["controls"]: errs.append(("TYPE", f"{sp}.controls_considered", "must be a list of control ids"))
            ih, rs = a.get("inherent") if isinstance(a.get("inherent"), dict) else {}, a.get("residual") if isinstance(a.get("residual"), dict) else {}
            if rs.get("impact") is not None and ih.get("impact") is None: errs.append(("RESIDUAL_NEEDS_INHERENT", f"{p}.assessment.residual", "residual risk cannot be judged before inherent risk"))
        if r.get("owner") is not None: _text(r.get("owner"), f"{p}.owner", errs, LIMITS["short"])
        t = r.get("treatment")
        if _keys(t, ("strategy", "notes", "actions", "approval"), f"{p}.treatment", errs):
            if t.get("strategy") not in (None, *STRATEGIES): errs.append(("STRATEGY", f"{p}.treatment.strategy", f"must be one of {STRATEGIES} or null"))
            _text(t.get("notes"), f"{p}.treatment.notes", errs)
            ap = t.get("approval")
            if ap is not None:
                if t.get("strategy") != "ACCEPT": errs.append(("APPROVAL", f"{p}.treatment.approval", "only an ACCEPT treatment carries an approval record"))
                if _keys(ap, ("by", "role", "at", "note"), f"{p}.treatment.approval", errs):
                    for f in ("by", "role", "at", "note"):
                        _text(ap.get(f), f"{p}.treatment.approval.{f}", errs, LIMITS["short"])
                        if isinstance(ap.get(f), str) and not ap[f].strip(): errs.append(("APPROVAL", f"{p}.treatment.approval.{f}", "an approval record needs who, role, when and a note"))
            acts = t.get("actions")
            if not isinstance(acts, list) or len(acts) > LIMITS["actions"]: errs.append(("TYPE", f"{p}.treatment.actions", "must be a short list"))
            else:
                ids = set()
                for j, x in enumerate(acts):
                    xp = f"{p}.treatment.actions[{j}]"
                    if not _keys(x, ("id", "text", "owner", "status", "evidence_note"), xp, errs): continue
                    if x.get("id") in ids: errs.append(("DUPLICATE", f"{xp}.id", "appears twice"))
                    ids.add(x.get("id"))
                    _text(x.get("text"), f"{xp}.text", errs, LIMITS["short"]); _text(x.get("owner"), f"{xp}.owner", errs, LIMITS["short"], nullable=True); _text(x.get("evidence_note"), f"{xp}.evidence_note", errs)
                    if x.get("status") not in ACTION_STATUS: errs.append(("ACTION_STATUS", f"{xp}.status", f"must be one of {list(ACTION_STATUS)}"))
                    if x.get("status") == "COMPLETED" and not str(x.get("evidence_note", "")).strip(): errs.append(("ACTION_EVIDENCE", f"{xp}.evidence_note", "a completed action needs the evidence it rests on"))
        rv = r.get("review")
        if _keys(rv, ("status", "reviewer", "note", "at", "history"), f"{p}.review", errs):
            if rv.get("status") not in REVIEW_STATUS: errs.append(("REVIEW_STATUS", f"{p}.review.status", f"must be one of {list(REVIEW_STATUS)}: nothing is shown as approved"))
            _text(rv.get("reviewer"), f"{p}.review.reviewer", errs, LIMITS["short"], nullable=True); _text(rv.get("note"), f"{p}.review.note", errs); _text(rv.get("at"), f"{p}.review.at", errs, LIMITS["short"], nullable=True)
            if rv.get("status") == "REVIEWED" and not all(isinstance(rv.get(f), str) and rv[f].strip() for f in ("reviewer", "note", "at")): errs.append(("REVIEW_FIELDS", f"{p}.review", "a recorded review needs the reviewer, a note and a date"))
            h = rv.get("history")
            if not isinstance(h, list) or len(h) > LIMITS["history"]: errs.append(("TYPE", f"{p}.review.history", "must be a short list"))
            else:
                for j, x in enumerate(h):
                    if _keys(x, ("at", "event", "note"), f"{p}.review.history[{j}]", errs):
                        for f in ("at", "event", "note"): _text(x.get(f), f"{p}.review.history[{j}].{f}", errs, LIMITS["short"] if f != "note" else LIMITS["text"])
        d = r.get("derived")
        if _keys(d, ("inherent_level", "residual_level"), f"{p}.derived", errs) and isinstance(r.get("assessment"), dict):
            try:
                want = derive(r)
                if d != want: errs.append(("DERIVED", f"{p}.derived", f"does not follow from the entries by the method (expected {want})"))
            except (KeyError, TypeError):
                pass
    return errs


def validate_seed(seed: dict) -> list[str]:
    """The source-backed side: every candidate's facts have a source with a matching hash, and no analyst field is pre-filled."""
    errs = [f"{p}: a score, percentage or rating field is not allowed" for p, k, _ in A._walk_keys(seed) if A.FORBIDDEN_KEYS.search(k)]
    for c in seed.get("candidates", []):
        cid = c.get("id", "?")
        if not c.get("sources"): errs.append(f"{cid}: needs sources")
        for s in c.get("sources", []):
            if not (ROOT / s["file"]).is_file(): errs.append(f"{cid}: {s['file']} does not exist")
            elif A.sha256_file(s["file"]) != s["sha256"]: errs.append(f"{cid}: sha256 of {s['file']} does not match")
        for k in ("impact", "likelihood", "owner", "treatment", "residual", "inherent", "approval", "severity"):
            if k in c: errs.append(f"{cid}: {k} is an analyst field and may not be pre-filled")
        for ctl in c.get("controls", []):
            if ctl.get("effectiveness") is not None and "effectiveness" in ctl: errs.append(f"{cid}: a control carries no effectiveness rating")
        if c.get("derived", {}).get("has_linked_findings") != bool(c.get("evidence", {}).get("findings")): errs.append(f"{cid}: has_linked_findings does not follow from the linked findings")
    return errs
