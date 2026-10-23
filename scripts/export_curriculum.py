#!/usr/bin/env python3
"""Export the 12-domain curriculum and the 32 registered labs for the React Academy, with a source reference for every piece of text.

Single source stays where it is: learning/academy/{taxonomy,lab_registry_data,curriculum}.json, learning/level_1/<LAB>/{README,workshop,evidence,
dashboard,knowledge-check}.md, lab-manifest.json, specimens/, searches/, and splunk_app/.../views/*.xml. Nothing here is written by hand: a lab section with
no source is exported as null and shown as "not documented". Re-run after editing any source, then rebuild the UI.
"""
from __future__ import annotations

import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from agentsec.launch_catalog import known_lab_ids  # noqa: E402

LEARN = ROOT / "learning"
LABS = LEARN / "level_1"
VIEWS = ROOT / "splunk_app" / "agentsec" / "default" / "data" / "ui" / "views"
MAX = 1100
# The original curriculum's display names (taxonomy.json keeps its own titles; both are exported).
DOMAIN_NAMES = {"D01": "AI & Agent Foundations", "D02": "Prompt Injection", "D03": "MCP & Tool Security", "D04": "A2A & Delegation", "D05": "RAG & Knowledge",
                "D06": "Memory & State", "D07": "Identity & Secrets", "D08": "Data Protection", "D09": "Runtime Governance", "D10": "Agent Observability",
                "D11": "Detection & Response", "D12": "Risk & Assurance"}
AVAIL = {"GUIDED MISSION": "guided", "WORKBENCH": "workbench", "REPLAY": "replay", "CONTENT-ONLY": "content_only"}
NATIVE = {"LAB-LOANDESK-001": "/learn/loan-desk", "LAB-MCP-001": "/learn/mcp"}


def clean(s: str) -> str:
    """Plain text: markdown emphasis and backticks removed, whitespace collapsed. The provenance test applies the same function to the source."""
    return re.sub(r"\s+", " ", re.sub(r"[*`]", "", s)).strip()


def cut(s: str) -> str:
    s = clean(s)
    if len(s) <= MAX:
        return s
    head = s[:MAX]
    end = max(head.rfind(". "), head.rfind("; "))
    return (head[: end + 1] if end > 400 else head.rstrip()) + " …"


def rel(p: Path) -> str:
    return p.relative_to(ROOT).as_posix()


def md_sections(text: str) -> dict[str, str]:
    parts = re.split(r"^## ", text, flags=re.M)
    return {p.split("\n", 1)[0].strip(): p.split("\n", 1)[1] if "\n" in p else "" for p in parts[1:]}


def bold_para(body: str, labels: list[str]) -> str | None:
    for lab in labels:
        m = re.search(r"^\*\*" + lab + r"\??:?\*\*:?[ \t]*(.+?)(?:\n\s*\n|\Z)", body, re.M | re.S | re.I)
        if m:
            return m.group(1)
    return None


def section_by_prefix(secs: dict[str, str], *prefixes: str) -> str | None:
    for name, body in secs.items():
        if any(name.lower().startswith(p.lower()) for p in prefixes):
            return body
    return None


def entry(text: str | None, src: Path | str) -> dict | None:
    if not text or not clean(text):
        return None
    return {"text": cut(text), "source": src if isinstance(src, str) else rel(src)}


def numbered(block: str) -> list[str]:
    return [clean(m.group(2)) for m in re.finditer(r"^\s*(\d+)\.\s+(.+?)(?=\n\s*\d+\.\s|\n\s*\n|\Z)", block, re.M | re.S)]


def checks_of(path: Path) -> list[dict]:
    """Three layouts exist in the repository: '## Questions' + '## Answers'; '## Checks' with '### N. question' + answer text; a bare numbered list."""
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8")
    secs = md_sections(text)
    blocks = re.findall(r"^###\s*(\d+)\.\s*(.+?)\n\s*\n(.*?)(?=^###|\Z)", text, re.M | re.S)
    if blocks:
        return [{"q": clean(q), "a": clean(a) or None} for _, q, a in blocks]
    qs = numbered(secs.get("Questions", "")) or numbered(section_by_prefix(secs, "Knowledge check", "Concept checks") or "") or numbered(text.split("\n## ", 1)[0])
    ans = numbered(secs.get("Answers", ""))
    return [{"q": q, "a": ans[i] if len(ans) == len(qs) else None} for i, q in enumerate(qs)]


EXPL = LEARN / "academy" / "explainers"


def _dig(doc, dotted: str):
    for part in dotted.split("."):
        doc = doc[part]
    return doc


def md_table(text: str) -> tuple[list[str], list[list[str]]]:
    rows = [[clean(c) for c in l.strip().strip("|").split("|")] for l in text.splitlines() if l.strip().startswith("|")]
    rows = [r for r in rows if not all(re.fullmatch(r":?-{2,}:?", c) for c in r)]
    return (rows[0], rows[1:]) if rows else ([], [])


def bullets(text: str) -> list[str]:
    return [clean(m.group(1)) for m in re.finditer(r"^[-*]\s+(.+)$", text, re.M)]


def explainer_for(lab_id: str) -> dict | None:
    """Embed the hand-written explainer, resolving every reference to the real source text so nothing is retyped."""
    path = EXPL / f"{lab_id}.json"
    if not path.exists():
        return None
    e = json.loads(path.read_text(encoding="utf-8"))
    for item in e.get("practice", {}).get("predict", []):
        f, _, dotted = item["source"].partition("#")
        item["text"] = clean(_dig(json.loads((ROOT / f).read_text(encoding="utf-8")), dotted))
    rt = e.get("recorded_table")
    if rt:
        src = ROOT / rt["source"]
        if "md_section" in rt:
            head, rows = md_table(md_sections(src.read_text(encoding="utf-8"))[rt["md_section"]])
            rt["columns"], rt["rows"] = head, rows
        else:
            data = _dig(json.loads(src.read_text(encoding="utf-8")), rt["json_path"])
            rt["rows"] = [[clean(str(r.get(k, ""))) for k, _ in rt["columns"]] for r in data]
            rt["columns"] = [h for _, h in rt["columns"]]
    if "spl" in e:
        e["spl"] = [{"name": n, "source": f"learning/level_1/{lab_id}/searches/{n}", "text": (LABS / lab_id / "searches" / n).read_text(encoding="utf-8").strip()} for n in e["spl"]]
    cc = e.get("cannot_claim")
    if cc:
        e["cannot_claim"] = {"source": cc["source"] + "#" + cc["section"], "items": bullets(md_sections((ROOT / cc["source"]).read_text(encoding="utf-8"))[cc["section"]])}
    ccl = e.pop("cannot_claim_lines", None)
    if ccl:
        e["cannot_claim"] = {"source": ccl["source"], "items": [clean(x) for x in ccl["lines"]]}
    return e


def view_for(lab: str) -> str | None:
    hits = [p.stem for p in sorted(VIEWS.glob("ws_lab_*.xml")) if lab in p.read_text(encoding="utf-8", errors="ignore")]
    return hits[0] if hits else None


def view_label(name: str) -> tuple[str | None, str | None]:
    root = ET.parse(VIEWS / f"{name}.xml").getroot()
    return root.findtext("label"), root.findtext("description")


def build() -> dict:
    registry = {e["lab_id"]: e for e in json.loads((LEARN / "academy" / "lab_registry_data.json").read_text(encoding="utf-8"))["entries"]}
    tax = {d["id"]: d for d in json.loads((LEARN / "academy" / "taxonomy.json").read_text(encoding="utf-8"))["domains"]}
    cur = json.loads((LEARN / "academy" / "curriculum.json").read_text(encoding="utf-8"))
    level_of = {l["lab_id"]: (lv["id"], lv["title"], l["title"]) for lv in cur["levels"] for l in lv["labs"]}
    launchable = known_lab_ids()
    labs = []
    for lab_id, e in sorted(registry.items()):
        d = LABS / lab_id
        readme = d / "README.md"; wk = d / "workshop.md"; ev = d / "evidence.md"; dash = d / "dashboard.md"; man = d / "lab-manifest.json"
        rd = readme.read_text(encoding="utf-8") if readme.exists() else ""
        wks = md_sections(wk.read_text(encoding="utf-8")) if wk.exists() else {}
        evs = md_sections(ev.read_text(encoding="utf-8")) if ev.exists() else {}
        dashs = md_sections(dash.read_text(encoding="utf-8")) if dash.exists() else {}
        rds = md_sections(rd) if rd else {}
        manifest = json.loads(man.read_text(encoding="utf-8")) if man.exists() else {}
        pred = manifest.get("prediction", {}) if isinstance(manifest.get("prediction"), dict) else {}
        att = pred.get("ATTACK", {}) if isinstance(pred.get("ATTACK"), dict) else {}
        ret = pred.get("RETEST", {}) if isinstance(pred.get("RETEST"), dict) else {}
        learn_body = wks.get("LEARN", "")
        view = view_for(lab_id)
        vlabel, vdesc = view_label(view) if view else (None, None)
        title = level_of.get(lab_id, (None, None, None))[2] or vlabel or (re.match(r"# (.+)", rd).group(1) if re.match(r"# (.+)", rd) else lab_id)
        idea = re.search(r"This lab teaches one idea:\s*(.+?)(?:\n\s*\n|\Z)", rd, re.S)
        quote = e["evidence"][0] if e.get("evidence") else None
        objectives = numbered(rds.get("Learner objectives", "").split("\n\n", 1)[-1]) if "Learner objectives" in rds else []
        S = {
            "learn": ({"items": [clean(o) for o in objectives][:8], "source": rel(readme) + "#Learner objectives"} if objectives else
                      (entry(section_by_prefix(rds, "Learning outcomes", "Objective", "Mission"), rel(readme) + "#" + next(n for n in rds if n.lower().startswith(("learning outcomes", "objective", "mission")))) if section_by_prefix(rds, "Learning outcomes", "Objective", "Mission") else None)),
            "idea": entry(idea.group(1), readme) if idea else (entry(quote["quote"], quote["file"]) if quote else None),
            "problem": entry(bold_para(learn_body, ["What is it", "Core question"]), wk) if bold_para(learn_body, ["What is it", "Core question"]) else (entry(att.get("attack_objective"), man) if att.get("attack_objective") else (entry(vdesc, VIEWS / f"{view}.xml") if vdesc else None)),
            "why": entry(bold_para(learn_body, ["Why it exists", "Why does it exist"]), wk) if bold_para(learn_body, ["Why it exists", "Why does it exist"]) else (entry(att.get("why_this_matters"), man) if att.get("why_this_matters") else None),
            "controls": entry(bold_para(learn_body, ["What the attacker controls"]), wk) if bold_para(learn_body, ["What the attacker controls"]) else (entry(att.get("attacker_influence"), man) if att.get("attacker_influence") else None),
            "boundary": entry(bold_para(learn_body, ["Trust boundary"]), wk) if bold_para(learn_body, ["Trust boundary"]) else (entry(att.get("which_control") or att.get("security_property"), man) if (att.get("which_control") or att.get("security_property")) else None),
            "how": entry(bold_para(wks.get("ATTACK", ""), ["Expected", "Action"]), wk) if bold_para(wks.get("ATTACK", ""), ["Expected", "Action"]) else (entry(att.get("what_will_change"), man) if att.get("what_will_change") else None),
            "predict": entry(att.get("predict_before_launch"), man) if att.get("predict_before_launch") else (entry(bold_para(wks.get("HUNT", ""), ["Question"]), wk) if bold_para(wks.get("HUNT", ""), ["Question"]) else None),
            "defend": entry(wks.get("DEFEND"), wk) if wks.get("DEFEND") else (entry(att.get("defense_should"), man) if att.get("defense_should") else None),
            "conclude": (entry(section_by_prefix(evs, "What each layer proves"), ev) if section_by_prefix(evs, "What each layer proves") else
                         entry(section_by_prefix(dashs, "What this dashboard is not allowed to claim"), dash) if section_by_prefix(dashs, "What this dashboard is not allowed to claim") else
                         entry(" ".join(manifest.get("limitations", [])[:4]), man) if manifest.get("limitations") else None),
        }
        for k in ("idea", "problem", "why", "controls", "boundary", "how", "predict", "defend", "conclude"):
            if S[k] and S[k]["source"].endswith("lab-manifest.json"):
                S[k]["source"] += "#prediction"
        rules = [clean(m.group(0)) for m in re.finditer(r"^[A-Z][A-Z0-9 /,.'()-]{6,}(?:!=|≠)[A-Z0-9 /,.'()-]{3,}$", rd, re.M)][:8]
        labs.append({
            "id": lab_id, "title": clean(title), "level": level_of.get(lab_id, (None,))[0],
            "primary_domain": e["primary_domain"], "secondary_domain": e.get("secondary_domain"), "domain_confidence": e["domain_confidence"],
            "tier": e["tier"], "availability": AVAIL[e["tier"]], "launchable": lab_id in launchable, "native": NATIVE.get(lab_id),
            "registry_quote": quote, "sections": S, "rules": rules,
            "assets": {"specimens": sorted(p.name for p in (d / "specimens").glob("*")) if (d / "specimens").exists() else [], "hunts": sorted(p.name for p in (d / "searches").glob("*")) if (d / "searches").exists() else [],
                       "dashboard": view, "evidence_docs": [rel(p) for p in (ev, dash) if p.exists()]},
            "explainer": explainer_for(lab_id),
            "limitations": ({"items": [clean(x) for x in manifest["limitations"]], "source": rel(man) + "#limitations"} if manifest.get("limitations") else None),
            "checks": checks_of(d / "knowledge-check.md"), "checks_source": rel(d / "knowledge-check.md") if (d / "knowledge-check.md").exists() else None,
        })
    domains = [{"id": k, "name": DOMAIN_NAMES[k], "taxonomy_title": tax[k]["title"], "source": "learning/academy/taxonomy.json"} for k in sorted(tax)]
    return {"inventory_date": "2026-10-23", "domains": domains, "labs": labs,
            "sources": ["learning/academy/taxonomy.json", "learning/academy/lab_registry_data.json", "learning/academy/curriculum.json"]}


if __name__ == "__main__":
    out = build()
    dest = ROOT / "academy-ui" / "src" / "content" / "curriculum.json"
    dest.write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    filled = sum(1 for l in out["labs"] for v in l["sections"].values() if v)
    print(f"wrote {dest.relative_to(ROOT)}: {len(out['domains'])} domains, {len(out['labs'])} labs, {filled} sourced sections, {dest.stat().st_size // 1024} KB")
