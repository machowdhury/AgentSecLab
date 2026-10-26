#!/usr/bin/env python3
"""Export the 12-domain curriculum and the 32 registered labs for the React Academy, with a source reference for every piece of text.

Single source stays where it is: learning/academy/{taxonomy,lab_registry_data,curriculum}.json, learning/level_1/<LAB>/{README,workshop,evidence,
dashboard,knowledge-check}.md, lab-manifest.json, specimens/, searches/, and splunk_app/.../views/*.xml. Nothing here is written by hand: a lab section with
no source is exported as null and shown as "not documented". Re-run after editing any source, then rebuild the UI.
"""
from __future__ import annotations

import hashlib
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


# Fields identical on every event of a run: exported once per run (meta), never per event. Anything else is exported unchanged under its original key.
RUN_CONSTANT = ("service.name", "service.version", "deployment.environment", "agentsec.schema.name", "agentsec.schema.version", "agentsec.run.id", "agentsec.incident.id",
                "agentsec.lab.id", "agentsec.security.profile", "agentsec.testbed.mode", "agentsec.execution.mode", "agentsec.telemetry.fidelity", "user.id",
                "agentsec.principal.id", "agentsec.principal.type", "agentsec.workflow.entry", "gen_ai.workflow.name", "agentsec.attack.id", "trace_id")
RUN_META = {"attack_id": "agentsec.attack.id", "mode": "agentsec.testbed.mode", "profile": "agentsec.security.profile", "schema_version": "agentsec.schema.version",
            "execution_mode": "agentsec.execution.mode", "fidelity": "agentsec.telemetry.fidelity", "trace_id": "trace_id", "principal": "agentsec.principal.id",
            "workflow_entry": "agentsec.workflow.entry"}


def pack_run(lab_id: str, run_id: str) -> dict:
    """One committed specimen pack, event for event. Run-wide constants move to meta; every other field keeps its original key and value."""
    pack = LABS / lab_id / "specimens" / f"{run_id}.jsonl"
    raw = pack.read_bytes()
    events = [json.loads(l) for l in raw.decode("utf-8").splitlines() if l.strip()]
    if [e["agentsec.sequence"] for e in events] != list(range(1, len(events) + 1)):
        raise SystemExit(f"{pack.name}: sequence is not 1..n")
    first = events[0]
    for k in RUN_CONSTANT:
        if len({json.dumps(e.get(k)) for e in events}) != 1:
            raise SystemExit(f"{pack.name}: {k} is not constant across the run")
    return {"run_id": run_id, "pack": rel(pack), "sha256": hashlib.sha256(raw).hexdigest(),
            "meta": {**{k: first.get(v) for k, v in RUN_META.items()}, "started": first["timestamp"], "ended": events[-1]["timestamp"], "event_count": len(events)},
            "events": [{k: v for k, v in e.items() if k not in RUN_CONSTANT} for e in events]}


def spl_for(files: list[str]) -> list[dict]:
    return [{"name": Path(f).name, "source": f, "text": (ROOT / f).read_text(encoding="utf-8").strip()} for f in files]


def recorded_for(lab_id: str, rec: dict) -> dict:
    """Embed the committed specimen packs the lab documents, event for event. Nothing is invented: a missing field stays missing, and the tests re-read every pack."""
    doc_src = ROOT / rec["doc_source"]
    doc_lines = doc_src.read_text(encoding="utf-8").splitlines()
    runs = []
    for r in rec["runs"]:
        run = pack_run(lab_id, r["run_id"])
        bullet = next((l for l in doc_lines if r["run_id"] in l and l.lstrip().startswith("- ")), None)
        if bullet is None:
            raise SystemExit(f"{r['run_id']} is not documented in {rec['doc_source']}")
        if run["events"][r["decisive"] - 1]["event.name"] != "agentsec.control.decision":
            raise SystemExit(f"{run['pack']}: sequence {r['decisive']} is not a control decision")
        runs.append({"role": r["role"], "run_id": run["run_id"], "pack": run["pack"], "sha256": run["sha256"], "decisive": r["decisive"],
                     "documented_as": {"text": clean(bullet.lstrip()[2:]), "source": rel(doc_src)}, "meta": run["meta"], "events": run["events"]})
    return {"options": rec["options"], "runs": runs, "spl": spl_for(rec["spl"])}


def _items(value) -> list[str]:
    """A lab document's list, dict or string as plain text lines, values unchanged."""
    if isinstance(value, str):
        return [clean(value)]
    if isinstance(value, dict):
        return [clean(f"{k}: {v}") for k, v in value.items()]
    return [clean(f"{x['id']}{' (' + x['level'] + ')' if 'level' in x else ''}: {x['text']}" if isinstance(x, dict) and "text" in x and "id" in x else " · ".join(f"{k}: {v}" for k, v in x.items())) if isinstance(x, dict) else clean(str(x)) for x in value]


def _runs_of(canon, stages: list[str]) -> list[tuple[str, str]]:
    if isinstance(canon, str):
        return [("run", canon)]
    if "run_id" in canon:
        return [("run", canon["run_id"])]
    return [(s, canon[s]) for s in stages if s in canon]


def investigation_for(lab_id: str, spec: dict) -> dict:
    """An investigation over committed packs: scenarios of runs, optional external scanner records, questions whose answers the UI computes from the packs, and verbatim blocks from the lab's documents."""
    def text_of(f):
        return (ROOT / f).read_text(encoding="utf-8")
    out = {"kind": "investigation"}
    b = spec["brief"]
    body = text_of(b["file"])
    if b.get("starts"):                       # the named paragraph and the ones after it
        paras = [p for p in re.split(r"\n\s*\n", body) if p.strip()]
        i = next(i for i, p in enumerate(paras) if p.startswith(b["starts"]))
        paras = paras[i:i + b.get("count", 1)]
    else:
        body = md_sections(body)[b["section"]] if b.get("section") else body.split("\n", 1)[1]
        paras = [p for p in re.split(r"\n\s*\n", re.sub(r"```.*?```", "", body, flags=re.S)) if p.strip()]
    out["brief"] = {"paragraphs": [clean(p) for p in paras if clean(p)], "source": b["file"] + (f"#{b['section']}" if b.get("section") else "")}
    canon_doc = json.loads(text_of(spec["canonical"]["file"])) if "canonical" in spec else None
    out["scenarios"] = []
    for sc in spec["scenarios"]:
        if "from" in sc:
            pairs = _runs_of(_dig(canon_doc, sc["from"]), spec["canonical"]["stages"])
            doc = spec["canonical"]["file"] + "#" + sc["from"]
        else:
            pairs = [(r["stage"], r["run_id"]) for r in sc["runs"]]
            hay = text_of(sc["documented_in"])
            for _, rid in pairs:
                if rid not in hay:
                    raise SystemExit(f"{rid} is not documented in {sc['documented_in']}")
            doc = sc["documented_in"]
        out["scenarios"].append({"id": sc["id"], "label": sc["label"], "documented_in": doc, "runs": [{"stage": st, **pack_run(lab_id, rid)} for st, rid in pairs]})
    out["external"] = []
    for x in spec.get("external", []):
        pack = LABS / lab_id / "specimens" / "scanner" / f"{x['scan_id']}.jsonl"
        raw = pack.read_bytes()
        if x["scan_id"] not in text_of(x["documented_in"]):
            raise SystemExit(f"{x['scan_id']} is not documented in {x['documented_in']}")
        out["external"].append({"scan_id": x["scan_id"], "pack": rel(pack), "sha256": hashlib.sha256(raw).hexdigest(), "documented_in": x["documented_in"],
                                "records": [json.loads(json.loads(l)["event"]) for l in raw.decode("utf-8").splitlines() if l.strip()]})
    out["questions"] = spec["questions"]
    for q in out["questions"]:
        if clean(q["quote"]["text"]) not in clean(text_of(q["quote"]["file"])):
            raise SystemExit(f"quote for {q['id']} is not in {q['quote']['file']}")
    for k in ("graph", "control_analysis"):
        if k in spec:
            out[k] = {**json.loads(text_of(spec[k]["file"])), "source": spec[k]["file"]}
    out["blocks"] = []
    for blk in spec["blocks"]:
        if "section" in blk and blk.get("sentences"):
            items = [x for x in re.split(r"(?<=\.)\s+", clean(md_sections(text_of(blk["file"]))[blk["section"]])) if x]; src = blk["file"] + "#" + blk["section"]
        elif "section" in blk:
            items = bullets(md_sections(text_of(blk["file"]))[blk["section"]]); src = blk["file"] + "#" + blk["section"]
        elif blk.get("rules"):
            items = [clean(m.group(0)) for m in re.finditer(r"^[A-Z][A-Z0-9 /,.'()-]{6,}(?:!=|≠)[A-Z0-9 /,.'()-]{3,}$", text_of(blk["file"]), re.M)]; src = blk["file"]
        else:
            items = _items(_dig(json.loads(text_of(blk["file"])), blk["path"])); src = blk["file"] + "#" + blk["path"]
        if not items:
            raise SystemExit(f"block {blk['title']!r} in {lab_id} has no items: an empty block would show a heading with nothing under it")
        out["blocks"].append({"group": blk["group"], "title": blk["title"], "source": src, "items": items})
    out["spl"] = spl_for(spec["spl"])
    return out


def source_text(path: Path) -> str:
    """A source file as the learner-facing tests read it: JSON string values, XML text, or markdown, with emphasis removed."""
    if path.suffix == ".json":
        out: list[str] = []
        def walk(o):
            if isinstance(o, str): out.append(clean(o))
            elif isinstance(o, dict): [(out.append(clean(k)), walk(v)) for k, v in o.items()]
            elif isinstance(o, list): [walk(v) for v in o]
        walk(json.loads(path.read_text(encoding="utf-8")))
        return "\n".join(out)
    if path.suffix == ".xml":
        return clean(" ".join(ET.parse(path).getroot().itertext())).replace('\\"', '"')
    return clean(path.read_text(encoding="utf-8"))


def checkpoint_for(lab_id: str, spec: dict) -> dict:
    """A simulated or documented packet and the interaction spec for it. The packet is embedded unchanged; every field the spec names must exist in it."""
    if spec.get("kind") == "study":
        return study_for(lab_id, spec)
    f = ROOT / spec["packet"]
    raw = f.read_bytes()
    packet = json.loads(raw)
    kind = spec.get("kind", "modes")
    def resolves(path):
        try:
            return _dig(packet, path) is not None
        except (KeyError, TypeError):
            return False
    if kind == "modes":
        modes = {m["mode"]: m for m in packet["modes"]}
        if sorted(modes) != sorted(spec["order"]):
            raise SystemExit(f"{lab_id}: order {spec['order']} does not match the packet's modes {sorted(modes)}")
        fields = set().union(*[m.keys() for m in modes.values()])
        need = [x["field"] for k in ("setup", "outcome", "diff", "decisive") for x in spec.get(k, [])]
        for pr in spec["predictions"]:
            if pr["field"] != "derived":
                need.append(pr["field"])
            if pr.get("reason_field"):
                need.append(pr["reason_field"])
            d = pr.get("derived")
            if d:
                need.append(d["at"] if d["kind"] == "within" else d["a"])
                if d["kind"] == "equals" and not resolves(d["b_packet"]):
                    raise SystemExit(f"{lab_id}: packet has no {d['b_packet']}")
                w = d.get("window", {})
                if "packet_path" in w and not (resolves(w["packet_path"] + "." + w["from"]) and resolves(w["packet_path"] + "." + w["to"])):
                    raise SystemExit(f"{lab_id}: window {w} does not resolve")
                if "lookup" in w:
                    lk = w["lookup"]; need.append(lk["by"])
                    if not all(w["from"] in c and w["to"] in c for c in _dig(packet, lk["list"])):
                        raise SystemExit(f"{lab_id}: lookup window fields are missing")
            if pr["options"] == "from_packet":
                pr["options"] = list(dict.fromkeys(modes[m][pr["field"]] for m in spec["order"] if pr["field"] in modes[m]))
        missing = [n for n in need if n not in fields]
        if missing:
            raise SystemExit(f"{lab_id}: the packet's modes have no field {missing}")
    else:
        items = _dig(packet, spec["items_path"])
        keys = set().union(*[i.keys() for i in items])
        bad = [c[0] for c in spec["columns"] if c[0] not in keys] + [q["where"]["field"] for q in spec["questions"] if q["where"]["field"] not in keys]
        if bad:
            raise SystemExit(f"{lab_id}: the packet's items have no field {bad}")
        for q in spec["questions"]:
            if clean(q["quote"]["text"]) not in source_text(ROOT / q["quote"]["file"]):
                raise SystemExit(f"quote for {q['id']} is not in {q['quote']['file']}")
    for k in ("context", "packet_facts"):
        for x in spec.get(k, []):
            if not resolves(x["path"]):
                raise SystemExit(f"{lab_id}: packet has no {x['path']}")
    for k in ("tables", "lists"):
        for x in spec.get(k, []):
            if not isinstance(_dig(packet, x["path"]), list):
                raise SystemExit(f"{lab_id}: {x['path']} is not a list in the packet")
    body = {k: v for k, v in spec.items() if k not in ("packet", "spl")}
    return {"kind": "checkpoint", "packet_file": spec["packet"], "sha256": hashlib.sha256(raw).hexdigest(), "packet": packet, "spec": body, "spl": spl_for(spec["spl"])}


def _t(v) -> str:
    return v if isinstance(v, str) else json.dumps(v)


def _walk(o, path: str) -> list:
    """Every value at a dotted path; a trailing [] on a key steps into each element of that list."""
    cur = [o]
    for part in path.split("."):
        many = part.endswith("[]")
        key = part[:-2] if many else part
        cur = [(c[int(key)] if isinstance(c, list) else c[key]) if key else c for c in cur]
        if many:
            cur = [x for c in cur for x in c]
    return cur


def _keep(item, w) -> bool:
    if isinstance(w, list):   # every condition must hold
        return all(_keep(item, x) for x in w)
    v = _t(_walk(item, w["field"])[0]) if "field" in w else item
    if "equals" in w:
        return v == w["equals"]
    if "not_equals" in w:
        return v != w["not_equals"]
    if "contains" in w:
        return w["contains"].lower() in v.lower()
    return w["not_contains"].lower() not in v.lower()


def _sel(packet: dict, s: dict) -> list[str]:
    """A list of strings read from the committed sources. Used for both the options a learner sees and the answer, so no answer is typed beside its question."""
    if "literal" in s:
        return list(s["literal"])
    if "value" in s:
        return [_t(x) for x in _walk(packet, s["value"])]
    if "count" in s:   # distinct values at a path
        return [str(len({_t(x) for x in _walk(packet, s["count"])}))]
    if "keys" in s:
        return list(_walk(packet, s["keys"])[0])
    if "minus" in s:
        a, b = (_sel(packet, x) for x in s["minus"])
        return [x for x in a if x not in b]
    if "quote_token" in s:
        q = s["quote_token"]
        if clean(q["text"]) not in source_text(ROOT / q["file"]) or q["token"] not in q["text"]:
            raise SystemExit(f"quote_token {q['text']!r} is not in {q['file']} or does not contain {q['token']!r}")
        return [q.get("answer", q["token"])]
    items = bullets(md_sections((ROOT / s["bullets"]["file"]).read_text(encoding="utf-8"))[s["bullets"]["section"]]) if "bullets" in s else _walk(packet, s["items"])
    items = [i for i in items if _keep(i, s["where"])] if "where" in s else items
    vals = [x for i in items for x in (_walk(i, s["pick"]) if "pick" in s else [i])]
    return list(dict.fromkeys(_t(y) for x in vals for y in (x if isinstance(x, list) else [x])))


def study_for(lab_id: str, spec: dict) -> dict:
    """Documented or recorded sources read as one study. Each question's options and answer are computed from the sources; every quoted line must be in its file."""
    packet: dict = {}
    files = []
    for name, f in spec["sources"].items():
        raw = (ROOT / f).read_bytes()
        packet[name] = json.loads(raw)
        files.append({"name": name, "file": f, "sha256": hashlib.sha256(raw).hexdigest()})
    for name, j in spec.get("jsonl", {}).items():   # a native report: chosen rows, chosen fields, values unchanged; the hash is of the whole file
        raw = (ROOT / j["file"]).read_bytes()
        rows = [json.loads(l) for l in raw.decode("utf-8").splitlines() if l.strip()]
        packet[name] = {t: [({k: r[k] for k in keep} if keep else r) for r in rows if r.get("entry_type") == t] for t, keep in j["rows"].items()}
        files.append({"name": name, "file": j["file"], "sha256": hashlib.sha256(raw).hexdigest()})
    for st in spec["steps"]:
        for q in st["questions"]:
            q["candidates"], q["answer"] = _sel(packet, q["candidates"]), _sel(packet, q["answer"])
            if not q["answer"] or not set(q["answer"]) <= set(q["candidates"]) or (q["mode"] == "single" and len(q["answer"]) != 1) or len(q["candidates"]) < 2:
                raise SystemExit(f"{lab_id} {q['id']}: options {q['candidates']} and answer {q['answer']} do not make a question")
            if "quote" in q and clean(q["quote"]["text"]) not in source_text(ROOT / q["quote"]["file"]):
                raise SystemExit(f"quote for {q['id']} is not in {q['quote']['file']}")
    for k in ("documented", "limits"):
        for x in spec.get(k, []):
            if clean(x["text"]) not in source_text(ROOT / x["file"]):
                raise SystemExit(f"{lab_id}: {k} line {x['text']!r} is not in {x['file']}")
    paths = [x["path"] for k in ("facts", "tables", "lists") for x in spec.get(k, [])]
    if "compare" in spec:
        c = spec["compare"]
        paths += [c["left"]["path"], c["right"]["path"], c["need"]["path"]]
    for pth in paths:
        if not _walk(packet, pth):
            raise SystemExit(f"{lab_id}: the sources have no {pth}")
    for x in spec.get("tables", []) + spec.get("lists", []):
        if not _walk(packet, x["path"])[0]:
            raise SystemExit(f"{lab_id}: {x['path']} is empty")
    body = {k: v for k, v in spec.items() if k not in ("sources", "jsonl", "spl")}
    return {"kind": "checkpoint", "packet_file": files[0]["file"], "sha256": files[0]["sha256"], "files": files, "packet": packet, "spec": body, "spl": spl_for(spec.get("spl", []))}


def write_recorded(lab_id: str, data: dict) -> dict:
    """Large evidence is written to its own file and loaded on demand, so it stays out of the main JavaScript bundle."""
    dest = ROOT / "academy-ui" / "src" / "content" / "recorded"
    dest.mkdir(parents=True, exist_ok=True)
    (dest / f"{lab_id}.json").write_text(json.dumps(data, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
    return {"kind": data["kind"], "file": f"{lab_id}.json"}


def explainer_for(lab_id: str) -> dict | None:
    """Embed the hand-written explainer, resolving every reference to the real source text so nothing is retyped."""
    path = EXPL / f"{lab_id}.json"
    if not path.exists():
        return None
    e = json.loads(path.read_text(encoding="utf-8"))
    for item in e.get("practice", {}).get("predict", []):
        f, _, dotted = item["source"].partition("#")
        item["text"] = clean(_dig(json.loads((ROOT / f).read_text(encoding="utf-8")), dotted))
    wb = e.get("workbench")
    if wb:
        wb["resolved"] = {}
        for key, ref in wb["texts"].items():
            f, _, dotted = ref.partition("#")
            wb["resolved"][key] = {"text": clean(_dig(json.loads((ROOT / f).read_text(encoding="utf-8")), dotted)), "source": ref}
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
    if "checkpoint" in e:
        e["recorded_ref"] = write_recorded(lab_id, checkpoint_for(lab_id, e.pop("checkpoint")))
    elif "investigation" in e:
        e["recorded_ref"] = write_recorded(lab_id, investigation_for(lab_id, e.pop("investigation")))
    elif e.get("recorded", {}).get("lazy"):
        spec = e.pop("recorded"); spec.pop("lazy")
        e["recorded_ref"] = write_recorded(lab_id, {"kind": "decision", **recorded_for(lab_id, spec)})
    elif "recorded" in e:
        e["recorded"] = recorded_for(lab_id, e["recorded"])
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
            "explainer": explainer_for(lab_id), "integrated": bool((LEARN / "academy" / "explainers" / f"{lab_id}.json").exists() and "workbench" in json.loads((LEARN / "academy" / "explainers" / f"{lab_id}.json").read_text(encoding="utf-8"))),
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
