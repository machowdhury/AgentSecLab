#!/usr/bin/env python3
"""Curriculum preservation harness. Runs the SAME probes against two source trees (the original baseline export and
the current branch) and compares what a learner would see and what the labs would do. It reads source trees and
starts in-process Flask apps with a labelled stub LLM; it never touches Docker, Splunk or the running lab.

  collect --tree DIR --out FILE      run every probe against the code under DIR (cwd and PYTHONPATH must point at DIR)
  compare --base FILE --head FILE    print the differences, classified

Probes: (1) sha256 of every learning file, Splunk view and search, (2) crawl of the Academy, Attack UI and Banking UI
(status, title, headings, control counts, link targets, visible-text digest), (3) every GET route without a path parameter,
(4) all 21 LIVE launches: HTTP result, normalised response and the ordered event/decision sequence, (5) the registry
and curriculum structure.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from html.parser import HTMLParser
from pathlib import Path


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()[:16]


def tree_hashes(root: Path, rel: str) -> dict:
    base = root / rel
    return {str(p.relative_to(root)): sha(p.read_bytes()) for p in sorted(base.rglob("*")) if p.is_file() and "__pycache__" not in p.parts}


class Facts(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title, self.headings, self.hrefs, self.text, self.counts = "", [], set(), [], {}
        self._in, self._skip = None, 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ("script", "style"):
            self._skip += 1
        if tag in ("button", "input", "select", "textarea", "form", "table", "dialog", "details", "svg", "img"):
            self.counts[tag] = self.counts.get(tag, 0) + 1
        if tag == "a" and a.get("href"):
            self.counts["a"] = self.counts.get("a", 0) + 1
            self.hrefs.add(a["href"])
        if tag in ("title", "h1", "h2", "h3", "h4"):
            self._in = tag
            self._buf = []

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self._skip -= 1
        if self._in == tag:
            t = " ".join("".join(self._buf).split())
            if tag == "title":
                self.title = t
            elif t:
                self.headings.append(f"{tag}:{t}")
            self._in = None

    def handle_data(self, data):
        if self._skip:
            return
        if self._in:
            self._buf.append(data)
        self.text.append(data)


def page_facts(body: str) -> dict:
    f = Facts()
    f.feed(body)
    text = " ".join(" ".join(f.text).split())
    text = re.sub(r"Version \d+\.\d+\.\d+", "Version X", text)
    return {"title": f.title, "headings": f.headings, "counts": dict(sorted(f.counts.items())), "hrefs": sorted(f.hrefs),
            "text_sha": sha(text.encode()), "words": len(text.split())}


UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
TS = re.compile(r"\d{4}-\d{2}-\d{2}T[\d:.]+Z?")
HEX = re.compile(r"\b[0-9a-f]{16}\b|\b[0-9a-f]{32}\b")  # random span and trace ids


def norm_json(x):
    s = json.dumps(x, sort_keys=True)
    return json.loads(HEX.sub("<id>", TS.sub("<ts>", UUID.sub("<uuid>", s))))


def collect(tree: Path, out: Path) -> None:
    os.chdir(tree)
    sys.path.insert(0, str(tree / "src"))
    tmp = tempfile.mkdtemp(prefix="pres-")
    os.environ.update(AGENTSEC_OTEL_ENABLED="false", AGENTSEC_SECURITY_PROFILE="defended", AGENTSEC_ARTIFACTS_DIR=tmp,
                      AGENTSEC_LAB_ID="agentsec-local", AGENTSEC_SPLUNK_WEB_URL="http://127.0.0.1:8000")
    os.environ.pop("AGENTSEC_TESTBED_MODE", None)
    from agentsec.attack_app import AcmeBankClient, create_app as create_attack
    from agentsec.bank_app import build_runtime, create_app as create_bank
    from agentsec.launch_catalog import LAUNCH_ALLOWLIST
    from agentsec.llm import StubLLM
    from agentsec.settings import get_settings

    res: dict = {"tree": str(tree)}
    reg = json.loads((tree / "learning/academy/lab_registry_data.json").read_text())["entries"]
    cur = json.loads((tree / "learning/academy/curriculum.json").read_text())
    res["registry_ids"] = sorted(e["lab_id"] for e in reg)
    res["registry"] = {e["lab_id"]: {k: e.get(k) for k in ("tier", "primary_domain", "secondary_domain", "pillars", "domain_confidence")} for e in reg}
    res["curriculum_path"] = [[lv.get("title"), [(l["lab_id"], l["mode"], l.get("view")) for l in lv.get("labs", [])]] for lv in cur["levels"]]
    res["curriculum_checkpoints"] = cur["checkpoints"]
    res["nav_collections"] = cur["nav_collections"]
    # 1. files
    labs = sorted(p.name for p in (tree / "learning/level_1").iterdir() if p.is_dir())
    res["lab_files"] = {lab: tree_hashes(tree, f"learning/level_1/{lab}") for lab in labs}
    views = tree / "splunk_app/agentsec/default/data/ui/views"
    res["splunk_views"] = {p.name: sha(p.read_bytes()) for p in sorted(views.glob("*.xml"))}
    res["splunk_static"] = tree_hashes(tree, "splunk_app/agentsec/appserver/static")
    res["splunk_conf"] = {p.name: sha(p.read_bytes()) for p in sorted((tree / "splunk_app/agentsec/default").glob("*.conf"))}
    res["assets"] = {p: sha((tree / p).read_bytes()) for p in sorted(str(q.relative_to(tree)) for q in (tree / "src/agentsec/static").glob("*") if q.is_file())}
    res["templates"] = tree_hashes(tree, "src/agentsec/templates")

    # apps (in-process, test doubles only for the LLM)
    settings = get_settings()
    rt = build_runtime(settings, llm=StubLLM(), otel_enabled=False)
    bank = create_bank(rt)
    bank.config["TESTING"] = True
    bc = bank.test_client()

    def post_fn(path, payload):
        r = bc.post(path, json=payload)
        return r.status_code, r.get_json()

    def get_fn(path):
        r = bc.get(path)
        return r.status_code, (r.get_json() if r.is_json else {})

    attack = create_attack(AcmeBankClient("http://acmebank-unused", post_fn=post_fn, get_fn=get_fn),
                           launch_kwargs={"probe_fn": lambda rid: {"splunk_attempted": False, "splunk_ok": False, "splunk_count": 0, "error": "stubbed"}})
    attack.config["TESTING"] = True
    ac = attack.test_client()

    # 2. crawl
    def crawl(client, seeds, tag):
        seen, queue, out_pages = set(), list(seeds), {}
        while queue and len(seen) < 120:
            url = queue.pop(0)
            if url in seen or not url.startswith("/") or url.startswith("//") or url.startswith("/static"):
                continue
            seen.add(url)
            r = client.get(url)
            ctype = r.headers.get("Content-Type", "")
            facts = {"status": r.status_code, "type": ctype.split(";")[0]}
            if "html" in ctype:
                pf = page_facts(r.get_data(as_text=True))
                facts.update(pf)
                for h in pf["hrefs"]:
                    queue.append(h.split("#")[0] or url)
            elif r.is_json:
                facts["json_keys"] = sorted(r.get_json().keys()) if isinstance(r.get_json(), dict) else "list"
            out_pages[url] = facts
        res[tag] = out_pages

    lab_ids = [e["lab_id"] for e in reg]
    crawl(ac, ["/", "/academy", "/acmebank", "/academy/foundations", "/academy/path", "/academy/status", "/academy/labs/LAB-MCP-001"] + [f"/labs/{l}" for l in lab_ids], "attack_ui_pages")
    crawl(bc, ["/", "/health"], "banking_ui_pages")

    # 3. GET routes without parameters
    def routes(app, client, tag):
        got = {}
        for rule in sorted(app.url_map.iter_rules(), key=lambda r: r.rule):
            if "GET" in rule.methods and "<" not in rule.rule and not rule.rule.startswith("/static"):
                r = client.get(rule.rule)
                got[rule.rule] = {"status": r.status_code, "type": r.headers.get("Content-Type", "").split(";")[0]}
        res[tag] = got
    routes(attack, ac, "attack_routes")
    routes(bank, bc, "bank_routes")
    res["attack_all_rules"] = sorted(f"{sorted(r.methods - {'HEAD', 'OPTIONS'})} {r.rule}" for r in attack.url_map.iter_rules() if not r.rule.startswith("/static"))
    res["bank_all_rules"] = sorted(f"{sorted(r.methods - {'HEAD', 'OPTIONS'})} {r.rule}" for r in bank.url_map.iter_rules() if not r.rule.startswith("/static"))

    # 4. launches
    launches = {}
    for spec in LAUNCH_ALLOWLIST:
        before = len(rt.memory.snapshot())
        r = ac.post("/api/launch", json={"lab_id": spec.lab_id, "specimen_id": spec.specimen_id, "mode": spec.mode, "execution": "live"})
        body = r.get_json() or {}
        run_id = body.get("run_id") or (body.get("launch") or {}).get("run_id")
        evs = [e for e in rt.memory.snapshot()[before:] if (not run_id) or e.get("agentsec.run.id") == run_id]
        seq = [[e.get("event.name"), e.get("agentsec.control.id"), e.get("agentsec.control.decision"), e.get("gen_ai.tool.name"),
                e.get("agentsec.mcp.executed") if "agentsec.mcp.executed" in e else e.get("agentsec.action.executed")] for e in sorted(evs, key=lambda e: e.get("agentsec.sequence", 0))]
        launches[f"{spec.lab_id}|{spec.specimen_id}|{spec.mode}"] = {"http": r.status_code, "response": norm_json(body), "events": len(evs), "sequence": seq}
    res["launches"] = launches
    legacy = ac.post("/api/attacks/ATK-002", json={})
    res["legacy_atk002"] = {"http": legacy.status_code, "keys": sorted((legacy.get_json() or {}).keys())}
    out.write_text(json.dumps(res, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"collected {len(res['launches'])} launches, {len(res['attack_ui_pages'])} attack pages, {len(res['banking_ui_pages'])} banking pages -> {out}")


def compare(base: Path, head: Path) -> dict:
    b, h = json.loads(base.read_text()), json.loads(head.read_text())
    rep: dict = {"per_lab": {}, "global": {}}
    ids = b["registry_ids"]
    for lab in ids:
        r = {"files_changed": [], "files_removed": [], "files_added": [], "registry_changed": [], "launches": [], "pages": []}
        bf, hf = b["lab_files"].get(lab, {}), h["lab_files"].get(lab, {})
        r["files_changed"] = sorted(k for k in bf if k in hf and bf[k] != hf[k])
        r["files_removed"] = sorted(k for k in bf if k not in hf)
        r["files_added"] = sorted(k for k in hf if k not in bf)
        if b["registry"][lab] != h["registry"].get(lab):
            r["registry_changed"] = [k for k in b["registry"][lab] if b["registry"][lab][k] != h["registry"].get(lab, {}).get(k)]
        for k in b["launches"]:
            if k.startswith(lab + "|") and b["launches"][k] != h["launches"].get(k):
                r["launches"].append(k)
        for url in b["attack_ui_pages"]:
            if url == f"/labs/{lab}" and b["attack_ui_pages"][url] != h["attack_ui_pages"].get(url):
                r["pages"].append(url)
        rep["per_lab"][lab] = r
    g = rep["global"]
    g["registry_ids_missing_in_head"] = sorted(set(ids) - set(h["registry_ids"]))
    g["registry_ids_added_in_head"] = sorted(set(h["registry_ids"]) - set(ids))
    bv, hv = b["splunk_views"], h["splunk_views"]
    g["views_changed"] = sorted(k for k in bv if k in hv and bv[k] != hv[k])
    g["views_removed"] = sorted(set(bv) - set(hv))
    g["views_added"] = sorted(set(hv) - set(bv))
    g["splunk_static_changed"] = sorted(k for k in b["splunk_static"] if k in h["splunk_static"] and b["splunk_static"][k] != h["splunk_static"][k])
    g["splunk_static_removed"] = sorted(set(b["splunk_static"]) - set(h["splunk_static"]))
    g["splunk_conf_changed"] = sorted(k for k in b["splunk_conf"] if b["splunk_conf"][k] != h["splunk_conf"].get(k))
    g["assets_changed"] = sorted(k for k in b["assets"] if k in h["assets"] and b["assets"][k] != h["assets"][k])
    g["assets_removed"] = sorted(set(b["assets"]) - set(h["assets"]))
    g["templates_changed"] = sorted(k for k in b["templates"] if k in h["templates"] and b["templates"][k] != h["templates"][k])
    g["templates_removed"] = sorted(set(b["templates"]) - set(h["templates"]))
    for tag in ("attack_ui_pages", "banking_ui_pages"):
        g[tag + "_changed"] = {u: {k: [b[tag][u].get(k), h[tag].get(u, {}).get(k)] for k in set(b[tag][u]) | set(h[tag].get(u, {})) if b[tag][u].get(k) != h[tag].get(u, {}).get(k)}
                               for u in b[tag] if b[tag][u] != h[tag].get(u)}
        g[tag + "_missing_in_head"] = sorted(set(b[tag]) - set(h[tag]))
        g[tag + "_new_in_head"] = sorted(set(h[tag]) - set(b[tag]))
    for tag in ("attack_routes", "bank_routes"):
        g[tag + "_changed"] = {u: [b[tag][u], h[tag].get(u)] for u in b[tag] if b[tag][u] != h[tag].get(u)}
        g[tag + "_new_in_head"] = sorted(set(h[tag]) - set(b[tag]))
    g["attack_rules_removed"] = sorted(set(b["attack_all_rules"]) - set(h["attack_all_rules"]))
    g["attack_rules_added"] = sorted(set(h["attack_all_rules"]) - set(b["attack_all_rules"]))
    g["bank_rules_removed"] = sorted(set(b["bank_all_rules"]) - set(h["bank_all_rules"]))
    g["bank_rules_added"] = sorted(set(h["bank_all_rules"]) - set(b["bank_all_rules"]))
    g["legacy_atk002_same"] = b["legacy_atk002"] == h["legacy_atk002"]
    g["launches_same"] = {k: (b["launches"][k] == h["launches"].get(k)) for k in b["launches"]}
    g["curriculum_path_same_prefix"] = all(
        [tuple(l) for l in lv[1]] == [tuple(l) for l in h["curriculum_path"][i][1]][: len(lv[1])] for i, lv in enumerate(b["curriculum_path"]))
    g["checkpoints_same"] = b["curriculum_checkpoints"] == h["curriculum_checkpoints"]
    return rep


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect")
    c.add_argument("--tree", required=True)
    c.add_argument("--out", required=True)
    d = sub.add_parser("compare")
    d.add_argument("--base", required=True)
    d.add_argument("--head", required=True)
    d.add_argument("--out")
    a = ap.parse_args()
    if a.cmd == "collect":
        collect(Path(a.tree).resolve(), Path(a.out).resolve())
    else:
        rep = compare(Path(a.base), Path(a.head))
        text = json.dumps(rep, indent=1, sort_keys=True)
        if a.out:
            Path(a.out).write_text(text + "\n")
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
