"""Curriculum Explorer: coverage of the 12 domains and 32 registered labs, availability honesty, and provenance of every sentence shown."""

from __future__ import annotations

import importlib.util
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("export_curriculum", ROOT / "scripts" / "export_curriculum.py")
EXP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXP)
DATA = json.loads((ROOT / "academy-ui" / "src" / "content" / "curriculum.json").read_text(encoding="utf-8"))
REGISTRY = {e["lab_id"]: e for e in json.loads((ROOT / "learning" / "academy" / "lab_registry_data.json").read_text(encoding="utf-8"))["entries"]}
TIER = {"GUIDED MISSION": "guided", "WORKBENCH": "workbench", "REPLAY": "replay", "CONTENT-ONLY": "content_only"}


def test_export_matches_its_sources():
    assert json.loads(json.dumps(EXP.build(), ensure_ascii=False)) == DATA


def test_twelve_domains_and_thirty_two_labs_each_registered_once():
    assert [d["id"] for d in DATA["domains"]] == [f"D{i:02d}" for i in range(1, 13)]
    ids = [l["id"] for l in DATA["labs"]]
    assert len(ids) == 32 == len(set(ids)) and set(ids) == set(REGISTRY)
    assert {l["primary_domain"] for l in DATA["labs"]} <= {d["id"] for d in DATA["domains"]}
    assert not [l for l in DATA["labs"] if l["primary_domain"] == "D01"], "D01 has no registered lab; the Explorer must say so rather than invent one"


def test_availability_is_the_registry_tier_and_nothing_stronger():
    from agentsec.launch_catalog import known_lab_ids
    for l in DATA["labs"]:
        assert l["availability"] == TIER[REGISTRY[l["id"]]["tier"]] and l["primary_domain"] == REGISTRY[l["id"]]["primary_domain"]
    assert {l["id"] for l in DATA["labs"] if l["launchable"]} == set(known_lab_ids())
    assert {l["id"] for l in DATA["labs"] if l["native"]} == {"LAB-LOANDESK-001", "LAB-MCP-001"}
    assert {l["id"] for l in DATA["labs"] if l["availability"] == "guided"} == {"LAB-LOANDESK-001", "LAB-MCP-001"}


def _plain(path: Path) -> str:
    if path.suffix == ".json":
        strings: list[str] = []
        def walk(o):
            if isinstance(o, str): strings.append(EXP.clean(o))
            elif isinstance(o, dict): [(strings.append(EXP.clean(k)), walk(v)) for k, v in o.items()]
            elif isinstance(o, list): [walk(v) for v in o]
        doc = json.loads(path.read_text(encoding="utf-8")); walk(doc)
        lim = doc.get("limitations") if isinstance(doc, dict) else None
        if isinstance(lim, list): strings.append(EXP.clean(" ".join(lim[:4])))
        return "\n".join(strings)
    if path.suffix == ".xml":
        root = ET.parse(path).getroot()
        return EXP.clean(" ".join(root.itertext())).replace('\\"', '"')
    return EXP.clean(path.read_text(encoding="utf-8"))


def test_every_sentence_shown_to_learners_appears_in_the_file_it_cites():
    problems = []
    for l in DATA["labs"]:
        for key, e in l["sections"].items():
            if not e:
                continue
            src = ROOT / e["source"].split("#")[0]
            if not src.is_file():
                problems.append((l["id"], key, "missing source")); continue
            hay = _plain(src)
            texts = e["items"] if "items" in e else [e["text"]]
            for t in texts:
                if t.removesuffix(" …").strip() not in hay:
                    problems.append((l["id"], key, t[:60]))
        if l["registry_quote"] and l["registry_quote"]["quote"] not in (ROOT / l["registry_quote"]["file"]).read_text(encoding="utf-8"):
            problems.append((l["id"], "registry_quote", "not verbatim"))
        if l["checks"]:
            hay = _plain(ROOT / l["checks_source"])
            problems += [(l["id"], "check", c["q"][:50]) for c in l["checks"] if c["q"] not in hay or (c["a"] and c["a"] not in hay)]
    assert not problems, problems[:8]


def test_every_lab_has_at_least_one_sourced_statement_and_asset_paths_exist():
    for l in DATA["labs"]:
        assert l["sections"]["idea"], f"{l['id']} has no sourced statement at all"
        d = ROOT / "learning" / "level_1" / l["id"]
        assert all((d / "specimens" / s).exists() for s in l["assets"]["specimens"]) and all((d / "searches" / h).exists() for h in l["assets"]["hunts"])
        if l["assets"]["dashboard"]:
            assert (ROOT / "splunk_app/agentsec/default/data/ui/views" / f"{l['assets']['dashboard']}.xml").is_file()


def test_ui_never_describes_registry_membership_as_verified_execution():
    ui = ROOT / "academy-ui" / "src"
    cur = (ui / "curriculum.ts").read_text(encoding="utf-8")
    assert "Registry membership is not verified execution" in cur
    blurbs = cur[cur.index("export const AVAIL"): cur.index("export const AVAIL_ORDER")]
    assert "verified" not in blurbs.lower() and "validated" not in blurbs.lower()
    for rel in ("pages/Curriculum.tsx", "pages/Lab.tsx"):
        text = (ui / rel).read_text(encoding="utf-8")
        assert "REGISTRY_NOTE" in text, f"{rel} must show the registry note"
        assert "ws_lab_" not in re.sub(r"\{a\.dashboard\}", "", text) or "not linked" in text


def test_inventory_document_covers_every_lab_domain_and_keeps_the_distinctions():
    doc = (ROOT / "docs" / "curriculum" / "CURRICULUM_INVENTORY_2026-10-23.md").read_text(encoding="utf-8")
    assert "2026-10-23" in doc and "Registry membership is not verified execution" in doc
    for lab in REGISTRY:
        assert f"`{lab}`" in doc, lab
    for d in DATA["domains"]:
        assert f"{d['id']} {d['name']}" in doc
    for term in ("Registered", "Launchable", "Replay", "Content only", "Independently validated", "https://github.com/uber/ADR"):
        assert term in doc


def _explained():
    return [(l["id"], l["explainer"]) for l in DATA["labs"] if l["explainer"]]


def test_explainer_facts_and_quotes_appear_verbatim_in_their_cited_sources():
    problems = []
    for lab, e in _explained():
        def cited(grounds):
            return "\n".join(_plain(ROOT / g.split("#")[0]) for g in grounds)
        for block in ([e["summary"]] if e.get("summary") else []) + e.get("glance", []) + e.get("known", []) + ([e["practice"]["defender"]] if e.get("practice", {}).get("defender") else []):
            hay = cited(block["grounds"])
            problems += [(lab, f[:50]) for f in block["facts"] if EXP.clean(f) not in hay]
        for n in e.get("path", []):
            for node in [n] + n.get("outcomes", []):
                if EXP.clean(node["fact"]) not in _plain(ROOT / node["source"]):
                    problems.append((lab, "path", node["fact"][:50]))
        for t in e.get("terms", []):
            if EXP.clean(t["fact"]) not in _plain(ROOT / t["source"]):
                problems.append((lab, "term", t["term"]))
        for i in e.get("identifiers", []):
            if EXP.clean(i["value"].split(",")[0]) not in _plain(ROOT / i["source"]):
                problems.append((lab, "identifier", i["label"]))
        for q in e.get("spl", []):
            if q["text"] != (ROOT / q["source"]).read_text(encoding="utf-8").strip():
                problems.append((lab, "spl", q["name"]))
        hay = _plain(ROOT / e["recorded_table"]["source"]) if e.get("recorded_table") else ""
        problems += [(lab, "table", c[:40]) for r in (e.get("recorded_table") or {}).get("rows", []) for c in r if c and EXP.clean(c) not in hay]
        cc = e.get("cannot_claim")
        if cc:
            hay = _plain(ROOT / cc["source"].split("#")[0])
            problems += [(lab, "cannot_claim", x[:40]) for x in cc["items"] if EXP.clean(x) not in hay]
        for p in e.get("practice", {}).get("predict", []):
            f, _, dotted = p["source"].partition("#")
            doc = json.loads((ROOT / f).read_text(encoding="utf-8"))
            for part in dotted.split("."):
                doc = doc[part]
            if p["text"] != EXP.clean(doc):
                problems.append((lab, "predict", p["label"]))
    assert not problems, problems[:8]


def test_pi_001_explainer_covers_the_requested_topics_and_the_path_has_no_invented_steps():
    e = dict(_explained())["LAB-PI-001"]
    assert e["status"] == "full" and {g["id"] for g in e["glance"]} == {"goal", "input", "entry", "boundary", "control", "impact", "evidence"}
    assert [n["kind"] for n in e["path"]] == ["attacker", "entry", "boundary", "control", "operation", "evidence"]
    assert all(n["fact"] and n["source"].endswith((".md", ".json")) for n in e["path"]), "every path node cites a fact and a source file"
    assert {o["label"] for o in e["path"][3]["outcomes"]} == {"DENY or ERROR", "ALLOW"}
    assert e["recorded_table"]["columns"] == ["Run", "Expected", "Actual"] and len(e["recorded_table"]["rows"]) == 4


def test_credential_lifetime_was_the_thin_lab_and_is_now_a_full_checkpoint_that_stays_content_only():
    # Increment 11D upgraded it from a partial explainer (no summary, no glance) to a full simulated-packet checkpoint; its registry tier is unchanged.
    e = dict(_explained())["LAB-CREDENTIAL-LIFETIME"]
    assert e["status"] == "full" and e["summary"] and e["glance"] and e["recorded_ref"]["kind"] == "checkpoint"
    lab = next(l for l in DATA["labs"] if l["id"] == "LAB-CREDENTIAL-LIFETIME")
    assert lab["availability"] == "content_only" and not lab["assets"]["specimens"] and not lab["checks"]


def test_lab_template_suppresses_empty_sections_and_labels_what_each_block_is():
    ui = ROOT / "academy-ui" / "src"
    lab = (ui / "pages" / "Lab.tsx").read_text(encoding="utf-8")
    assert "Full guided lesson not yet available" in lab and "AttackPath" in lab and "Not documented for this lab" not in lab
    for label in ("EXPLANATION", "QUOTED FROM THE LAB", "RECORDED, NOT RE-RUN"):
        assert label in lab
    assert "tabs.some" in lab and "hasPractice" in lab and "hasProve" in lab, "tabs without supported content must not render"
    path = (ui / "AttackPath.tsx").read_text(encoding="utf-8")
    assert "not what happened in a run" in path and "<ol" in path


def test_pi_workbench_uses_only_the_existing_launch_contract_and_never_auto_launches():
    import re
    ui = ROOT / "academy-ui" / "src" / "workbench"
    launch = (ui / "launch.ts").read_text(encoding="utf-8")
    urls = set(re.findall(r'"(/api/[^"?`]*)', launch)) | set(re.findall(r"`(/api/[^`$?]*)", launch))
    assert urls == {"/api/launch", "/api/launches/", "/api/compare-handoff"}, urls
    assert 'execution: "live"' in launch and "retry" not in launch.lower().replace("nothing was retried", "").replace("never retries", "")
    page = (ui / "PiWorkbench.tsx").read_text(encoding="utf-8")
    assert page.count("launchLab(") == 1 and "const run = async" in page, "the only launch call is inside the button handler"
    assert "if (inflight.current) return" in page, "a second press while one is in flight must be ignored"
    effects = "\n".join(re.findall(r"useEffect\(\(\) => \{.*?\}, \[", page, re.S))
    assert "launchLab" not in effects and "run(" not in effects, "no effect may start a launch"
    for text in (launch, page, (ui / "pi.ts").read_text(encoding="utf-8")):
        assert "SPLUNK-VERIFIED" not in text, "this lab has no signed verifier, so the UI must never claim SPLUNK-VERIFIED"
    assert "No. This lab has no signed verifier" in page


@pytest.mark.parametrize("lab_id", ["LAB-PI-001", "LAB-RAG-CONTEXT", "LAB-AGENT-GOAL-INTEGRITY-001", "LAB-AGENT-DELEGATION-001", "LAB-MEMORY-001", "LAB-AGENTSEC-CAPSTONE-001"])
def test_workbench_matches_the_backend_allowlist_and_runtime_fields(lab_id):
    from agentsec.launch_catalog import allowlist_public_rows
    from agentsec.launch_contract import parse_launch_json
    wb = dict(_explained())[lab_id]["workbench"]
    rows = {(r["mode"], r["specimen_id"]) for r in allowlist_public_rows() if r["lab_id"] == lab_id}
    assert rows == set(wb["specimens"].items())
    for mode, spec in wb["specimens"].items():
        parsed = parse_launch_json(json.dumps({"lab_id": lab_id, "specimen_id": spec, "mode": mode, "execution": "live"}))
        assert parsed.ok and parsed.lab_id == lab_id
    if lab_id == "LAB-PI-001":
        pipeline = (ROOT / "src" / "agentsec" / "pipeline.py").read_text(encoding="utf-8")
        for key in ("control.decision", "control.reason", "operation.attempted", "operation.executed", "operation.outcome", "llm.started", "llm.completed", "llm.failed"):
            assert f'"{key}"' in pipeline, key
    for key, ref in wb["texts"].items():
        f, _, dotted = ref.partition("#")
        doc = json.loads((ROOT / f).read_text(encoding="utf-8"))
        for part in dotted.split("."):
            doc = doc[part]
        assert wb["resolved"][key]["text"] == EXP.clean(doc)


def test_only_the_six_native_labs_are_integrated_and_the_registry_tier_is_unchanged():
    assert [l["id"] for l in DATA["labs"] if l["integrated"]] == ["LAB-AGENT-DELEGATION-001", "LAB-AGENT-GOAL-INTEGRITY-001", "LAB-AGENTSEC-CAPSTONE-001", "LAB-MEMORY-001", "LAB-PI-001", "LAB-RAG-CONTEXT"]
    for lab in ("LAB-PI-001", "LAB-RAG-CONTEXT", "LAB-AGENT-GOAL-INTEGRITY-001", "LAB-AGENT-DELEGATION-001", "LAB-MEMORY-001", "LAB-AGENTSEC-CAPSTONE-001"):
        assert next(l for l in DATA["labs"] if l["id"] == lab)["availability"] == "workbench"
    e = next(l for l in DATA["labs"] if l["id"] == "LAB-RAG-CONTEXT")["explainer"]
    assert [n["kind"] for n in e["path"]] == ["attacker", "entry", "boundary", "control", "control", "operation", "evidence"]
    assert {g["id"] for g in e["glance"]} == {"goal", "controls", "entry", "boundary", "control", "impact", "evidence"}
    for lab, kinds in (("LAB-MEMORY-001", ["attacker", "entry", "boundary", "control", "control", "operation", "evidence"]), ("LAB-AGENTSEC-CAPSTONE-001", ["attacker", "entry", "boundary", "control", "control", "operation", "evidence"]), ("LAB-AGENT-GOAL-INTEGRITY-001", ["attacker", "entry", "boundary", "control", "control", "operation", "evidence"]), ("LAB-AGENT-DELEGATION-001", ["attacker", "entry", "boundary", "control", "control", "operation", "evidence"])):
        e = next(l for l in DATA["labs"] if l["id"] == lab)["explainer"]
        assert [n["kind"] for n in e["path"]] == kinds and e["status"] == "full"
