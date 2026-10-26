"""Phase 12B: the EVAL Center data, rebuilt from committed evidence by code that is separate from the exporter.

These tests re-read the committed packs, reports, README lines, the 11F collection and the framework file and check every experiment, case, comparison, finding and
metric the Center shows. They also prove the validator refuses scores, invented severity and owners, findings from simulated evidence and uncontrolled comparisons.
"""
from __future__ import annotations

import copy
import glob
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import assurance_model as A  # noqa: E402
import eval_model as V  # noqa: E402

_s = importlib.util.spec_from_file_location("export_evals", ROOT / "scripts" / "export_evals.py")
X = importlib.util.module_from_spec(_s)
_s.loader.exec_module(X)
EXP = X.EXP
OUT = ROOT / "academy-ui/src/content/evals"
sha = lambda b: hashlib.sha256(b).hexdigest()
J = lambda p: json.loads((ROOT / p).read_text(encoding="utf-8"))
CATALOG = J("learning/academy/evals/catalog.json")
REFS = J("learning/academy/framework_refs.json")


@pytest.fixture(scope="module")
def data():
    index = json.loads((OUT / "index.json").read_text(encoding="utf-8"))
    exps = {e["id"]: json.loads((OUT / f"exp-{e['id']}.json").read_text(encoding="utf-8")) for e in index["experiments"]}
    return index, exps


def raw_events(lab, rid):
    p = ROOT / f"learning/level_1/{lab}/specimens/{rid}.jsonl"
    return p, [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]


def test_committed_data_is_valid_and_exactly_what_the_sources_produce(data):
    index, exps = X.build()
    dump = lambda o: json.dumps(o, ensure_ascii=False, indent=1) + "\n"
    assert (OUT / "index.json").read_text(encoding="utf-8") == dump(index)
    for k, e in exps.items():
        assert (OUT / f"exp-{k}.json").read_text(encoding="utf-8") == dump(e)
    assert sorted(p.name for p in OUT.glob("*.json")) == sorted(["index.json"] + [f"exp-{k}.json" for k in exps])
    for e in exps.values():
        assert V.validate_experiment(e, REFS) == []


def test_every_case_source_hash_and_event_is_preserved_exactly(data):
    _, exps = data
    consts = set(EXP.RUN_CONSTANT)
    n = 0
    for e in exps.values():
        if e["kind"] != "pack_triple":
            continue
        for c in e["cases"]:
            rid = c["facts"]["run_id"]
            p, raw = raw_events(e["lab_id"], rid)
            assert c["sources"][0]["sha256"] == sha(p.read_bytes()) and c["sources"][0]["file"] == p.relative_to(ROOT).as_posix()
            assert len(raw) == len(c["timeline"]) == c["facts"]["events_in_pack"]
            for r, t in zip(raw, c["timeline"]):
                assert all(r[k] == v for k, v in t.items()), (rid, t.get("agentsec.sequence"))      # every shown value is the source value
                assert set(r) - set(t) <= consts, (rid, set(r) - set(t))                            # only run-wide constants were moved out
            n += 1
    assert n == 25


def test_case_facts_are_recomputed_from_the_raw_events(data):
    _, exps = data
    for e in exps.values():
        if e["kind"] != "pack_triple":
            continue
        for c in e["cases"]:
            _, raw = raw_events(e["lab_id"], c["facts"]["run_id"])
            dec = [x for x in raw if x["event.name"] == "agentsec.control.decision"]
            assert [(d["control"], d["decision"], d["reason"], d["tool"], d["sequence"]) for d in c["facts"]["decisions"]] == [(x["agentsec.control.id"], x["agentsec.control.decision"], x["agentsec.control.reason"], x.get("gen_ai.tool.name"), x["agentsec.sequence"]) for x in dec]
            starts = [x for x in raw if x["event.name"] == "agentsec.mcp.started"]
            assert [(s["tool"], s["executed"]) for s in c["facts"]["handler_starts"]] == [(x.get("gen_ai.tool.name"), x.get("agentsec.operation.executed")) for x in starts]
            assert c["facts"]["model_calls_started"] == sum(1 for x in raw if x["event.name"] == "agentsec.llm.started")
            assert c["facts"]["run_outcome"] == next(x.get("agentsec.outcome") for x in reversed(raw) if x["event.name"] == "agentsec.run.completed")
            assert c["facts"]["profile"] == c["conditions"]["profile"] and c["verification"] == {"status": "NOT_VERIFIED", "receipt": None}


def test_each_experiment_has_the_right_class_and_roles_and_simulated_evidence_stays_simulated(data):
    index, exps = data
    assert [e["id"] for e in index["experiments"]] == [x["id"] for x in CATALOG["experiments"]]
    for k, e in exps.items():
        assert e["evidence_class"] == ("SIMULATED" if k == "component-provenance" else "RECORDED")
        assert all(c["evidence_class"] == e["evidence_class"] for c in e["cases"])
    for k in ("mcp-001", "mcp-003", "mcp-004", "mcp-006", "mcp-catalog", "rag-context", "delegation-001"):
        assert [c["role"] for c in exps[k]["cases"]] == ["BASELINE", "ATTACK", "RETEST"]
    assert [c["role"] for c in exps["pi-001"]["cases"]] == ["BASELINE", "ATTACK", "RETEST", "DEFENDED_ATTACK"]
    assert [(c["role"], c["facts"]["profile"]) for c in exps["pi-001"]["cases"]] == [("BASELINE", "defended"), ("ATTACK", "vulnerable"), ("RETEST", "defended"), ("DEFENDED_ATTACK", "defended")]
    sim = exps["component-provenance"]
    assert sim["findings"] == [] and "no finding" in sim["comparison_unavailable"].lower() and sim["status"].startswith("SIMULATED")
    pk = J("learning/level_1/LAB-COMPONENT-PROVENANCE/evidence.packet.json")
    assert {c["role"]: c["facts"] for c in sim["cases"]} == {m["mode"]: m for m in pk["modes"]}


def test_documented_run_lists_match_the_pack_run_ids_and_quotes_are_verbatim(data):
    _, exps = data
    for e in exps.values():
        for c in e["cases"]:
            q = c["expected"].get("quote")
            if q:
                assert EXP.clean(q["text"]) in EXP.source_text(ROOT / q["file"]), c["id"]
                if e["kind"] == "pack_triple":
                    assert c["facts"]["run_id"][:8] in q["text"] or c["role"] in ("BASELINE", "ATTACK", "RETEST", "DEFENDED_ATTACK")
            else:
                assert c["expected"] == {"documented": False}
    triples = {k: re.findall(r"^- (BASELINE|ATTACK|RETEST) `([0-9a-f-]{36})`", (ROOT / f"learning/level_1/{e['lab_id']}/README.md").read_text(encoding="utf-8"), re.M) for k, e in exps.items() if e["kind"] == "pack_triple" and e["id"] != "pi-001"}
    for k, t in triples.items():
        assert [(c["role"], c["facts"]["run_id"]) for c in exps[k]["cases"]] == t, k


def test_attack_retest_comparisons_are_recomputed_and_denominators_are_explicit(data):
    _, exps = data
    sigs = {x["id"]: x["signature"] for x in CATALOG["experiments"] if x["kind"] == "pack_triple"}
    for k, sig in sigs.items():
        e = exps[k]
        by = {c["role"]: c for c in e["cases"]}
        def pick(role):
            _, raw = raw_events(e["lab_id"], by[role]["facts"]["run_id"])
            d = [x for x in raw if x["event.name"] == "agentsec.control.decision" and x.get("agentsec.control.id") == sig["control"]]
            return {f: d[sig["nth"]].get(f) for f in sig["fields"]} if len(d) > sig["nth"] else {f: None for f in sig["fields"]}
        a, r = pick("ATTACK"), pick("RETEST")
        c = e["comparison"]
        assert c["same_request_check"]["attack"] == a and c["same_request_check"]["retest"] == r
        assert c["same_request_fields"] == {f: a[f] == r[f] for f in sig["fields"]}
        assert c["controlled_pair"] == (all(a[f] == r[f] for f in sig["fields"]) and any(v is not None for v in a.values())) is True
        assert c["roles"] == [x["role"] for x in e["cases"]] and len(e["cases"]) in (3, 4)
        assert "NOT a controlled pair" not in c["reading"]
    m6 = exps["mcp-006"]["comparison"]
    assert m6["also_reported"]["agentsec.content.hash"]["equal"] is False and "differ" in m6["reading"]
    assert exps["mcp-003"]["comparison"]["same_request_check"]["fields_absent_in_both"] == ["agentsec.mcp.resource.id"]


def test_scanner_runtime_correlation_is_recomputed_from_hashes(data):
    _, exps = data
    sc = exps["scanner-catalog"]
    rows = {r["scan"]: r for r in sc["comparison"]["rows"]}
    cat = exps["mcp-catalog"]
    for fixture, scan_id in (("NORMAL", "b3061c4e-7a81-445c-8fd8-3108dd14c419"), ("MALICIOUS", "7ae3ea64-4e7a-40fe-943f-3e582bce5ee8")):
        pack = ROOT / f"learning/level_1/LAB-SCANNER-RUNTIME-EVIDENCE/specimens/scanner/{scan_id}.jsonl"
        evs = [json.loads(json.loads(l)["event"]) for l in pack.read_text(encoding="utf-8").splitlines() if l.strip()]
        scan = next(x for x in evs if x["event.name"] == "agentsec.scanner.scan")
        h = scan["artifact"]["description_sha256"]
        want = []
        for c in cat["cases"]:
            _, raw = raw_events("LAB-MCP-CATALOG", c["facts"]["run_id"])
            if any(x.get("agentsec.control.id") == "CTRL-MCP-METADATA-001" and x.get("agentsec.content.hash") == h for x in raw):
                want.append(c["role"])
        assert [x["role"] for x in rows[fixture]["runtime_runs_with_the_same_hash"]] == want and rows[fixture]["finding_count"] == scan["scan"]["finding_count"]
        assert sha(pack.read_bytes()) == next(c for c in sc["cases"] if c["role"] == fixture)["sources"][0]["sha256"]
    assert [x["role"] for x in rows["NORMAL"]["runtime_runs_with_the_same_hash"]] == ["BASELINE"] and [x["role"] for x in rows["MALICIOUS"]["runtime_runs_with_the_same_hash"]] == ["ATTACK", "RETEST"]
    assert "does not show a shared request or process" in sc["comparison"]["method"]


def test_garak_has_no_comparison_and_states_the_limit(data):
    _, exps = data
    g = exps["garak-dan"]
    man = J("docs/p1a-evidence/garak-aeb05718-1364-4143-8248-71dd6f27b07b/manifest.json")
    assert g["comparison"] is None and "not a robustness evaluation" in g["comparison_unavailable"]
    assert g["cases"][0]["facts"]["model"] == man["target"]["model"] and g["cases"][0]["facts"]["probe"] == man["execution"]["probe"]
    assert "One local model, one probe, one generation and one detector." in g["limitations"]


def test_findings_are_traceable_rule_derived_and_never_assessed(data):
    index, exps = data
    cases = {c["id"]: (e, c) for e in exps.values() for c in e["cases"]}
    assert len(index["findings"]) == 9
    for f in index["findings"]:
        e, c = cases[f["evidence"][0]]
        assert f["experiment"] == e["id"] and c["evidence_class"] == "RECORDED"
        assert f["severity"] == f["likelihood"] == f["impact"] == "NOT ASSESSED" and f["owner"] == f["remediation_status"] == "NOT ASSIGNED"
        assert f["verification"] == {"status": "NOT_VERIFIED", "receipt": None} and f["limitations"]
        assert f["sources"] == c["sources"] and f["conditions"] == c["conditions"]
        if f["rule"] == "fail_open_allow_then_execution":
            assert c["role"] == "ATTACK" and c["facts"]["profile"] == "vulnerable"
            d = [x for x in c["facts"]["decisions"] if x["reason"].startswith("vulnerable_profile_fail_open")][0]
            assert d["reason"] in f["observed"] and d["decision"] in f["observed"]
            assert c["facts"]["handler_starts"] or c["facts"]["model_calls_started"]
        else:
            assert f["rule"] == "scanner_native_finding" and c["facts"]["findings"][0]["native_severity"] in f["observed"]
        if f["expected"]["documented"]:
            assert EXP.clean(f["expected"]["quote"]["text"]) in EXP.source_text(ROOT / f["expected"]["quote"]["file"])
    assert [f["id"] for f in index["findings"] if f["matches_documented"] is not True] == ["F-pi-001-execution"] == index["gaps"]["unmatched_findings"]
    assert all(not e["findings"] for k, e in exps.items() if k in ("garak-dan", "component-provenance"))


def test_every_metric_is_recomputed_and_none_is_a_rate_or_score(data):
    index, exps = data
    m = {x["id"]: x for x in index["metrics"]}
    cases = [c for e in exps.values() for c in e["cases"]]
    assert (m["experiments-recorded"]["numerator"], m["experiments-recorded"]["denominator"]) == (sum(e["evidence_class"] == "RECORDED" for e in exps.values()), len(exps)) == (10, 11)
    assert (m["cases-recorded"]["numerator"], m["cases-recorded"]["denominator"]) == (sum(c["evidence_class"] == "RECORDED" for c in cases), len(cases)) == (28, 31)
    assert m["cases-verified"]["numerator"] == 0 and m["cases-verified"]["denominator"] == len(cases)
    coll = {r["run_id"]: r for r in J("docs/splunk-evidence-11f/collection.json")["index_inventory"]["runs"]}
    packed = [c for e in exps.values() if e["kind"] == "pack_triple" for c in e["cases"]]
    assert m["runs-splunk-identical"]["denominator"] == len(packed) == 25
    assert all(coll[c["facts"]["run_id"]]["match"]["exact_raw_bytes"] == coll[c["facts"]["run_id"]]["match"]["pack_events"] == c["facts"]["events_in_pack"] for c in packed)
    n_dec = sum(len(c["facts"]["decisions"]) for c in packed)
    assert m["decisions-recorded"]["numerator"] == m["decisions-recorded"]["denominator"] == n_dec == 43
    roles = {}
    for c in packed:
        for d in c["facts"]["decisions"]:
            roles.setdefault(c["role"], {}).setdefault(d["decision"], 0)
            roles[c["role"]][d["decision"]] += 1
    assert index["decisions_by_role"] == roles
    assert m["findings-severity"]["numerator"] == 0 and m["findings-severity"]["denominator"] == 9 and m["findings-documented"]["numerator"] == 8
    caps = [x for c in CATALOG["categories"] for x in c["capabilities"]]
    assert (m["capabilities-implemented"]["numerator"], m["capabilities-implemented"]["denominator"]) == (sum(x["status"] == "AVAILABLE_WITH_EVIDENCE" for x in caps), len(caps)) == (7, 14)
    assert V.validate_metrics(index["metrics"]) == [] and not re.search(r"\d\s*%|success rate|ranking|risk score", json.dumps(index), re.I)


def test_catalog_statuses_are_derived_and_gaps_are_complete(data):
    index, exps = data
    for c in index["categories"]:
        assert c["status"] == "AVAILABLE_WITH_EVIDENCE" and c["experiments"] == [e["id"] for e in exps.values() if e["category"] == c["id"]] and c["experiments"]
        for cap in c["capabilities"]:
            if cap["status"] != "AVAILABLE_WITH_EVIDENCE":
                assert cap.get("quote") or cap.get("note")
                if cap.get("quote"):
                    assert EXP.clean(cap["quote"]["text"]) in EXP.source_text(ROOT / cap["quote"]["file"])
            else:
                assert cap["experiments"] and all(i in exps for i in cap["experiments"])
    assert {c["status"] for c in index["categories"]} == {"AVAILABLE_WITH_EVIDENCE"}
    assert len(index["gaps"]["not_implemented"]) == 6 and len(index["gaps"]["documented_only"]) == 1
    included = {e["lab_id"] for e in exps.values()}
    labs = {p.relative_to(ROOT / "learning/level_1").parts[0] for p in (ROOT / "learning/level_1").glob("*/specimens/**/*.jsonl")}
    assert set(index["gaps"]["evidence_exists_but_not_included"]) == labs - included - {"LAB-SCANNER-RUNTIME-EVIDENCE"} and "LAB-MEMORY-001" in index["gaps"]["evidence_exists_but_not_included"]
    assert index["gaps"]["no_verifier_receipt"]["cases"] == 31


@pytest.mark.parametrize("mutate,message", [
    (lambda e, f: e["cases"][0].update(severity_rating="high"), "rating"),
    (lambda e, f: e["cases"][0]["sources"][0].update(sha256="0" * 64), "does not match"),
    (lambda e, f: e["cases"][0]["verification"].update(status="VERIFIED"), "needs a receipt"),
    (lambda e, f: e["cases"][0].update(limitations=[]), "limitations"),
    (lambda e, f: e["cases"][0].update(evidence_class="SIMULATED"), "differs from the experiment"),
    (lambda e, f: e["cases"][0]["expected"].update(documented=True, quote=None), "needs its quote"),
    (lambda e, f: e["comparison"].update(controlled_pair=False), "controlled_pair does not follow"),
    (lambda e, f: e["comparison"]["same_request_fields"].update({"gen_ai.tool.name": False}), "controlled_pair does not follow"),
    (lambda e, f: e.update(comparison=None), "stated reason"),
    (lambda e, f: e.update(mappings=[{**e["mappings"][0], "claims_compliance": True}]), "claims compliance"),
    (lambda e, f: e.update(cases=[]), "at least one test case"),
])
def test_the_validator_refuses_unsupported_experiments(data, mutate, message):
    _, exps = data
    e = copy.deepcopy(exps["mcp-003"])
    mutate(e, None)
    assert any(message in x for x in V.validate_experiment(e, REFS)), V.validate_experiment(e, REFS)


@pytest.mark.parametrize("mutate,message", [
    (lambda f: f.update(severity="HIGH"), "severity may not be invented"),
    (lambda f: f.update(owner="Dana"), "owner and remediation"),
    (lambda f: f.update(remediation_status="OPEN"), "owner and remediation"),
    (lambda f: f.update(verification={"status": "VERIFIED", "receipt": "x"}), "NOT_VERIFIED"),
    (lambda f: f.update(evidence=["nope:ATTACK"]), "unknown evidence"),
    (lambda f: f.update(rule="made_up"), "stated rule"),
    (lambda f: f.update(limitations=[]), "limitations"),
    (lambda f: f.update(score=0.7), "score"),
    (lambda f: f.pop("observed"), "missing observed"),
    (lambda f: f.update(expected={"documented": True}), "needs its quote"),
])
def test_the_validator_refuses_unsupported_findings(data, mutate, message):
    index, exps = data
    cases = {c["id"]: c for e in exps.values() for c in e["cases"]}
    f = copy.deepcopy(next(x for x in index["findings"] if x["id"] == "F-mcp-003-execution"))
    mutate(f)
    assert any(message in x for x in V.validate_finding(f, cases)), V.validate_finding(f, cases)


def test_a_finding_is_never_derived_from_simulated_evidence(data):
    index, exps = data
    cases = {c["id"]: c for e in exps.values() for c in e["cases"]}
    f = copy.deepcopy(index["findings"][0])
    f["evidence"] = ["component-provenance:ATTACK"]
    assert any("simulated" in x for x in V.validate_finding(f, cases))


def test_metrics_validator_refuses_rates_and_impossible_counts():
    ok = {"id": "m", "label": "l", "numerator": 1, "denominator": 2, "unit": "u", "scope": "s", "derivation": "d"}
    assert V.validate_metrics([ok]) == []
    assert V.validate_metrics([{**ok, "numerator": 3}]) and V.validate_metrics([{**ok, "rate": 0.5}]) and V.validate_metrics([{k: v for k, v in ok.items() if k != "scope"}])


def test_eval_center_is_on_demand_and_the_ui_calls_no_backend():
    assets = ROOT / "src/agentsec/static/learn/assets"
    main = next(assets.glob("index-*.js")).read_text(encoding="utf-8")
    assert "F-mcp-003-execution" not in main and "Findings requiring investigation" not in main and "agentsec.eval_report.v1" not in main
    chunk = next(assets.glob("EvalCenter-*.js")).read_text(encoding="utf-8")
    assert "Findings requiring investigation" in chunk
    assert len(list(assets.glob("exp-*.js"))) == 11
    for f in ("pages/EvalCenter.tsx", "eval/data.ts", "eval/report.ts"):
        t = (ROOT / "academy-ui/src" / f).read_text(encoding="utf-8")
        for bad in ("fetch(", "XMLHttpRequest", "/api/", "WebSocket"):
            assert bad not in t, (f, bad)
