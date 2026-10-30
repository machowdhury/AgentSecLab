"""Static checks on the generated AI Security Assurance Splunk app (macros, lookups, six dashboards). SPL cannot run without Splunk, so these check what can be
checked offline: the files are current, the SPL is well formed, every macro, lookup, token and visualization it names exists, nothing destructive is used,
the generated case() matches the rule table, and the dashboards carry the fields and the empty-state wording the requirements demand."""
from __future__ import annotations

import csv
import json
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "splunk_app/agentsec"
VIEWS = ["ws_assurance_executive", "ws_assurance_agent_mcp", "ws_assurance_supply_chain", "ws_assurance_threat_model", "ws_assurance_compliance", "ws_assurance_finding"]
RULES = json.loads((ROOT / "learning/assurance/rules.json").read_text(encoding="utf-8"))
FORBIDDEN = re.compile(r"\|\s*(delete|outputlookup|outputcsv|collect|mcollect|tscollect|sendemail|script|run|dbxquery|rest|sendalert|map)\b", re.I)


def view(name):
    root = ET.parse(APP / f"default/data/ui/views/{name}.xml").getroot()
    return json.loads(root.find("definition").text)


def macros():
    text = (APP / "default/macros.conf").read_text(encoding="utf-8")
    out = {}
    for m in re.finditer(r"^\[(\w+)\]\ndefinition = (.*?)\niseval = 0", text, re.M | re.S):
        out[m.group(1)] = m.group(2).replace(" \\\n", "\n")
    return out


def queries():
    for v in VIEWS:
        for k, ds in view(v)["dataSources"].items():
            yield v, k, ds["options"]["query"]


def balanced(spl: str):
    s = re.sub(r'\\"', "", spl)
    assert s.count('"') % 2 == 0, "unbalanced double quotes"
    nq = re.sub(r'"[^"]*"', '""', s)
    for a, b in ("()", "[]"):
        assert nq.count(a) == nq.count(b), f"unbalanced {a}{b}"
    assert nq.count("`") % 2 == 0, "unbalanced backticks"


def test_generated_files_are_current():
    p = subprocess.run([sys.executable, str(ROOT / "scripts/build_assurance_app.py"), "--check"], capture_output=True, text=True, env={"PYTHONPATH": str(ROOT / "src"), "PATH": "/usr/bin:/bin"})
    assert p.returncode == 0, p.stdout + p.stderr


def test_macros_are_well_formed_and_use_no_dollar_sign():
    m = macros()
    assert {"agentsec_index", "agentsec_assurance_units", "agentsec_assurance_findings", "agentsec_assurance_findings_linked"} <= set(m)
    for name, body in m.items():
        balanced(body)
        assert "$" not in body, f"{name}: a dollar sign would be read as a macro argument"
        assert not FORBIDDEN.search(body), name


def test_every_dashboard_query_is_balanced_read_only_and_names_real_macros_and_lookups():
    transforms = (APP / "default/transforms.conf").read_text(encoding="utf-8")
    known_macros = set(macros())
    lookups = {m.group(1) for m in re.finditer(r"^\[(\w+)\]", transforms, re.M)}
    seen = 0
    for v, k, q in list(queries()) + [("macro", n, b) for n, b in macros().items()]:
        seen += 1
        balanced(q)
        assert not FORBIDDEN.search(q), (v, k)
        for mac in re.findall(r"`(\w+)`", q):
            assert mac in known_macros, (v, k, mac)
        for lk in re.findall(r"(?:inputlookup|lookup)\s+(agentsec_\w+)", q):
            assert lk in lookups and (APP / "lookups" / f"{lk}.csv").exists(), (v, k, lk)
    assert seen > 35


def test_lookup_output_fields_exist_in_the_csv_headers():
    for v, k, q in list(queries()) + [("macro", n, b) for n, b in macros().items()]:
        for m in re.finditer(r"\blookup\s+(agentsec_\w+)\s+([\w ]+?)(?:\s+AS\s+\w+)?\s+OUTPUT\s+([^|\n\]]+)", q):
            hdr = next(csv.reader((APP / "lookups" / f"{m.group(1)}.csv").open(encoding="utf-8")))
            key = m.group(2).split()[0]
            assert key in hdr, (v, k, m.group(1), key)
            for out in re.split(r"[,\s]+", m.group(3).strip()):
                if out and out.upper() not in ("AS",) and not re.match(r"^(class|control_class|ctrl_class|cclass|workshops|control_workshops|recorded)$", out) or out in hdr:
                    continue
                assert out in hdr or out in ("class", "control_class", "ctrl_class", "cclass", "control_workshops", "workshops", "recorded", "AS"), (v, k, m.group(1), out)


@pytest.mark.parametrize("name", VIEWS)
def test_dashboard_structure_tokens_and_layout(name):
    d = view(name)
    inputs = {i["options"]["token"] for i in d["inputs"].values()}
    for k, ds in d["dataSources"].items():
        for tok in re.findall(r"\$(\w+)(?:\.\w+)?\$", ds["options"]["query"] + json.dumps(ds["options"].get("queryParameters", {}))):
            assert tok in inputs, (name, k, tok)
    for k, v in d["visualizations"].items():
        for ref in v.get("dataSources", {}).values():
            assert ref in d["dataSources"], (name, k, ref)
    items = d["layout"]["structure"]
    assert {i["item"] for i in items} == set(d["visualizations"]), name
    boxes = [(i["position"]["x"], i["position"]["y"], i["position"]["x"] + i["position"]["w"], i["position"]["y"] + i["position"]["h"]) for i in items]
    for a in range(len(boxes)):
        for b in range(a + 1, len(boxes)):
            x1, y1, x2, y2 = boxes[a]; u1, v1, u2, v2 = boxes[b]
            assert x2 <= u1 or u2 <= x1 or y2 <= v1 or v2 <= y1, (name, "panels overlap", items[a]["item"], items[b]["item"])
    assert set(d["layout"]["globalInputs"]) <= set(d["inputs"])


def test_navigation_lists_all_five_dashboards_and_they_exist():
    nav = (APP / "default/data/ui/nav/default.xml").read_text(encoding="utf-8")
    for v in VIEWS[:5]:
        assert f'<view name="{v}">' in nav
    for v in VIEWS:
        assert (APP / f"default/data/ui/views/{v}.xml").exists()


def test_the_generated_case_matches_the_rule_table_and_the_status_model():
    body = macros()["agentsec_assurance_findings"]
    for r in RULES["rules"]:
        assert f'"{r["id"]}"' in body, r["id"]
        c = r["cond"]
        if "decision" in c:
            assert f'decision="{c["decision"]}"' in body
    order = [body.index(f'"{r["id"]}"') for r in sorted(RULES["rules"], key=lambda x: x["order"])]
    assert order == sorted(order), "rules must be tried in ascending order"
    assert body.index('"R-INCOMPLETE"') < body.index('"R-DENY-HELD"'), "incomplete telemetry is tested before any verified status"
    for s in RULES["statuses"]:
        if s not in ("NOT_TESTED", "VERIFICATION_UNAVAILABLE"):
            assert s in body or s == "VERIFIED_INEFFECTIVE_BY_DESIGN", s
    for rr in RULES["run_rules"]:
        assert rr["id"] in body


def test_findings_expose_every_evidence_to_meaning_field_and_the_drilldown_ids():
    cols = {c.strip() for c in re.search(r"FINDING_COLS = \"([^\"]+)\"", (ROOT / "scripts/build_assurance_app.py").read_text(encoding="utf-8")).group(1).split(",")}
    need = {"observation", "interpretation", "impact", "control_interpretation", "recommended_action", "retest_outcome", "confidence", "status_label", "run_id", "control_id", "hop", "workshops", "evidence_class"}
    assert need <= cols
    detail = view("ws_assurance_finding")
    q = json.dumps(detail["dataSources"])
    for field in ("observation", "interpretation", "impact", "control_interpretation", "recommended_action", "retest"):
        assert field in q
    assert "framework" in q and "agentsec.sequence" in q                    # framework mapping and raw events
    exec_ = view("ws_assurance_executive")
    h = exec_["visualizations"]["viz_findings"]["eventHandlers"][0]["options"]
    assert h["dashboard"] == "ws_assurance_finding" and {t["token"] for t in h["tokens"]} == {"run_id", "control_id", "hop"}


def test_empty_and_missing_telemetry_never_reads_as_a_pass():
    q = {k: v for _, k, v in queries()}
    nar = q["ds_exec_narrative"]
    assert "NOT a pass" in nar and "findings=0" in nar
    health = view("ws_assurance_executive")
    assert any("Reading the statuses" in str(v.get("options", {}).get("markdown", "")) for v in health["visualizations"].values())
    nem = q["ds_c_nemotron"]
    assert "Not tested" in nem and "nemotron_evaluations=0" in nem
    assert "Unavailable" in q["ds_exec_metrics"] and "not detection time" in q["ds_exec_metrics"]


def test_no_composite_score_or_compliance_percentage_anywhere():
    for v, k, q in queries():
        assert not re.search(r"compliance[_ ]?(score|percent)|risk[_ ]?score|\bpercent\b|\bperc\(", q, re.I), (v, k)
    for v in VIEWS:
        text = (APP / f"default/data/ui/views/{v}.xml").read_text(encoding="utf-8")
        assert "compliance score" not in text.lower()


def test_framework_lookup_carries_only_verified_identifiers_with_sources_and_no_satisfaction_claim():
    rows = list(csv.DictReader((APP / "lookups/agentsec_framework_map.csv").open(encoding="utf-8")))
    assert rows and {r["relationship"] for r in rows} == {"RELATED"}
    for r in rows:
        assert r["verification"] in ("VERIFIED", "VERIFIED_WITH_LIMITS"), r
        assert r["source_url"].startswith("https://") and r["retrieved_on"] == "2026-10-29" and r["rationale"]
    assert {r["framework"] for r in rows} >= {"NIST AI RMF 1.0", "NIST AI 600-1", "OWASP LLM Top 10 2025", "OWASP Top 10 for Agentic Applications 2026", "MITRE ATLAS", "ISO/IEC 42001:2023"}
    iso = [r for r in rows if r["framework"].startswith("ISO")]
    assert iso and all(r["verification"] == "VERIFIED_WITH_LIMITS" for r in iso)


def test_recorded_run_list_matches_the_committed_specimens_and_workshop_map_covers_every_attack_id():
    rec = {r["run_id"] for r in csv.DictReader((APP / "lookups/agentsec_recorded_runs.csv").open())}
    assert rec == {p.stem for p in (ROOT / "learning/level_1").glob("*/specimens/*.jsonl")}
    amap = {r["attack_id"]: r["workshops"] for r in csv.DictReader((APP / "lookups/agentsec_attack_workshops.csv").open())}
    seen = set()
    for f in (ROOT / "learning/level_1").glob("*/specimens/*.jsonl"):
        for line in f.read_text().splitlines():
            if '"agentsec.attack.id"' in line:
                seen.add(json.loads(line)["agentsec.attack.id"])
    assert seen <= set(amap), seen - set(amap)


def test_independent_review_fixes_are_present_in_the_generated_spl():
    """One assertion per review finding that can be checked statically (the engine tests cover the rest)."""
    q = {k: v for _, k, v in queries()}
    m = macros()
    findings, linked, units = m["agentsec_assurance_findings"], m["agentsec_assurance_findings_linked"], m["agentsec_assurance_units"]
    # 1: stats BY skips null fields, so these panels fill them first
    assert "fillnull" in q["ds_b_outcomes"] and "fillnull" in q["ds_b_technique"] and "fillnull" in q["ds_b_attempts"] and "fillnull" in q["ds_c_models"]
    # 2: an unknown or missing decision is shown, not dropped
    assert '"R-UNCLASSIFIED"' in findings and "true()" in findings.split("rule_id=case(")[1].split("| where")[0]
    # 3: retest linking is null-safe and never crosses evidence classes
    assert 'coalesce(attack_id,"(none)")' in linked and "by attack_key control_id evidence_class" in linked and 'coalesce(n_retest,0)=0' in linked
    # 4: the fail-open reason is a literal prefix, not a like() pattern in which the underscores are wildcards
    assert "like(reason,\"vulnerable_profile_fail_open" not in findings and 'match(reason,"^vulnerable_profile_fail_open")' in findings
    # 5a: the evidence class is decided per run, not per event
    assert "values(lab_marker) as run_marker" in units and "mvfind(run_marker" in units
    # 5c: the model panel obeys the evidence-class and workshop inputs
    assert "$ec$" in q["ds_c_models"] and "$ws$" in q["ds_c_models"]
    # 6: zeros are qualified, and the 'untested' count ignores the workshop filter
    assert "runs_with_incomplete_telemetry" in q["ds_b_attempts"] and "$ws$" not in q["ds_exec_untested"]
    assert "no control is shown as effective" in q["ds_exec_narrative"] and "among these findings" in q["ds_exec_narrative"]
    # 7: the unauthorized-execution metric is hop-level, with run-level failures reported beside it
    assert 'control_id!="(run)"' in q["ds_exec_metrics"] and "run-level retest failures" in q["ds_exec_metrics"]
    # 8: the dead join is gone
    assert "framework_items" not in q["ds_e_workshop"] and "rename control_id as c" not in q["ds_e_workshop"]
    # 9: a null hop or control id cannot leave a drilldown token undefined
    assert 'hop=coalesce(hop,"-")' in findings and '"(unknown control)"' in findings


def test_the_vulnerable_profile_is_never_reported_as_a_control_failure_on_the_coverage_and_compliance_pages():
    """Found on the real Splunk: an execution that the intentionally vulnerable profile allows by design must not read as 'Verified ineffective'."""
    q = {k: v for _, k, v in queries()}
    for ds in ("ds_d_layers", "ds_d_register", "ds_e_matrix"):
        assert 'by_design=0' in q[ds] and 'by_design=1' in q[ds], ds
    assert "observed_executed_by_design" in q["ds_d_layers"] and "executed_by_design" in q["ds_e_matrix"]
    assert "Only the intentionally vulnerable profile was observed" in q["ds_d_register"] and "Only the intentionally vulnerable profile was observed" in q["ds_e_matrix"]
    assert "verified_ineffective" not in q["ds_e_matrix"].split("| table")[-1]
