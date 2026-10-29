#!/usr/bin/env python3
"""Generate the AI Security Assurance part of the Splunk app from learning/assurance and the repository's own evidence files.

Writes (all generated; edit the sources, then re-run):
  splunk_app/agentsec/lookups/*.csv         controls, recorded runs, attack to workshop, framework map, MAESTRO threats, declared components, metric definitions
  splunk_app/agentsec/default/transforms.conf   lookup definitions
  splunk_app/agentsec/default/macros.conf       the generated SPL macros (the agentsec_index macro is kept)
  splunk_app/agentsec/default/data/ui/views/ws_assurance_*.xml   five dashboards and a finding-detail page
  (the navigation entry is written by scripts/apply_guided_learning.py, which owns nav/default.xml)
`--check` writes nothing and exits 1 when a generated file differs from what is on disk.
"""
from __future__ import annotations

import csv
import io
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))
import assurance_spl as S  # noqa: E402

APP = ROOT / "splunk_app" / "agentsec"
AS = ROOT / "learning" / "assurance"
rules = json.loads((AS / "rules.json").read_text(encoding="utf-8"))
controls = json.loads((AS / "controls.json").read_text(encoding="utf-8"))["controls"]
fmap = json.loads((AS / "framework_map.json").read_text(encoding="utf-8"))
maestro = json.loads((ROOT / "learning/level_1/LAB-THREAT-MODELING-001/maestro.json").read_text(encoding="utf-8"))
images = json.loads((ROOT / "deploy/images.lock.json").read_text(encoding="utf-8"))
models = json.loads((ROOT / "deploy/models.lock.json").read_text(encoding="utf-8"))

OUT: dict[Path, str] = {}


def csv_text(header: list[str], rows: list[list]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(header)
    w.writerows(rows)
    return buf.getvalue()


# ---------------------------------------------------------------------------------------------------- lookups
def lookups() -> dict[str, str]:
    out = {}
    out["agentsec_controls.csv"] = csv_text(
        ["control_id", "control_name", "class", "guards", "boundary", "technique", "maestro_layers", "workshops", "remediation", "retest_check"],
        [[c["id"], c["name"], c["class"], c["guards"], c["boundary"], c["technique"], "|".join(map(str, c["maestro_layers"])), "|".join(c["workshops"]), c["remediation"], c["retest"]] for c in controls])
    recorded = sorted(p.stem for p in (ROOT / "learning/level_1").glob("*/specimens/*.jsonl"))
    out["agentsec_recorded_runs.csv"] = csv_text(["run_id", "recorded"], [[r, "true"] for r in recorded])
    atk: dict[str, set] = {}
    for f in (ROOT / "learning/level_1").glob("*/specimens/*.jsonl"):
        lab = f.parts[-3]
        for line in f.read_text(encoding="utf-8").splitlines():
            if '"agentsec.attack.id"' in line:
                try:
                    a = json.loads(line).get("agentsec.attack.id")
                except ValueError:
                    continue
                if a:
                    atk.setdefault(a, set()).add(lab)
    from agentsec.launch_catalog import LAUNCH_ALLOWLIST
    for row in LAUNCH_ALLOWLIST:
        if row.mode in ("ATTACK", "RETEST"):
            atk.setdefault(row.specimen_id, set()).add(row.lab_id)
    out["agentsec_attack_workshops.csv"] = csv_text(["attack_id", "workshops"], [[a, "|".join(sorted(v))] for a, v in sorted(atk.items())])
    items = {(i["framework"], i["id"]): i for i in fmap["items"]}
    rows = []
    for r in fmap["relationships"]:
        it = items[(r["framework"], r["id"])]
        rows.append([r["control_id"], r["framework"], r["id"], it["name"], r["kind"], r["relationship"], r["rationale"], it["status"], it["version_or_date"], it["source_url"], it["retrieved_on"], it["limits"]])
    out["agentsec_framework_map.csv"] = csv_text(["control_id", "framework", "item_id", "item_name", "kind", "relationship", "rationale", "verification", "version_or_date", "source_url", "retrieved_on", "limits"], rows)
    out["agentsec_framework_items.csv"] = csv_text(["framework", "item_id", "item_name", "verification", "version_or_date", "source_url", "retrieved_on", "limits"],
                                                   [[i["framework"], i["id"], i["name"], i["status"], i["version_or_date"], i["source_url"], i["retrieved_on"], i["limits"]] for i in fmap["items"]])
    layers = {l["n"]: l["name"] for l in maestro["framework"]["layers"]}
    matrix = maestro["risk_method"]["matrix"] if "matrix" in maestro["risk_method"] else None
    trows = []
    for t in maestro["example"]["register"]:
        trows.append([t["id"], t["layer"], layers[t["layer"]], t["label"], t["evidence"], "|".join(t["scenarios"]), "|".join(t["controls"]), t["inherent"]["impact"] + "/" + t["inherent"]["likelihood"], t["residual"]["impact"] + "/" + t["residual"]["likelihood"], t["description"]])
    out["agentsec_maestro_threats.csv"] = csv_text(["threat_id", "layer", "layer_name", "threat", "modeled_evidence_status", "workshops", "controls", "inherent_impact_likelihood", "residual_impact_likelihood", "description"], trows)
    comp = []
    sp = images["splunk"]
    for ver, v in sorted(sp["versions"].items()):
        comp.append(["container image", f"splunk/splunk {ver}", f"{sp['repository']}:{v['tag']}", v.get("digest") or "", "yes" if v.get("digest") else "no (floating tag)", v.get("status", ""),
                     "default install" if ver == sp["default"] else "candidate, not installed by default", "deploy/images.lock.json"])
    oll = images["ollama"]
    ov = oll["versions"][oll["default"]]
    comp.append(["container image", "ollama", f"{oll['repository']}:{ov['tag']}", ov.get("digest") or "", "yes" if ov.get("digest") else "no (floating tag)", ov.get("status", ""), "default install", "deploy/images.lock.json"])
    for name, v in sorted(images.get("others", {}).items()):
        if isinstance(v, dict) and v.get("ref"):
            comp.append(["container image", name, v["ref"], v.get("digest") or "", "yes" if v.get("digest") else "no (floating tag)", v.get("status", "pinned" if v.get("digest") else "unpinned"), "default install", "deploy/images.lock.json"])
    roles = {m: r for r, m in models["roles"].items()}
    for name, m in sorted(models["models"].items()):
        comp.append(["language model", name, name, m.get("digest") or "", "yes" if m.get("digest") else "no (digest recorded at runtime)", m.get("status", ""),
                     f"role: {roles[name]}" if name in roles else "candidate, not used by default", "deploy/models.lock.json"])
    out["agentsec_declared_components.csv"] = csv_text(["component_type", "component", "reference", "digest", "pinned_by_digest", "lock_status", "used_by", "declared_in"], comp)
    out["agentsec_metric_defs.csv"] = csv_text(["metric_id", "metric_order", "name", "numerator", "denominator", "source", "caveat"],
                                               [[m["id"], i, m["name"], m["numerator"], m["denominator"], m["source"], m["caveat"]] for i, m in enumerate(rules["metrics"])])
    return out


TRANSFORMS = "# GENERATED by scripts/build_assurance_app.py\n" + "".join(f"[{n[:-4]}]\nfilename = {n}\ncase_sensitive_match = false\n\n" for n in (
    "agentsec_controls.csv", "agentsec_recorded_runs.csv", "agentsec_attack_workshops.csv", "agentsec_framework_map.csv", "agentsec_framework_items.csv",
    "agentsec_maestro_threats.csv", "agentsec_declared_components.csv", "agentsec_metric_defs.csv"))

# ---------------------------------------------------------------------------------------------------- dashboards
UNITS = f"`{S.BASE_MACRO}`"
FIND = f"`{S.LINKED_MACRO}`"
F = S.FILTER
FEC = S.FILTER_EC
TRQ = {"earliest": "$tr.earliest$", "latest": "$tr.latest$"}
LAB_OPTIONS = sorted({w for c in controls for w in c["workshops"]})
VIEW_OF = {"LAB-PI-001": "ws_lab_pi_001", "LAB-MCP-001": "ws_lab_mcp_001", "LAB-MCP-003": "ws_lab_mcp_003", "LAB-MCP-004": "ws_lab_mcp_004", "LAB-MCP-005": "ws_lab_mcp_005", "LAB-MCP-006": "ws_lab_mcp_006",
           "LAB-MCP-CATALOG": "ws_lab_mcp_catalog", "LAB-RAG-CONTEXT": "ws_lab_rag_context", "LAB-MEMORY-001": "ws_lab_memory_security", "LAB-AGENT-GOAL-INTEGRITY-001": "ws_lab_agent_goal_integrity",
           "LAB-AGENT-DELEGATION-001": "ws_lab_agent_delegation", "LAB-AGENTSEC-CAPSTONE-001": "ws_lab_agentsec_capstone"}
STATUS_COLORS = {"Verified effective": "#2E7D32", "Verified ineffective": "#C62828", "Finding observed": "#EF6C00", "Insufficient evidence": "#6D4C41", "Not tested": "#546E7A", "Verification unavailable": "#455A64"}
DISCLAIM = "A lab test is evidence of how a control behaved in the tested environment. It is not proof of organization-wide compliance, certification or regulatory conformance."

FINDING_COLS = "finding_key, status_label, confidence, evidence_class, mode, profile, attack_id, control_id, hop, tool, decision, reason, observation, interpretation, impact, control_interpretation, recommended_action, retest_outcome, retest_run, workshops, run_id"


class Dash:
    def __init__(self, view: str, title: str, description: str, filters: bool = True):
        self.view, self.title, self.description = view, title, description
        self.ds: dict = {}
        self.viz: dict = {}
        self.items: list = []
        self.y = 0
        self.filters = filters
        self.n = 0

    def search(self, name: str, query: str, tr: bool = True) -> str:
        key = f"ds_{name}"
        opts = {"query": query}
        if tr:
            opts["queryParameters"] = dict(TRQ)
        self.ds[key] = {"type": "ds.search", "name": name, "options": opts}
        return key

    def row(self, *panels, h=260):
        """panels: (viz_key, weight)"""
        total = sum(w for _, w in panels)
        x = 0
        for k, w in panels:
            wd = int(1440 * w / total)
            self.items.append({"item": k, "type": "block", "position": {"x": x, "y": self.y, "w": wd, "h": h}})
            x += wd
        self.y += h

    def full(self, key: str, h: int):
        self.row((key, 1), h=h)

    def md(self, key: str, text: str, h=110):
        self.viz[key] = {"type": "splunk.markdown", "options": {"markdown": text, "fontSize": "default"}}
        self.row((key, 1), h=h)

    def table(self, key: str, title: str, ds: str, h=300, drill: bool = False, weight=1, wrap=True, colwidths=None, status_col=None, view_row=True):
        opts = {"count": 12, "wrap": True if wrap else False, "rowNumbers": False, "dataOverlayMode": "none", "tableFormat": {"headerBackgroundColor": "#0B1F33", "headerColor": "#FFFFFF", "rowBackgroundColors": ["#FFFFFF", "#F6F8FB"]}}
        v = {"type": "splunk.table", "title": title, "dataSources": {"primary": ds}, "options": opts}
        if drill:
            v["eventHandlers"] = [{"type": "drilldown.linkToDashboard", "options": {"app": "agentsec", "dashboard": "ws_assurance_finding", "newTab": True,
                                                                                    "tokens": [{"token": "run_id", "value": "row.run_id.value"}, {"token": "control_id", "value": "row.control_id.value"}, {"token": "hop", "value": "row.hop.value"}]}}]
        self.viz[key] = v
        return key

    def chart(self, key: str, title: str, ds: str, kind="splunk.column"):
        self.viz[key] = {"type": kind, "title": title, "dataSources": {"primary": ds}, "options": {"legendDisplay": "bottom", "stackMode": "stacked" if kind == "splunk.column" else "auto"}}
        return key

    def single(self, key: str, title: str, ds: str):
        self.viz[key] = {"type": "splunk.singlevalue", "title": title, "dataSources": {"primary": ds}, "options": {"majorFontSize": 36}}
        return key

    def build(self, extra_inputs: dict | None = None, hide_filters=False) -> str:
        inputs = {"input_tr": {"type": "input.timerange", "title": "Time range", "options": {"token": "tr", "defaultValue": "0,now"}}}
        gl = ["input_tr"]
        if self.filters:
            inputs["input_ec"] = {"type": "input.dropdown", "title": "Evidence class", "options": {"token": "ec", "defaultValue": "*", "items": [{"label": "LIVE and RECORDED (default; test fixtures are excluded)", "value": "*"}, {"label": "LIVE (run on this installation)", "value": "LIVE"}, {"label": "RECORDED (committed replay specimens)", "value": "RECORDED"}, {"label": "TEST_FIXTURE only (synthetic negative-test data)", "value": "TEST_FIXTURE"}, {"label": "Everything including fixtures", "value": "ALL"}]}}
            inputs["input_ws"] = {"type": "input.dropdown", "title": "Workshop", "options": {"token": "ws", "defaultValue": "*", "items": [{"label": "All workshops", "value": "*"}] + [{"label": w, "value": w} for w in LAB_OPTIONS]}}
            gl += ["input_ec", "input_ws"]
        if extra_inputs:
            inputs.update(extra_inputs)
            gl += list(extra_inputs)
        d = {"title": self.title, "description": self.description,
             "defaults": {"dataSources": {"ds.search": {"options": {"queryParameters": {"earliest": "$tr.earliest$", "latest": "$tr.latest$"}}}},
                          "visualizations": {"splunk.table": {"options": {"backgroundColor": "#FFFFFF", "headerBackgroundColor": "#0B1F33", "headerTextColor": "#FFFFFF"}},
                                             "splunk.markdown": {"options": {"fontColor": "#17202A", "fontSize": "default"}}}},
             "inputs": inputs, "dataSources": self.ds, "visualizations": self.viz,
             "layout": {"type": "grid", "globalInputs": gl, "options": {"backgroundColor": "#F6F8FB", "display": "auto-scale", "gutterSize": 8, "width": 1440, "height": self.y + 40}, "structure": self.items},
             "applicationProperties": {"collapsed": False}}
        body = json.dumps(d, indent=2, ensure_ascii=False)
        return f'<?xml version="1.0" encoding="utf-8"?>\n<dashboard version="2" theme="light">\n  <label>{self.title}</label>\n  <description>{self.description}</description>\n  <definition><![CDATA[\n{body}\n]]></definition>\n</dashboard>\n'


def states_legend() -> str:
    parts = [f"**{v['label']}**: {v['meaning']}" for v in rules["statuses"].values()]
    return "\n\n".join(parts)


def standard_findings_table(d: Dash, key="findings", title="Findings (select a row for the finding page: raw evidence, SPL, framework links, retest)", where="", h=360):
    ds = d.search(key, f"{FIND} {F} {where}\n| sort - _time\n| table {FINDING_COLS}")
    return d.table(f"viz_{key}", title, ds, h=h, drill=True)


def evidence_note() -> str:
    return ("**Evidence classes.** LIVE = a run on this installation. RECORDED = a run captured earlier and committed as a replay specimen (identified by the committed list `agentsec_recorded_runs`; the telemetry itself says `execution.mode=LIVE` for both). "
            "SIMULATED = workshop packets and CTF challenges; they are not in Splunk and never appear here. TEST_FIXTURE = synthetic data for negative acceptance tests (lab id `assurance-test-fixture`), mutated from real runs and never produced by the lab. The default view shows LIVE and RECORDED and always excludes fixtures; choose *Everything including fixtures* only to see them beside real evidence. Read the Evidence class column.")


# --- A. Executive
def executive() -> str:
    d = Dash("ws_assurance_executive", "AI Security Assurance: Executive overview",
             "Evidence-driven overview of AgentSecLab activity: attacks, outcomes, control effectiveness and evidence gaps. Every number is computed from telemetry in this index; no composite score is shown.")
    d.md("viz_head", "# What this shows\n\nThe outcome of real security tests run in AgentSecLab, read from Splunk telemetry by deterministic rules (`learning/assurance/rules.json`). **No evidence means no verified claim; no test means no claim about a control.** " + DISCLAIM + "\n\n" + evidence_note(), h=170)
    nar = d.search("exec_narrative", f"""{FIND} {F}
| stats dc(run_id) as runs, count as findings, count(eval(status="VERIFIED_EFFECTIVE")) as eff, count(eval(status="VERIFIED_INEFFECTIVE")) as ineff, count(eval(status="VERIFIED_INEFFECTIVE" AND by_design=1)) as design, count(eval(status="INSUFFICIENT_EVIDENCE")) as insuff, count(eval(status="FINDING_OBSERVED")) as obs, count(eval(mode="ATTACK" AND status="VERIFIED_INEFFECTIVE")) as atk_ineff, count(eval(mode="ATTACK" AND status="VERIFIED_INEFFECTIVE" AND retest_outcome="VALIDATED")) as validated
| eval real=ineff-design
| eval executive=if(findings=0, "No security findings were found for the selected range and filters. That is NOT a pass: with no telemetry nothing can be said about any control. Check the telemetry-health panel and the time range.", "In the selected range the evidence covers ".runs." runs and ".findings." findings. ".if(eff>0, eff." guarded operations were refused by an enforcing control with no execution in the same hop: verified effective for those observed attempts only. ", "").if(real>0, "ATTENTION: ".real." operations executed that an enforcing control should have stopped, outside the intentionally vulnerable profile. ", if(eff+design>0, "No execution outside the intentionally vulnerable profile was observed among these findings. ", "")).if(eff=0, "No operation is verified as blocked in this range, so no control is shown as effective. ", "").if(design>0, design." executions happened under the intentionally vulnerable profile, which is the lab's teaching condition. ", "").if(atk_ineff>0, validated." of ".atk_ineff." ineffective ATTACK findings are linked to a verified-effective retest. ", "").if(insuff>0, "Telemetry is incomplete or missing for ".insuff." findings, so no claim is made about them. ", "").if(obs>0, obs." findings come from controls that classify content instead of blocking it, so their effectiveness is not established. ", "")."This is evidence from the lab, not a statement about any organization's controls or compliance.")
| rename executive as "What this means (executive)"
| fields "What this means (executive)" """)
    d.table("viz_nar", "What this means: executive interpretation (changes with the data, range and filters)", nar, h=230)
    d.full("viz_nar", 230)
    tech = d.search("exec_tech", f"""{FIND} {F}
| eval sev=case(status="VERIFIED_INEFFECTIVE" AND by_design=0,1, status="INSUFFICIENT_EVIDENCE",2, status="VERIFIED_INEFFECTIVE",3, status="VERIFIED_EFFECTIVE",4, true(),5)
| sort sev, - _time
| head 5
| eval technical=observation." ".interpretation." ".control_interpretation." Verify with: index=agentsec_telemetry sourcetype=otel:agentic:json \\"agentsec.run.id\\"=\\"".run_id."\\" | sort agentsec.sequence. Retest: ".coalesce(retest_outcome,"NOT_APPLICABLE")."."
| table status_label technical""")
    d.table("viz_tech", "Technical interpretation: the five most significant findings (which run, hop, control, what happened, how to verify)", tech, h=420)
    d.full("viz_tech", 420)
    metric_ds = d.search("exec_metrics", f"""{UNITS} {F}
| stats dc(eval(if(mode="ATTACK",run_id,null()))) as atk, dc(run_id) as runs, dc(eval(if(complete=1,run_id,null()))) as comp
| eval rows=mvappend("M-ATTACK-RUNS|".atk." attack runs", "M-EVIDENCE-COMPLETENESS|".comp." of ".runs." runs")
| mvexpand rows
| append [ search {FIND} {F}
    | stats count(eval(status="VERIFIED_INEFFECTIVE" AND control_id!="(run)")) as ineff, count(eval(status="VERIFIED_INEFFECTIVE" AND control_id="(run)")) as run_level, count(eval(status="VERIFIED_INEFFECTIVE" AND by_design=1)) as design, count(eval(in(decision,"ALLOW","DENY","ERROR") AND control_id!="(run)")) as enforcing, count(eval(status="VERIFIED_EFFECTIVE")) as eff, count(eval(decision="DENY")) as denies, count(eval(mode="ATTACK" AND status="VERIFIED_INEFFECTIVE")) as atk_ineff, count(eval(mode="ATTACK" AND status="VERIFIED_INEFFECTIVE" AND retest_outcome="VALIDATED")) as v, count(eval(mode="ATTACK" AND status="VERIFIED_INEFFECTIVE" AND retest_outcome="NOT_VALIDATED")) as nv, count(eval(mode="ATTACK" AND status="VERIFIED_INEFFECTIVE" AND retest_outcome="NO_RETEST")) as nr
    | eval rows=mvappend("M-UNAUTH-EXECUTED|".ineff." of ".enforcing." hop-level decisions (".design." by design); plus ".run_level." run-level retest failures", "M-BLOCKED|".eff." verified, of ".denies." DENY decisions", "M-RETEST-EFFECTIVENESS|".v." validated, ".nv." not validated, ".nr." no retest, of ".atk_ineff." ineffective ATTACK findings")
    | mvexpand rows ]
| append [ | inputlookup agentsec_controls | fields control_id
    | join type=left control_id [ search {FIND} {FEC} | where mode="ATTACK" OR mode="RETEST" | stats count as tested by control_id ]
    | stats count as total, count(eval(isnull(tested))) as untested
    | eval rows="M-UNTESTED-CONTROLS|".untested." of ".total." catalogue controls have no ATTACK or RETEST finding"
    | fields rows ]
| append [ search {UNITS} {F} | stats max(first_decision_time) as fd, max(run_start) as st by run_id | eval lat=fd-st | where isnotnull(lat) | stats median(lat) as med, max(lat) as mx, count as n
    | eval rows="M-DECISION-LATENCY|median ".med." s, maximum ".mx." s over ".n." runs (control-decision latency, not detection time; time to detection: Unavailable)"
    | fields rows ]
| rex field=rows "^(?<metric_id>[^|]+)\\|(?<value>.*)$"
| lookup agentsec_metric_defs metric_id OUTPUT metric_order, name, numerator, denominator, source, caveat
| sort metric_order
| table name value numerator denominator source caveat""")
    d.table("viz_metrics", "Metrics: every value with its numerator, denominator and source (no composite score or compliance percentage is computed)", metric_ds, h=380)
    d.full("viz_metrics", 380)
    trend = d.search("exec_trend", f"{FIND} {F}\n| timechart span=1d count by status_label")
    d.chart("viz_trend", "Findings by status over time", trend)
    untested = d.search("exec_untested", f"""| inputlookup agentsec_controls
| join type=left control_id [ search {FIND} {FEC} | where mode="ATTACK" OR mode="RETEST" | stats count as tested_hops by control_id ]
| where isnull(tested_hops)
| eval status="Not tested"
| table status control_id control_name class technique""")
    d.table("viz_untested", "Controls with no qualifying test in this range (Not tested: no claim is made)", untested, h=300)
    d.row(("viz_trend", 1), ("viz_untested", 1), h=300)
    standard_findings_table(d, "findings", "Findings: select a row for the finding page (raw events, SPL, framework links, remediation, retest)", h=380)
    d.full("viz_findings", 380)
    d.md("viz_empty_help", "## Reading the statuses\n\n" + states_legend(), h=330)
    return d.build()


# --- B. Agent / MCP / A2A
def agent_mcp() -> str:
    d = Dash("ws_assurance_agent_mcp", "AI Security Assurance: Agent, MCP and A2A security",
             "Tool authorization outcomes, prompt-injection and tool-misuse attempts, delegation behaviour and scanner findings, from real agent and tool telemetry. An attempted attack is not a confirmed compromise.")
    d.md("viz_head", "# Attempts are not compromises\n\nEach row below separates **attempted** (a run exercised the technique), **blocked** (an enforcing control refused it and nothing executed in the same hop), **permitted** and **executed**. The ATTACK profile is *intentionally vulnerable*: executions there are shown but labelled by design. Tool and A2A behaviour here is the lab's in-process model; no real MCP or A2A transport is involved. " + evidence_note(), h=170)
    cat = d.search("b_outcomes", f"""{UNITS} {F}
| where is_decision=1
| eval control_id=mvindex(mvdedup('agentsec.control.id'),0), decision=mvindex(mvdedup('agentsec.control.decision'),0), tool=mvindex(mvdedup('gen_ai.tool.name'),0), reason=mvindex(mvdedup('agentsec.control.reason'),0)
| fillnull value="(none)" tool
| eval outcome=case(match(reason,"^vulnerable_profile_fail_open"),"permitted by the intentionally vulnerable profile", decision="ALLOW","permitted (authorized grant)", decision="DENY","denied", decision="OBSERVE","observed only (classified)", decision="ERROR","rejected as invalid", true(),decision)
| stats count as decisions, dc(run_id) as runs by control_id, tool, outcome
| sort control_id, tool
| table control_id tool outcome decisions runs""")
    d.table("viz_outcomes", "Tool invocation and authorization outcomes (all decisions, including permitted ones)", cat, h=320)
    cls = d.search("b_blocked", f"""{FIND} {F}
| eval category=case(decision="DENY" AND status="VERIFIED_EFFECTIVE","Blocked: verified (denied, nothing executed in the hop)", decision="DENY" AND status="INSUFFICIENT_EVIDENCE","Blocked decision, UNVERIFIED (telemetry incomplete)", decision="DENY","DENY but the operation executed (control failure)", status="VERIFIED_INEFFECTIVE" AND by_design=1,"Permitted and executed: intentionally vulnerable profile (by design)", status="VERIFIED_INEFFECTIVE","Permitted and executed: control failure", decision="OBSERVE","Observed only: effectiveness not established", decision="ERROR","Rejected as invalid", status="INSUFFICIENT_EVIDENCE","Unverified: incomplete telemetry", true(),"Other")
| stats count as operations, dc(run_id) as runs by category
| sort - operations""")
    d.table("viz_blocked", "Blocked, permitted and unverified operations", cls, h=320)
    d.row(("viz_outcomes", 3), ("viz_blocked", 2), h=320)
    att = d.search("b_attempts", f"""{UNITS} {F}
| where mode="ATTACK"
| fillnull value="(no attack id)" attack_id
| stats dc(run_id) as attack_runs, dc(eval(if(complete=0,run_id,null()))) as runs_with_incomplete_telemetry by attack_id
| join type=left attack_id [ search {FIND} {F} | where mode="ATTACK" | stats count(eval(status="VERIFIED_INEFFECTIVE" AND by_design=0)) as confirmed_control_failures, count(eval(status="VERIFIED_INEFFECTIVE" AND by_design=1)) as executed_by_design, count(eval(status="VERIFIED_EFFECTIVE")) as blocked_in_attack_run, count(eval(status="INSUFFICIENT_EVIDENCE")) as unverified by attack_id ]
| join type=left attack_id [ search {FIND} {F} | where mode="RETEST" | stats count(eval(status="VERIFIED_EFFECTIVE")) as retest_blocked, count(eval(status="VERIFIED_INEFFECTIVE")) as retest_failed by attack_id ]
| fillnull value=0
| lookup agentsec_attack_workshops attack_id OUTPUT workshops
| sort attack_id
| table attack_id workshops attack_runs runs_with_incomplete_telemetry confirmed_control_failures executed_by_design blocked_in_attack_run unverified retest_blocked retest_failed""")
    d.table("viz_attempts", "Attempted attacks versus confirmed outcomes, by attack id. A zero here means none was observed among runs with complete telemetry: check runs_with_incomplete_telemetry first. The attack id names a lab specimen such as MCP-003, not a MITRE technique.", att, h=300)
    pi = d.search("b_technique", f"""{FIND} {F}
| where control_id!="(none)" AND control_id!="(run)"
| fillnull value="(control not in the catalogue)" technique boundary
| stats dc(run_id) as runs, count as operations, count(eval(status="VERIFIED_EFFECTIVE")) as verified_effective, count(eval(status="VERIFIED_INEFFECTIVE")) as verified_ineffective, count(eval(status="FINDING_OBSERVED")) as finding_observed, count(eval(status="INSUFFICIENT_EVIDENCE")) as insufficient by technique, boundary
| sort - operations""")
    d.table("viz_technique", "Prompt injection and tool misuse by technique and trust boundary", pi, h=300)
    d.row(("viz_attempts", 3), ("viz_technique", 2), h=300)
    a2a = d.search("b_a2a", f"{FIND} {F}\n| where control_id IN (\"CTRL-DELEGATION-001\",\"CTRL-IDENTITY-001\")\n| sort - _time\n| table {FINDING_COLS}")
    d.table("viz_a2a", "Delegation and identity-claim behaviour (the lab's coded agents; not an A2A transport)", a2a, h=300, drill=True)
    d.full("viz_a2a", 300)
    standard_findings_table(d, "b_findings", "All findings for this view (select a row to open the finding page)", "", h=360)
    d.full("viz_b_findings", 360)
    scan = d.search("b_scan", """index=agentsec_telemetry sourcetype=agentsec:scanner:finding "event.name"=agentsec.scanner.finding
| eval scan_id=mvindex(mvdedup(scan_id),0), rule=mvindex(mvdedup('finding.native_rule_id'),0), category=mvindex(mvdedup('finding.native_category'),0), severity=mvindex(mvdedup('finding.native_severity'),0), tool_name=mvindex(mvdedup('finding.tool_name'),0), scanner=mvindex(mvdedup('scanner.name'),0), scanner_version=mvindex(mvdedup('scanner.version'),0), evidence_class_scanner=mvindex(mvdedup('evidence_class'),0)
| stats dc(scan_id) as scans, count as findings by scanner, scanner_version, category, severity, tool_name, rule
| sort - findings
| eval note="Scanner severity is the scanner's own rating. It is not proof of exploitation and not a control-effectiveness result."
| table scanner scanner_version category severity tool_name rule scans findings note""")
    d.table("viz_scan", "MCP scanner findings (static analysis of tool descriptions; Finding observed, never confirmed exploitation). Scanner evidence is separate from runtime evidence: the evidence-class and workshop filters above do not apply to this panel.", scan, h=300)
    cat2 = d.search("b_catalog", """index=agentsec_telemetry sourcetype=agentsec:scanner:finding "event.name"=agentsec.scanner.scan
| eval scan_id=mvindex(mvdedup(scan_id),0), fixture=mvindex(mvdedup('artifact.fixture'),0), description_sha256=mvindex(mvdedup('artifact.description_sha256'),0), tool_count=mvindex(mvdedup('artifact.tool_count'),0), classification=mvindex(mvdedup('scan.classification'),0), finding_count=mvindex(mvdedup('scan.finding_count'),0)
| stats earliest(_time) as first_seen, latest(_time) as last_seen, dc(description_sha256) as distinct_descriptions, values(scan_id) as scans, values(classification) as classification, max(finding_count) as finding_count by fixture
| eval catalog_change=if(distinct_descriptions>1,"description changed between scans","no change observed between the scans in range")
| convert ctime(first_seen) ctime(last_seen)
| table fixture tool_count scans classification finding_count distinct_descriptions catalog_change first_seen last_seen""")
    d.table("viz_catalog", "Tool discovery and catalog changes (the same artifact scanned at different times: did its description hash change?). Not filtered by evidence class or workshop.", cat2, h=300)
    d.row(("viz_scan", 3), ("viz_catalog", 2), h=300)
    corr = d.search("b_corr", """index=agentsec_telemetry ((sourcetype=agentsec:scanner:finding "event.name"=agentsec.scanner.scan) OR (sourcetype=otel:agentic:json "event.name"=agentsec.control.decision "agentsec.control.id"=CTRL-MCP-METADATA-001))
| eval hash=coalesce(mvindex(mvdedup('artifact.description_sha256'),0), mvindex(mvdedup('agentsec.content.hash'),0))
| where isnotnull(hash)
| eval kind=if(sourcetype="agentsec:scanner:finding","scanner","runtime"), scan_id=mvindex(mvdedup(scan_id),0), run_id=mvindex(mvdedup('agentsec.run.id'),0), mode=mvindex(mvdedup('agentsec.testbed.mode'),0)
| stats values(kind) as evidence_kinds, values(scan_id) as scan_id, values(run_id) as runtime_runs, values(mode) as runtime_modes by hash
| eval linked=if(mvcount(evidence_kinds)=2,"scanner and runtime share this description hash","only one side present: no link is claimed")
| table hash evidence_kinds scan_id runtime_runs runtime_modes linked""")
    d.table("viz_corr", "Scanner finding to runtime evidence: linked only by the explicit description hash, never by timestamp. Runtime sides can be LIVE or RECORDED; check the run before treating a match as current.", corr, h=260)
    d.row(("viz_corr", 1), h=260)
    return d.build()


# --- C. Supply chain and model
def supply_chain() -> str:
    d = Dash("ws_assurance_supply_chain", "AI Security Assurance: AI supply chain and model security",
             "Scanner findings, the declared component inventory, model identity and model evaluation evidence. A scanner severity is not proof of exploitation, and a missing component record is shown as missing.")
    d.md("viz_head", "# Supply chain and model evidence\n\n**Declared** means read from a file in the repository (`deploy/*.lock.json`); it describes what the installer pins, not what a running host proves. **Observed** means a field in telemetry. The lab produces **no AI BOM document** (for example CycloneDX); the declared inventory below is not one. **Nemotron has not been evaluated** by this lab; no comparison is shown unless matching evidence is in the index. " + DISCLAIM, h=190)
    sc = d.search("c_scan", """index=agentsec_telemetry sourcetype=agentsec:scanner:finding "event.name"=agentsec.scanner.finding
| eval scan_id=mvindex(mvdedup(scan_id),0), artifact_type=mvindex(mvdedup('artifact.type'),0), tool=mvindex(mvdedup('finding.tool_name'),0), category=mvindex(mvdedup('finding.native_category'),0), severity=mvindex(mvdedup('finding.native_severity'),0), rule=mvindex(mvdedup('finding.native_rule_id'),0), title=mvindex(mvdedup('finding.title'),0), summary=mvindex(mvdedup('finding.summary'),0), scanner=mvindex(mvdedup('scanner.name'),0), scanner_version=mvindex(mvdedup('scanner.version'),0), raw_sha=mvindex(mvdedup('provenance.raw_output_sha256'),0)
| eval status="Finding observed", confidence="Inferred", note="Scanner rating only: not confirmed exploitation, not control effectiveness."
| table _time status confidence scanner scanner_version artifact_type tool category severity rule title summary raw_sha scan_id note""")
    d.table("viz_scan", "Agent skill and tool scanner findings (artifact types seen below; if no agent-skill artifact appears, no agent skill was scanned)", sc, h=340)
    d.row(("viz_scan", 1), h=340)
    st = d.search("c_artifacts", """index=agentsec_telemetry sourcetype=agentsec:scanner:finding "event.name"=agentsec.scanner.scan
| eval scan_id=mvindex(mvdedup(scan_id),0), artifact_type=mvindex(mvdedup('artifact.type'),0), fixture=mvindex(mvdedup('artifact.fixture'),0), tool_count=mvindex(mvdedup('artifact.tool_count'),0), classification=mvindex(mvdedup('scan.classification'),0), finding_count=mvindex(mvdedup('scan.finding_count'),0), scanner=mvindex(mvdedup('scanner.name'),0), static_scan=mvindex(mvdedup('execution.static_scan'),0), target_executed=mvindex(mvdedup('execution.target_executed'),0), llm_used=mvindex(mvdedup('execution.llm_used'),0)
| table _time scan_id scanner artifact_type fixture tool_count classification finding_count static_scan target_executed llm_used""")
    d.table("viz_artifacts", "Scans performed (what was scanned and how: static, target not executed, no language model)", st, h=300)
    comp = d.search("c_declared", """| inputlookup agentsec_declared_components
| eval basis="DECLARED (lock file), not observed on a host", evidence=if(pinned_by_digest="yes","digest pinned","MISSING OR INCOMPLETE: "+pinned_by_digest)
| table component_type component reference digest pinned_by_digest lock_status used_by evidence declared_in basis""", tr=False)
    d.table("viz_declared", "Declared component inventory: images and models (the nearest the lab has to an AI BOM; it is not one)", comp, h=300)
    d.row(("viz_artifacts", 3), ("viz_declared", 3), h=300)
    mi = d.search("c_models", f"""{UNITS} {F}
| where ev="agentsec.llm.started" OR ev="agentsec.llm.completed"
| eval requested=mvindex(mvdedup('gen_ai.request.model'),0), responded=mvindex(mvdedup('gen_ai.response.model'),0), provider=mvindex(mvdedup('gen_ai.provider.name'),0)
| fillnull value="(not recorded)" requested responded provider
| stats dc(run_id) as runs, count as model_events, values(mode) as modes, values(evidence_class) as evidence_classes by provider, requested, responded
| eval identity_check=case(requested="(not recorded)","no requested model recorded (incomplete)", responded="(not recorded)","response model not recorded (cannot confirm)", requested=responded,"requested model matches the model that answered", true(),"MISMATCH: requested and responding model differ")
| table provider requested responded identity_check runs model_events modes evidence_classes""")
    d.table("viz_models", "Observed model identity in runtime telemetry (version/digest of the installed model is recorded by the Loan Desk run record and by Ollama, not by these events)", mi, h=260)
    ev = d.search("c_eval", """index=agentsec_telemetry sourcetype=agentsec:external:evaluation
| eval model=mvindex(mvdedup('external.subject.id'),0), tool=mvindex(mvdedup('external.tool'),0), tool_version=mvindex(mvdedup('external.tool_version'),0), probe=mvindex(mvdedup('evaluation.probe'),0), detector=mvindex(mvdedup('evaluation.detector'),0), passed=tonumber(mvindex(mvdedup('evaluation.passed'),0)), fails=tonumber(mvindex(mvdedup('evaluation.fails'),0)), total=tonumber(mvindex(mvdedup('evaluation.total_evaluated'),0)), evidence_class=mvindex(mvdedup('external.evidence_class'),0), raw_sha=mvindex(mvdedup('external.raw_evidence_sha256'),0)
| eval status="Finding observed", note="An evaluation result for one model, probe and detector; not a general model-security rating and not control effectiveness."
| table _time status model tool tool_version probe detector passed fails total evidence_class raw_sha note""")
    d.table("viz_eval", "Model security evaluation evidence (external adversarial evaluations ingested into this index)", ev, h=260)
    d.row(("viz_models", 1), ("viz_eval", 1), h=260)
    nem = d.search("c_nemotron", """index=agentsec_telemetry sourcetype=agentsec:external:evaluation
| eval model=mvindex(mvdedup('external.subject.id'),0)
| stats count as evaluations, dc(model) as models, values(model) as models_seen, count(eval(like(lower(model),"%nemotron%"))) as nemotron_evaluations
| eval status=if(nemotron_evaluations=0,"Not tested","Finding observed"), message=if(nemotron_evaluations=0,"Not tested: the index holds no Nemotron evaluation evidence (models evaluated: ".coalesce(mvjoin(models_seen,", "),"none")."). No Nemotron versus baseline comparison is shown, and none is implied.","Nemotron evidence exists: compare it with the baseline model in the evaluation table above, probe by probe. A pass rate on one probe is not a general ranking.")
| table status message""")
    d.table("viz_nemotron", "Nemotron versus baseline model security tests", nem, h=160)
    d.row(("viz_nemotron", 1), h=160)
    fr = d.search("c_frameworks", """| inputlookup agentsec_framework_items
| search item_id IN ("LLM03:2025","ASI04","AML.T0010","AML.T0010.001","AML.M0023","AML.M0035","MAP 4.1","GOVERN 6.1","MG-3.1-002","GV-6.1-007","A.10.3")
| eval claim="Educational link only; no compliance claim"
| table framework item_id item_name verification version_or_date retrieved_on limits claim""", tr=False)
    d.table("viz_frameworks", "Relevant supply-chain guidance (identifiers verified on the retrieval date shown)", fr, h=320)
    d.row(("viz_frameworks", 1), h=320)
    return d.build()


# --- D. Threat modelling and defence coverage
def threat_coverage() -> str:
    d = Dash("ws_assurance_threat_model", "AI Security Assurance: Threat modeling and defense coverage (CSA MAESTRO)",
             "Connects the lab's MAESTRO threat model to observed lab activity. Modeled threats and observed incidents are separate columns: a modeled threat is not an incident, and an untested threat is not mitigated.")
    d.md("viz_head", "# Modeled versus observed\n\n**Modeled** = a threat in the lab's worked MAESTRO example (`learning/level_1/LAB-THREAT-MODELING-001/maestro.json`, the lab author's analysis, not CSA material). **Observed** = findings from telemetry on the controls that threat names. A threat whose controls have no ATTACK or RETEST finding is **Not tested**; it is never shown as mitigated. MAESTRO layers: 1 Foundation Models, 2 Data Operations, 3 Agent Frameworks, 4 Deployment and Infrastructure, 5 Evaluation and Observability, 6 Security and Compliance (vertical), 7 Agent Ecosystem. The lab implements MAESTRO v1 as a workbench; it does not run CSA's Threat Analyzer. " + evidence_note(), h=200)
    lay = d.search("d_layers", f"""| inputlookup agentsec_maestro_threats
| stats count as modeled_threats, count(eval(modeled_evidence_status="DEMONSTRATED")) as modeled_demonstrated, count(eval(modeled_evidence_status="DOCUMENTED")) as modeled_documented, count(eval(modeled_evidence_status="ASSUMED")) as modeled_assumed by layer, layer_name
| join type=left layer [ search {FIND} {F} | where control_id!="(none)" AND control_id!="(run)" | eval layer=split(maestro_layers,"|") | mvexpand layer | stats count(eval(status="VERIFIED_EFFECTIVE")) as observed_verified_effective, count(eval(status="VERIFIED_INEFFECTIVE" AND by_design=0)) as observed_control_failures, count(eval(status="VERIFIED_INEFFECTIVE" AND by_design=1)) as observed_executed_by_design, count(eval(status="FINDING_OBSERVED")) as observed_finding, count(eval(status="INSUFFICIENT_EVIDENCE")) as observed_insufficient by layer ]
| fillnull value=0
| eval observed_status=if(observed_verified_effective+observed_control_failures+observed_executed_by_design+observed_finding+observed_insufficient=0,"Not tested","observed")
| sort layer
| table layer layer_name modeled_threats modeled_demonstrated modeled_documented modeled_assumed observed_status observed_verified_effective observed_control_failures observed_executed_by_design observed_finding observed_insufficient""")
    d.table("viz_layers", "MAESTRO layers: modeled threats (left) versus observed evidence (right)", lay, h=300)
    d.row(("viz_layers", 1), h=300)
    reg = d.search("d_register", f"""| inputlookup agentsec_maestro_threats
| eval control_id=split(controls,"|")
| mvexpand control_id
| join type=left control_id [ search {FIND} {F} | where control_id!="(none)" AND control_id!="(run)" | stats count(eval(status="VERIFIED_EFFECTIVE")) as eff, count(eval(status="VERIFIED_INEFFECTIVE" AND by_design=0)) as ineff, count(eval(status="VERIFIED_INEFFECTIVE" AND by_design=1)) as design, count(eval(status="FINDING_OBSERVED")) as obs, count(eval(status="INSUFFICIENT_EVIDENCE")) as insuff by control_id ]
| lookup agentsec_controls control_id OUTPUT class AS ctrl_class
| eval has_telemetry=if(isnotnull(ctrl_class),1,0)
| eval control_view=case(has_telemetry=0,control_id." (no telemetry-producing control: not testable here)", isnull(eff) AND isnull(ineff) AND isnull(design) AND isnull(obs) AND isnull(insuff), control_id." (Not tested)", true(), control_id." (effective ".coalesce(eff,0).", control failures ".coalesce(ineff,0).", executed by design under the vulnerable profile ".coalesce(design,0).", observed ".coalesce(obs,0).", insufficient ".coalesce(insuff,0).")")
| stats values(control_view) as observed_by_control, sum(eff) as eff, sum(ineff) as ineff, sum(design) as design, sum(obs) as obs, sum(insuff) as insuff, sum(has_telemetry) as telemetry_controls by threat_id, layer, threat, modeled_evidence_status, workshops, residual_impact_likelihood
| eval observed_status=case(telemetry_controls=0,"Not tested", coalesce(ineff,0)>0,"Verified ineffective: a control failure outside the vulnerable profile", coalesce(eff,0)>0,"Verified effective in the defended retests observed (the vulnerable profile executed by design in ".coalesce(design,0)." attack hops)", coalesce(design,0)>0,"Only the intentionally vulnerable profile was observed: no defended retest verified", coalesce(obs,0)>0,"Finding observed", coalesce(insuff,0)>0,"Insufficient evidence", true(),"Not tested")
| sort layer, threat_id
| table threat_id layer threat modeled_evidence_status residual_impact_likelihood observed_status observed_by_control workshops""")
    d.table("viz_register", "Modeled threats and their observed evidence (modeled evidence status is the analysis; observed status is from telemetry)", reg, h=480)
    d.row(("viz_register", 1), h=480)
    tech = d.search("d_techniques", f"""{FIND} {F}
| where control_id!="(none)" AND control_id!="(run)"
| stats dc(run_id) as runs, values(attack_id) as attack_ids, values(status_label) as statuses, values(maestro_layers) as layers by technique, boundary, control_id
| sort technique
| table technique boundary control_id layers attack_ids runs statuses""")
    d.table("viz_techniques", "Observed attack techniques, the trust boundary each reached and the control exercised", tech, h=300)
    inv = d.search("d_links", f"""{FIND} {F}
| where control_id!="(none)" AND control_id!="(run)"
| stats dc(run_id) as runs, latest(run_id) as example_run, values(workshops) as workshops by control_id
| eval investigation="Open the workshop dashboard for the run in Splunk (ws_lab_*), or the finding page for the SPL"
| table control_id workshops runs example_run investigation""")
    d.table("viz_links", "Links to supporting investigations (workshop dashboards and the finding page SPL)", inv, h=300)
    d.row(("viz_techniques", 3), ("viz_links", 2), h=300)
    standard_findings_table(d, "d_findings", "Findings behind this view (select a row for the finding page)", h=340)
    d.full("viz_d_findings", 340)
    return d.build()


# --- E. Compliance and governance
def compliance() -> str:
    d = Dash("ws_assurance_compliance", "AI Security Assurance: Compliance and governance evidence",
             "Maps observed lab evidence to guidance from NIST AI RMF and AI 600-1, OWASP LLM and Agentic, MITRE ATLAS, CSA MAESTRO and ISO/IEC 42001. It makes no certification or compliance claim.")
    d.md("viz_head", "# What this is, and is not\n\n" + DISCLAIM + " Mappings are **educational relationships** (kind and rationale are shown); none says an item is satisfied. Identifiers were verified against the sources on the retrieval date shown; ISO/IEC 42001 identifiers are `VERIFIED_WITH_LIMITS` because the standard is paywalled. **No compliance percentage is computed.** " + evidence_note(), h=190)
    mat = d.search("e_matrix", f"""| inputlookup agentsec_framework_map
| join type=left control_id [ search {FIND} {F} | where control_id!="(none)" AND control_id!="(run)" | stats count(eval(status="VERIFIED_EFFECTIVE")) as eff, count(eval(status="VERIFIED_INEFFECTIVE" AND by_design=0)) as ineff, count(eval(status="VERIFIED_INEFFECTIVE" AND by_design=1)) as design, count(eval(status="FINDING_OBSERVED")) as obs, count(eval(status="INSUFFICIENT_EVIDENCE")) as insuff, count(eval(mode="ATTACK" OR mode="RETEST")) as tested by control_id ]
| fillnull value=0 eff ineff design obs insuff tested
| stats sum(eff) as verified_effective, sum(ineff) as control_failures, sum(design) as executed_by_design, sum(obs) as finding_observed, sum(insuff) as insufficient, sum(tested) as tested_hops, values(control_id) as controls, values(kind) as relationship_kinds, values(verification) as identifier_verification, values(version_or_date) as version by framework, item_id, item_name
| eval evidence_status=case(tested_hops=0,"Not tested", control_failures>0,"Verified ineffective for at least one observed attempt outside the vulnerable profile", verified_effective>0,"Verified effective for the observed defended attempts only", executed_by_design>0,"Only the intentionally vulnerable profile was observed: no defended retest verified", finding_observed>0,"Finding observed", insufficient>0,"Insufficient evidence", true(),"Not tested")
| eval claim="No compliance claim: lab evidence for the mapped lab controls only"
| sort framework, item_id
| table framework item_id item_name evidence_status verified_effective control_failures executed_by_design finding_observed insufficient controls relationship_kinds identifier_verification version claim""")
    d.table("viz_matrix", "Framework item to lab evidence (evidence status is the status model; it describes lab controls, not your organization)", mat, h=520)
    d.row(("viz_matrix", 1), h=520)
    rev = d.search("e_workshop", f"""{FIND} {F}
| where control_id!="(none)" AND control_id!="(run)"
| eval ws=split(workshops,"|")
| mvexpand ws
| stats count as operations, count(eval(status="VERIFIED_EFFECTIVE")) as verified_effective, count(eval(status="VERIFIED_INEFFECTIVE")) as verified_ineffective, count(eval(status="FINDING_OBSERVED")) as finding_observed, count(eval(status="INSUFFICIENT_EVIDENCE")) as insufficient, values(control_id) as controls by ws
| table ws operations verified_effective verified_ineffective finding_observed insufficient controls
| rename ws as workshop""")
    d.table("viz_workshop", "Reverse path: from each workshop to the controls it exercised (frameworks for each control are in the table above)", rev, h=300)
    ver = d.search("e_versions", """| inputlookup agentsec_framework_items
| stats count as identifiers_used, values(verification) as verification, values(version_or_date) as version, max(retrieved_on) as retrieved_on, values(source_url) as source, values(limits) as limits by framework
| sort framework""", tr=False)
    d.table("viz_versions", "Framework references: version, verification and source", ver, h=300)
    d.row(("viz_workshop", 3), ("viz_versions", 3), h=300)
    standard_findings_table(d, "e_findings", "Underlying findings (select a row for the finding page)", h=340)
    d.full("viz_e_findings", 340)
    d.md("viz_note", "## Version notes\n\n" + "\n\n".join(f"**{k}**: {v}" for k, v in fmap["version_notes"].items()), h=220)
    return d.build()


# --- F. Finding detail
def finding_detail() -> str:
    d = Dash("ws_assurance_finding", "AI Security Assurance: Finding", "One finding with its evidence, meaning, mapping, remediation and retest. Opened from a finding row.", filters=False)
    hidden = {"input_run": {"type": "input.text", "title": "Run id", "options": {"token": "run_id", "defaultValue": ""}},
              "input_ctl": {"type": "input.text", "title": "Control id", "options": {"token": "control_id", "defaultValue": ""}},
              "input_hop": {"type": "input.text", "title": "Hop", "options": {"token": "hop", "defaultValue": ""}}}
    d.md("viz_head", "# Finding\n\nPath: **Dashboard, Finding, Raw evidence, Investigation, Workshop, Remediation, Retest.** Every field below comes from the telemetry for this run or from the control catalogue; none is generated by a language model. " + DISCLAIM, h=130)
    fid = d.search("f_card", f"""{FIND}
| where run_id="$run_id$" AND control_id="$control_id$" AND (coalesce(hop,"-")="$hop$" OR "$hop$"="" OR "$hop$"="-")
| eval retest=retest_outcome.if(isnotnull(retest_run)," (run ".retest_run.")","")
| table status_label confidence evidence_class observation interpretation impact control_interpretation recommended_action retest_check retest workshops""")
    d.table("viz_card", "The finding: observation, interpretation, impact, control interpretation, action and retest", fid, h=300)
    d.full("viz_card", 300)
    raw = d.search("f_raw", """index=agentsec_telemetry sourcetype=otel:agentic:json "agentsec.run.id"="$run_id$"
| eval seq=tonumber(mvindex(mvdedup('agentsec.sequence'),0)), event=mvindex(mvdedup('event.name'),0), hop=mvindex(mvdedup('agentsec.hop.index'),0), control=mvindex(mvdedup('agentsec.control.id'),0), decision=mvindex(mvdedup('agentsec.control.decision'),0), reason=mvindex(mvdedup('agentsec.control.reason'),0), tool=mvindex(mvdedup('gen_ai.tool.name'),0), attempted=mvindex(mvdedup('agentsec.operation.attempted'),0), executed=mvindex(mvdedup('agentsec.operation.executed'),0), boundary=mvindex(mvdedup('agentsec.trust_boundary'),0), mode=mvindex(mvdedup('agentsec.testbed.mode'),0), profile=mvindex(mvdedup('agentsec.security.profile'),0), outcome=mvindex(mvdedup('agentsec.outcome'),0)
| dedup seq
| sort seq
| table seq _time event hop control decision reason tool attempted executed boundary mode profile outcome""")
    d.table("viz_raw", "Raw evidence: the run's events in order (the hop of this finding is the one the rule judged)", raw, h=360)
    d.full("viz_raw", 360)
    fm = d.search("f_frameworks", """| inputlookup agentsec_framework_map
| search control_id="$control_id$"
| table framework item_id item_name kind relationship rationale verification version_or_date retrieved_on source_url""", tr=False)
    d.table("viz_fm", "Relevant guidance for this control (educational relationships, not compliance claims)", fm, h=300)
    d.full("viz_fm", 300)
    d.md("viz_how", "## Reproduce and verify\n\n1. The SPL above (`index=agentsec_telemetry sourcetype=otel:agentic:json \"agentsec.run.id\"=\"<run id>\" | sort agentsec.sequence`) lists every event of the run. Compare the `control.decision` row with any `mcp.started` or `llm.started` row that has the same `hop`.\n2. Open the workshop named in the finding in the Academy (`/learn/lab/<ID>`) or its Splunk dashboard (`ws_lab_*`) to repeat the run: BASELINE, then ATTACK, then RETEST.\n3. After a change, run RETEST again. The dashboards re-evaluate from the new telemetry; the retest outcome on the ATTACK finding changes only when a RETEST with the same attack id and control id shows the control effective.", h=210)
    return d.build(extra_inputs=hidden)


def generate() -> dict[Path, str]:
    out: dict[Path, str] = {}
    for name, text in lookups().items():
        out[APP / "lookups" / name] = text
    out[APP / "default" / "transforms.conf"] = TRANSFORMS
    macros = (APP / "default" / "macros.conf").read_text(encoding="utf-8")
    keep = macros.split("# ---- AI Security Assurance")[0].rstrip() + "\n\n"
    out[APP / "default" / "macros.conf"] = keep + S.macros_conf(rules)
    for view, fn in (("ws_assurance_executive", executive), ("ws_assurance_agent_mcp", agent_mcp), ("ws_assurance_supply_chain", supply_chain),
                     ("ws_assurance_threat_model", threat_coverage), ("ws_assurance_compliance", compliance), ("ws_assurance_finding", finding_detail)):
        out[APP / "default/data/ui/views" / f"{view}.xml"] = fn()
    return out


def main() -> int:
    out = generate()
    if "--check" in sys.argv:
        bad = [str(p.relative_to(ROOT)) for p, t in out.items() if not p.exists() or p.read_text(encoding="utf-8") != t]
        print("generated files differ from disk:" if bad else "generated files are current", *bad, sep="\n  ")
        return 1 if bad else 0
    for p, t in out.items():
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(t, encoding="utf-8")
    print(f"wrote {len(out)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
