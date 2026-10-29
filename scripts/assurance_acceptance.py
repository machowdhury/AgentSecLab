#!/usr/bin/env python3
"""Acceptance tooling for the AI Security Assurance dashboards. Run on a host that has the lab's Splunk container; nothing here touches the network.

  fixtures   Write synthetic NEGATIVE-TEST runs (mutated copies of real runs, lab id 'assurance-test-fixture') for: a lost event, a run still arriving,
             a defended retest where the control stopped working, and a DENY that still executed. Prints what the rules must say about each.
  queries    Run every dashboard data source and the findings macro through the Splunk CLI (no REST, no TLS settings) and report rows and errors per query.
  compare    Compare the findings Splunk computes with the Python reference evaluator on the same events exported from Splunk.

The searches use the Splunk CLI inside the container (`docker exec <container> splunk search`), the same backend the lab's own evidence probe uses.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import re
import subprocess
import sys
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from agentsec.assurance import engine as E  # noqa: E402

MARKER = E.FIXTURE_MARKER
SPEC = ROOT / "learning/level_1/LAB-MCP-003/specimens"
ATTACK, RETEST = "b466ad12-72ec-44b7-be28-aacfaf2c25b1", "f638fd4f-1c4f-4ab6-8d42-4d03a4f3afd5"
NS = uuid.UUID("5b3a2d7e-0c52-4a77-9a70-7a1fe0a55e10")


def _clone(events: list[dict], name: str) -> list[dict]:
    rid = str(uuid.uuid5(NS, name))
    out = []
    for e in events:
        c = json.loads(json.dumps(e))
        c["agentsec.run.id"], c["agentsec.incident.id"], c["agentsec.lab.id"] = rid, rid, MARKER
        out.append(c)
    return out


def fixtures() -> dict[str, dict]:
    atk, ret = E.read_events(SPEC / f"{ATTACK}.jsonl"), E.read_events(SPEC / f"{RETEST}.jsonl")
    out: dict[str, dict] = {}
    lost = [e for e in _clone(ret, "lost-event") if e["agentsec.sequence"] != 4]
    out["lost-event"] = {"events": lost, "expect": [("R-INCOMPLETE", "INSUFFICIENT_EVIDENCE")], "why": "one event of a defended retest never reached Splunk: nothing may be claimed"}
    inflight = [e for e in _clone(ret, "still-arriving") if e["event.name"] != "agentsec.run.completed"]
    out["still-arriving"] = {"events": inflight, "expect": [("R-INCOMPLETE", "INSUFFICIENT_EVIDENCE")], "why": "the run has no terminal event yet"}
    broken = _clone(atk, "control-stopped-working")
    for e in broken:
        e["agentsec.testbed.mode"], e["agentsec.security.profile"] = "RETEST", "defended"
        if e["event.name"] == "agentsec.control.decision":
            e["agentsec.control.reason"] = "tool_granted"
    out["control-stopped-working"] = {"events": broken, "expect": [("RR-RETEST-NOT-PREVENTED", "VERIFIED_INEFFECTIVE")], "why": "a defended retest executed with no enforcing denial"}
    leak = _clone(ret, "deny-but-executed")
    hop = next(e for e in leak if e["event.name"] == "agentsec.control.decision")["agentsec.hop.index"]
    started = json.loads(json.dumps(next(e for e in _clone(atk, "x") if e["event.name"] == "agentsec.mcp.started")))
    started.update({"agentsec.run.id": leak[0]["agentsec.run.id"], "agentsec.incident.id": leak[0]["agentsec.run.id"], "agentsec.hop.index": hop, "agentsec.sequence": 4, "agentsec.lab.id": MARKER,
                    "agentsec.testbed.mode": leak[0]["agentsec.testbed.mode"], "agentsec.security.profile": leak[0]["agentsec.security.profile"], "agentsec.attack.id": leak[0].get("agentsec.attack.id")})   # one run, one mode
    for e in leak:
        if e["agentsec.sequence"] >= 4:
            e["agentsec.sequence"] += 1
    leak.append(started)
    out["deny-but-executed"] = {"events": sorted(leak, key=lambda e: e["agentsec.sequence"]), "expect": [("R-DENY-BYPASSED", "VERIFIED_INEFFECTIVE")], "why": "the control denied but the handler started in the same hop"}
    return out


def cmd_fixtures(a):
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    manifest = {}
    for name, f in fixtures().items():
        path = out / f"{name}.jsonl"
        path.write_text("".join(json.dumps(e, separators=(",", ":")) + "\n" for e in f["events"]), encoding="utf-8")
        findings = E.evaluate(f["events"], recorded=frozenset())
        got = [(x["rule_id"], x["status"]) for x in findings]
        manifest[name] = {"file": path.name, "run_id": f["events"][0]["agentsec.run.id"], "expect": f["expect"], "engine": got, "why": f["why"]}
        assert got == [tuple(x) for x in f["expect"]], (name, got)
    (out / "manifest.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    print(json.dumps(manifest, indent=1))


# ---------------------------------------------------------------------------------------------------------------- Splunk CLI
def splunk_search(container: str, spl: str, earliest="0", latest="now", app="agentsec", timeout=600) -> list[dict]:
    cmd = ["docker", "exec", "-i", container, "sh", "-c",
           f'/opt/splunk/bin/splunk search "$(cat)" -app {app} -earliest_time {earliest} -latest_time {latest} -maxout 0 -output csv -auth "admin:$SPLUNK_PASSWORD"']
    p = subprocess.run(cmd, input=spl, capture_output=True, text=True, timeout=timeout)
    if p.returncode != 0 or p.stdout.startswith("Error") or "FATAL" in p.stdout[:200]:
        raise RuntimeError((p.stdout + p.stderr)[:400])
    return list(csv.DictReader(io.StringIO(p.stdout)))


def view_queries(name: str) -> dict[str, str]:
    root = ET.parse(ROOT / f"splunk_app/agentsec/default/data/ui/views/{name}.xml").getroot()
    d = json.loads(root.find("definition").text)
    return {k: v["options"]["query"] for k, v in d["dataSources"].items()}


TOKENS = {"ec": "*", "ws": "*", "run_id": "", "control_id": "", "hop": "", "tr.earliest": "0", "tr.latest": "now"}


def substitute(q: str, tokens: dict[str, str]) -> str:
    return re.sub(r"\$([\w.]+)\$", lambda m: tokens.get(m.group(1), m.group(0)), q)


def cmd_queries(a):
    rows = []
    tokens = dict(TOKENS)
    if a.run_id:
        tokens.update(run_id=a.run_id, control_id=a.control_id or "", hop=a.hop or "")
    for view in a.views:
        for k, q in view_queries(view).items():
            try:
                res = splunk_search(a.container, substitute(q, tokens))
                rows.append({"view": view, "ds": k, "rows": len(res), "error": ""})
            except Exception as exc:  # noqa: BLE001 - the report is the point
                rows.append({"view": view, "ds": k, "rows": -1, "error": str(exc)[:300]})
    Path(a.out).write_text(json.dumps(rows, indent=1), encoding="utf-8")
    bad = [r for r in rows if r["error"]]
    print(f"{len(rows)} data sources, {len(bad)} with errors")
    for r in rows:
        print(f'{r["view"]:34} {r["ds"]:22} rows={r["rows"]:5} {r["error"][:120]}')
    return 1 if bad else 0


def cmd_compare(a):
    """Export every security event, run the Python evaluator, and compare it with the findings the SPL macro computes. Prints differences."""
    raw = splunk_search(a.container, '`agentsec_index` "agentsec.schema.name"="agentsec.security_event" | dedup _raw | table _raw')
    events = [json.loads(r["_raw"]) for r in raw if r.get("_raw")]
    py = {(f["run_id"], str(f["hop"]) if f["hop"] is not None else "-", f["control_id"], f["rule_id"]): f for f in E.evaluate(events, recorded=E.recorded_run_ids())}
    sp_rows = splunk_search(a.container, '`agentsec_assurance_findings_linked` | search evidence_class="*" | table finding_key status evidence_class retest_outcome')
    sp = {}
    for r in sp_rows:
        parts = r["finding_key"].split("|")
        sp[(parts[0], parts[1], parts[2], parts[3])] = r
    only_py, only_sp = sorted(set(py) - set(sp)), sorted(set(sp) - set(py))
    diff = [(k, py[k]["status"], sp[k]["status"]) for k in sorted(set(py) & set(sp)) if py[k]["status"] != sp[k]["status"]]
    cls = [(k, py[k]["evidence_class"], sp[k]["evidence_class"]) for k in sorted(set(py) & set(sp)) if py[k]["evidence_class"] != sp[k]["evidence_class"]]
    rt = [(k, py[k]["retest"]["outcome"], sp[k]["retest_outcome"]) for k in sorted(set(py) & set(sp)) if py[k]["retest"]["outcome"] != sp[k]["retest_outcome"]]
    report = {"events_exported": len(events), "python_findings": len(py), "splunk_findings": len(sp), "only_python": only_py[:20], "only_splunk": only_sp[:20], "status_differences": diff[:20], "class_differences": cls[:20], "retest_differences": rt[:20]}
    Path(a.out).write_text(json.dumps(report, indent=1, default=str), encoding="utf-8")
    print(json.dumps(report, indent=1, default=str))
    return 0 if not (only_py or only_sp or diff or cls or rt) else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fixtures"); f.add_argument("--out", required=True); f.set_defaults(fn=cmd_fixtures)
    q = sub.add_parser("queries"); q.add_argument("--container", default="agentsec-splunk"); q.add_argument("--out", required=True); q.add_argument("--run-id"); q.add_argument("--control-id"); q.add_argument("--hop")
    q.add_argument("views", nargs="*", default=["ws_assurance_executive", "ws_assurance_agent_mcp", "ws_assurance_supply_chain", "ws_assurance_threat_model", "ws_assurance_compliance", "ws_assurance_finding"]); q.set_defaults(fn=cmd_queries)
    c = sub.add_parser("compare"); c.add_argument("--container", default="agentsec-splunk"); c.add_argument("--out", required=True); c.set_defaults(fn=cmd_compare)
    a = ap.parse_args()
    return a.fn(a) or 0


if __name__ == "__main__":
    raise SystemExit(main())
