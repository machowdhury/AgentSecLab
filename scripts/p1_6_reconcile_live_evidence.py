#!/usr/bin/env python3
"""Reconcile LAB-MCP-001 run records with independent Splunk searches (read-only).

usage: p1_6_reconcile_live_evidence.py --out FILE LIVE:<run.id> REPLAY:<run.id> ...

LIVE records are read from artifacts/<run.id>/events.jsonl, REPLAY records from the
committed specimen packs. Splunk auth stays inside the agentsec_splunk container
(scripts/splunk_cli_csv.py). A run reconciles only if event count, the single
CTRL-MCP-001 decision, mcp.started and pipeline.stopped counts all match.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from splunk_cli_csv import splunk  # noqa: E402

RUN_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
SPECIMENS = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "specimens"
LLM_PREFIXES = ("agentsec.llm.", "gen_ai.client.inference")


def local_facts(run_id: str, provenance: str) -> dict:
    path = ROOT / "artifacts" / run_id / "events.jsonl" if provenance == "LIVE" else SPECIMENS / f"{run_id}.jsonl"
    events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    names = [e.get("event.name") or "" for e in events]
    decisions = [e for e in events if e.get("event.name") == "agentsec.control.decision"]
    return {
        "source": str(path.relative_to(ROOT)),
        "events": len(events),
        "decision": decisions[0].get("agentsec.control.decision") if decisions else "NOT MEASURED",
        "reason_code": str(decisions[0].get("agentsec.control.reason", "")).split(":")[0] if decisions else "NOT MEASURED",
        "mcp_started": names.count("agentsec.mcp.started"),
        "pipeline_stopped": names.count("agentsec.pipeline.stopped"),
        "llm_events": sum(1 for n in names if n.startswith(LLM_PREFIXES)),
        "schema": sorted({str(e.get("agentsec.schema.version")) for e in events}),
        "first": min(e.get("timestamp", "") for e in events),
        "last": max(e.get("timestamp", "") for e in events),
    }


def splunk_facts(run_id: str) -> dict:
    base = f'index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0 "agentsec.run.id"="{run_id}"'
    totals = splunk(
        base + " | eval en='event.name' | stats count as n dc(_raw) as distinct_raw"
        ' sum(eval(if(en="agentsec.mcp.started",1,0))) as mcp_started'
        ' sum(eval(if(en="agentsec.pipeline.stopped",1,0))) as pipeline_stopped'
        ' sum(eval(if(like(en,"agentsec.llm.%") OR like(en,"gen_ai.client.inference%"),1,0))) as llm_events'
        " values(agentsec.schema.version) as schema min(_time) as first max(_time) as last"
    )
    # The decision attribute is multivalued on the decision event in Splunk; dedupe and require one value.
    decisions = splunk(
        base + ' "event.name"="agentsec.control.decision"'
        " | eval raw_values=mvcount('agentsec.control.decision'),"
        " distinct=mvcount(mvdedup('agentsec.control.decision')),"
        " d=mvindex(mvdedup('agentsec.control.decision'),0),"
        " rsn=mvindex(mvdedup('agentsec.control.reason'),0)"
        " | table d rsn raw_values distinct"
    )
    row = totals[0] if totals else {}
    first = decisions[0] if decisions else {}
    decision = first.get("d", "NOT FOUND") if first.get("distinct") in ("1", None) else "AMBIGUOUS"
    return {
        "events": int(row.get("n", 0) or 0),
        "distinct_raw": int(row.get("distinct_raw", 0) or 0),
        "decision_events": len(decisions),
        "decision_field_raw_values": first.get("raw_values"),
        "decision": decision if decisions else "NOT FOUND",
        "reason_code": str(first.get("rsn", "NOT FOUND")).split(":")[0],
        "mcp_started": int(float(row.get("mcp_started", 0) or 0)),
        "pipeline_stopped": int(float(row.get("pipeline_stopped", 0) or 0)),
        "llm_events": int(float(row.get("llm_events", 0) or 0)),
        "schema": row.get("schema", ""),
        "first_epoch": row.get("first"),
        "last_epoch": row.get("last"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("runs", nargs="+", help="LIVE:<run.id> or REPLAY:<run.id>")
    args = parser.parse_args()
    result = {"queried_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "index": "agentsec_telemetry", "sourcetype": "otel:agentic:json", "runs": []}
    for spec in args.runs:
        provenance, _, run_id = spec.partition(":")
        if provenance not in ("LIVE", "REPLAY") or not RUN_ID.match(run_id):
            parser.error(f"bad run spec {spec!r}")
        local, remote = local_facts(run_id, provenance), splunk_facts(run_id)
        reconciled = (local["events"] == remote["events"] and local["decision"] == remote["decision"]
                      and local["mcp_started"] == remote["mcp_started"]
                      and local["pipeline_stopped"] == remote["pipeline_stopped"] and remote["decision_events"] == 1)
        result["runs"].append({"run_id": run_id, "provenance": provenance, "local": local, "splunk": remote,
                               "reconciled": reconciled})
        print(run_id, provenance, f"local={local['events']} splunk={remote['events']}",
              f"decision={local['decision']}/{remote['decision']} reason={local['reason_code']}/{remote['reason_code']}",
              f"started={local['mcp_started']}/{remote['mcp_started']} stopped={local['pipeline_stopped']}/{remote['pipeline_stopped']}",
              f"llm={local['llm_events']}/{remote['llm_events']} schema={remote['schema']} reconciled={reconciled}")
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return 0 if all(r["reconciled"] for r in result["runs"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
