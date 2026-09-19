#!/usr/bin/env python3
"""Phase 4C live Splunk CLI helper. Auth stays inside the Splunk container env."""

from __future__ import annotations

import csv
import io
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEARCH = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches"

RUNS = {
    "A": "5b089682-1d5a-49a7-ac43-967265fd6bc6",
    "B": "b466ad12-72ec-44b7-be28-aacfaf2c25b1",
    "C": "f638fd4f-1c4f-4ab6-8d42-4d03a4f3afd5",
    "D": "6ce19813-6cb5-4aae-a3a0-aa59386a82dd",
    "E": "3b8b3ac4-227d-4aa9-9d6f-4245a300bf57",
    "F": "c19a4f15-7e94-44f6-b498-238234b0b082",
}


def splunk(spl: str) -> list[dict]:
    collapsed = " ".join(line.strip() for line in spl.splitlines() if line.strip())
    inner = (
        "/opt/splunk/bin/splunk search "
        + json.dumps(collapsed)
        + ' -auth "admin:${SPLUNK_PASSWORD}" -output csv'
    )
    proc = subprocess.run(
        ["docker", "exec", "-u", "splunk", "agentsec_splunk", "bash", "-lc", inner],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr[-800:] if proc.stderr else "splunk search failed\n")
        raise SystemExit(proc.returncode)
    lines = [ln for ln in (proc.stdout or "").splitlines() if ln and not ln.startswith("WARNING:")]
    if not lines:
        return []
    return list(csv.DictReader(io.StringIO("\n".join(lines))))


def q(name: str, run_id: str) -> list[dict]:
    spl = (SEARCH / f"{name}.spl").read_text(encoding="utf-8").replace("__RUN_ID__", run_id)
    return splunk(spl)


def main() -> None:
    action = sys.argv[1] if len(sys.argv) > 1 else "all"
    if action == "completeness":
        for key, rid in RUNS.items():
            local = sum(
                1
                for line in (ROOT / "artifacts" / rid / "events.jsonl").read_text().splitlines()
                if line
            )
            rows = splunk(
                'index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0 '
                f'"agentsec.run.id"={rid} | stats dc(_raw) as n'
            )
            n = int(rows[0]["n"]) if rows else 0
            print(json.dumps({"id": key, "run_id": rid, "local": local, "splunk": n}))
        return
    if action.startswith("Q-") or action.startswith("DET-"):
        rid = sys.argv[2]
        if action.endswith(".spl"):
            spl = Path(action).read_text(encoding="utf-8")
            if "__RUN_ID__" in spl:
                spl = spl.replace("__RUN_ID__", rid)
            print(json.dumps(splunk(spl), indent=2))
            return
        print(json.dumps(q(action, rid), indent=2))
        return
    print("usage: completeness | Q-MCP-WHO <run_id> | raw.spl <run_id>", file=sys.stderr)
    raise SystemExit(2)


if __name__ == "__main__":
    main()
