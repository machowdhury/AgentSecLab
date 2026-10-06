#!/usr/bin/env python3
"""Run the Investigation Notebook searches against live Splunk for two run.ids.

Unit tests prove the notebook SPL references real field names. They cannot prove
it parses in Splunk or returns rows, because they never reach an indexer. This
script closes that gap: it reads the five searches out of the shipped dashboard
definition, substitutes the token the way Dashboard Studio would, and runs them.

Usage:

    python3 scripts/verify_investigation_notebook_spl.py <attack-run-id> <retest-run-id>

Auth follows scripts/splunk_cli_csv.py: SPLUNK_PASSWORD is expanded by the shell
*inside* the Splunk container, so the credential never appears in this process,
in an argument list, or in any output.

It reports rows. It does not assert an expected decision, because the expected
decision is what the learner is supposed to determine.
"""

from __future__ import annotations

import csv
import io
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFINITION = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "dashboard.definition.json"
CELLS = ("ds_nb_state", "ds_nb_decision", "ds_nb_execution", "ds_nb_scope", "ds_nb_timeline")
CONTAINER = "agentsec_splunk"


def splunk(spl: str) -> tuple[list[dict], str]:
    collapsed = " ".join(line.strip() for line in spl.splitlines() if line.strip())
    inner = (
        "/opt/splunk/bin/splunk search "
        + json.dumps(collapsed)
        + ' -auth "admin:${SPLUNK_PASSWORD}" -output csv -maxout 200'
    )
    proc = subprocess.run(
        ["docker", "exec", "-u", "splunk", CONTAINER, "bash", "-lc", inner],
        capture_output=True,
        text=True,
        check=False,
    )
    noise = ("WARNING", "Warning:", "Pid file", "Cannot initialize", "Failed to create")
    err = "\n".join(
        line for line in (proc.stderr or "").splitlines()
        if line.strip() and not line.startswith(noise)
    )
    if proc.returncode != 0:
        return [], err or f"exit {proc.returncode}"
    return list(csv.DictReader(io.StringIO(proc.stdout))), err


def bind(query: str, run_id: str) -> str:
    """Studio fills live_run_id and leaves the specimen dropdown out of play."""
    return query.replace("$live_run_id$", run_id).replace("$run_id$", "")


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    definition = json.loads(DEFINITION.read_text(encoding="utf-8"))
    failures = 0
    for mode, run_id in zip(("ATTACK", "RETEST"), sys.argv[1:3]):
        print(f"\n{'=' * 72}\n{mode}  run.id={run_id}\n{'=' * 72}")
        for cell in CELLS:
            rows, err = splunk(bind(definition["dataSources"][cell]["options"]["query"], run_id))
            if err:
                print(f"\n-- {cell}: SPL ERROR\n   {err}")
                failures += 1
                continue
            print(f"\n-- {cell}: {len(rows)} row(s)")
            if not rows:
                failures += 1
            for row in rows[:12]:
                print("   ", {k: v for k, v in row.items() if v})
        # LAB-MCP-001 emits no LLM events. If that ever changes, the notebook's
        # "this lab produces no LLM activity" framing becomes a false statement.
        llm, _ = splunk(
            "index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0 "
            f'"agentsec.run.id"="{run_id}" "event.name"=agentsec.llm.* | stats count'
        )
        count = llm[0].get("count") if llm else "?"
        print(f"\n-- agentsec.llm.* events: {count} (expected 0)")
        if count != "0":
            failures += 1
    print(f"\n{'=' * 72}\n{'FAIL' if failures else 'ALL CELLS RETURNED ROWS'}: {failures} problem(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
