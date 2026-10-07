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
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFINITION = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "dashboard.definition.json"
#: P1: the printed SPL moved from the INVESTIGATE cells to the REFERENCE panels
#: (CONTRACT CHANGE: P1 learner-experience redesign). Each REFERENCE panel prints the
#: EVIDENCE RESULT query first and, for questions 1-3, the CHECK query second. The
#: query is taken from the *markdown*, so this script verifies the text on screen and
#: proves it equals the executed data source before running anything.
CELLS = (
    ("viz_ref_state", "ds_nb_state", 0),
    ("viz_ref_nb1", "ds_nb_decision", 0),
    ("viz_ref_nb2", "ds_nb_execution", 0),
    ("viz_ref_nb3", "ds_nb_scope", 0),
    ("viz_ref_nb4", "ds_nb_timeline", 0),
)
#: (printed panel, CHECK data source, answer token). Run with "UNSURE" so the check
#: always has a row to prove it parses; it asserts no expected decision.
CHECK_CELLS = (
    ("viz_ref_nb1", "ds_nb_decision_fb", "nb_a1"),
    ("viz_ref_nb2", "ds_nb_execution_fb", "nb_a2"),
    ("viz_ref_nb3", "ds_nb_scope_fb", "nb_a3"),
)
CONTAINER = "agentsec_splunk"


def displayed_spl(definition: dict, viz_id: str, index: int = 0) -> str:
    markdown = definition["visualizations"][viz_id]["options"]["markdown"]
    blocks = re.findall(r"```text\n(.*?)\n```", markdown, re.S)
    if index >= len(blocks):
        raise SystemExit(f"{viz_id} prints {len(blocks)} query blocks; expected index {index}")
    return blocks[index]


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

    print(f"{'=' * 72}\nVISIBLE SPL == EXECUTED SPL\n{'=' * 72}")
    for viz_id, ds_id, idx in CELLS:
        shown = displayed_spl(definition, viz_id, idx)
        executed = definition["dataSources"][ds_id]["options"]["query"]
        same = shown == executed
        print(f"-- {viz_id:16s} vs {ds_id:16s} {'IDENTICAL' if same else 'DRIFTED'}")
        if not same:
            failures += 1
    for viz_id, ds_id, _token in CHECK_CELLS:
        shown = displayed_spl(definition, viz_id, 1)
        executed = definition["dataSources"][ds_id]["options"]["query"]
        same = shown == executed
        print(f"-- {viz_id:16s} vs {ds_id:20s} {'IDENTICAL' if same else 'DRIFTED'}")
        if not same:
            failures += 1

    for mode, run_id in zip(("ATTACK", "RETEST"), sys.argv[1:3]):
        print(f"\n{'=' * 72}\n{mode}  run.id={run_id}\n{'=' * 72}")
        for viz_id, ds_id, idx in CELLS:
            # Run what the learner can see, not what the dashboard stores.
            rows, err = splunk(bind(displayed_spl(definition, viz_id, idx), run_id))
            if err:
                print(f"\n-- {viz_id} ({ds_id}): SPL ERROR\n   {err}")
                failures += 1
                continue
            print(f"\n-- {viz_id} ({ds_id}): {len(rows)} row(s)")
            if not rows:
                failures += 1
            for row in rows[:12]:
                # Blank columns are the defect this remediation exists to fix,
                # so print every key, not only the populated ones.
                print("   ", dict(row))
                blank = [k for k, v in row.items() if not v]
                if blank:
                    print("    BLANK COLUMNS:", blank)
        # CHECK tables: closed when the answer is "none", one row once an answer is chosen.
        for viz_id, ds_id, token in CHECK_CELLS:
            shown = displayed_spl(definition, viz_id, 1)
            closed, err_c = splunk(bind(shown, run_id).replace(f"${token}$", "none"))
            opened, err_o = splunk(bind(shown, run_id).replace(f"${token}$", "UNSURE"))
            ok = not err_c and not err_o and len(closed) == 0 and len(opened) >= 1
            print(f"\n-- CHECK {ds_id}: closed={len(closed)} row(s), open={len(opened)} row(s) {'OK' if ok else 'PROBLEM'}")
            if not ok:
                failures += 1
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
