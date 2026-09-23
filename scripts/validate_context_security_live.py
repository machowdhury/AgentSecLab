#!/usr/bin/env python3
"""Validate fresh Context Security runs in local Splunk.

Authentication stays inside the Splunk container environment. Output contains
only investigation rows and count comparisons, never credentials.
"""

from __future__ import annotations

import csv
import io
import json
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CAPTURE = ROOT / "docs" / "screenshots" / "context-security-workbenches" / "final_validation.json"
OUTPUT = ROOT / "docs" / "screenshots" / "context-security-workbenches" / "final_splunk_validation.json"
MCP_SEARCH = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches"
RAG_SEARCH = ROOT / "learning" / "level_1" / "LAB-RAG-CONTEXT" / "searches"
MEMORY_SEARCH = ROOT / "learning" / "level_1" / "LAB-MEMORY-001" / "searches"
DOCKER = Path("/Applications/Docker.app/Contents/Resources/bin/docker")


def splunk(spl: str) -> list[dict]:
    collapsed = " ".join(line.strip() for line in spl.splitlines() if line.strip())
    inner = (
        "/opt/splunk/bin/splunk search "
        + json.dumps(collapsed)
        + ' -auth "admin:${SPLUNK_PASSWORD}" -output csv'
    )
    executable = str(DOCKER) if DOCKER.is_file() else "docker"
    process = subprocess.run(
        [executable, "exec", "-u", "splunk", "agentsec_splunk", "bash", "-lc", inner],
        capture_output=True,
        text=True,
        check=False,
    )
    if process.returncode != 0:
        raise RuntimeError((process.stderr or "Splunk CLI search failed")[-1000:])
    lines = [
        line
        for line in process.stdout.splitlines()
        if line and not line.startswith("WARNING:")
    ]
    return list(csv.DictReader(io.StringIO("\n".join(lines)))) if lines else []


def query(path: Path, **bindings: str) -> list[dict]:
    value = path.read_text(encoding="utf-8")
    for token, run_id in bindings.items():
        value = value.replace(token, json.dumps(run_id))
    return splunk(value)


def completeness(run_id: str) -> int:
    rows = splunk(
        "index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0 "
        f'"agentsec.run.id"="{run_id}" | stats dc(_raw) as count'
    )
    return int(rows[0]["count"]) if rows else 0


def main() -> int:
    capture = json.loads(CAPTURE.read_text(encoding="utf-8"))
    rag_attack = capture["labs"]["rag"]["attack"]
    rag_retest = capture["labs"]["rag"]["retest"]
    memory_attack = capture["labs"]["memory"]["attack"]
    memory_retest = capture["labs"]["memory"]["retest"]

    runs = {
        "rag_attack": (rag_attack["run_id"], rag_attack["local_event_count"]),
        "rag_retest": (rag_retest["run_id"], rag_retest["local_event_count"]),
        "memory_attack_write": (
            memory_attack["write_run_id"],
            memory_attack["local_event_count_write"],
        ),
        "memory_attack_recall": (
            memory_attack["recall_run_id"],
            memory_attack["local_event_count_recall"],
        ),
        "memory_retest_write": (
            memory_retest["write_run_id"],
            memory_retest["local_event_count_write"],
        ),
        "memory_retest_recall": (
            memory_retest["recall_run_id"],
            memory_retest["local_event_count_recall"],
        ),
    }

    indexed: dict[str, int] = {}
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        indexed = {name: completeness(run_id) for name, (run_id, _) in runs.items()}
        if all(indexed[name] == local for name, (_, local) in runs.items()):
            break
        time.sleep(5)

    q_rag = RAG_SEARCH / "Q-RAG-CONTEXT-AUTHORITY.spl"
    q_memory = MEMORY_SEARCH / "Q-MEMORY-CONTEXT-AUTHORITY.spl"
    q_authz = MCP_SEARCH / "Q-MCP-AUTHZ.spl"
    q_executed = MCP_SEARCH / "Q-MCP-EXECUTED.spl"
    investigations = {
        "rag_attack": {
            "context": query(q_rag, __RUN_ID__=rag_attack["run_id"]),
            "authz": query(q_authz, __RUN_ID__=rag_attack["run_id"]),
            "execution": query(q_executed, __RUN_ID__=rag_attack["run_id"]),
        },
        "rag_retest": {
            "context": query(q_rag, __RUN_ID__=rag_retest["run_id"]),
            "authz": query(q_authz, __RUN_ID__=rag_retest["run_id"]),
            "execution": query(q_executed, __RUN_ID__=rag_retest["run_id"]),
        },
        "memory_attack": {
            "context": query(
                q_memory,
                __WRITE_RUN_ID__=memory_attack["write_run_id"],
                __RECALL_RUN_ID__=memory_attack["recall_run_id"],
            ),
            "authz": query(q_authz, __RUN_ID__=memory_attack["recall_run_id"]),
            "execution": query(q_executed, __RUN_ID__=memory_attack["recall_run_id"]),
        },
        "memory_retest": {
            "context": query(
                q_memory,
                __WRITE_RUN_ID__=memory_retest["write_run_id"],
                __RECALL_RUN_ID__=memory_retest["recall_run_id"],
            ),
            "authz": query(q_authz, __RUN_ID__=memory_retest["recall_run_id"]),
            "execution": query(q_executed, __RUN_ID__=memory_retest["recall_run_id"]),
        },
    }

    failures: list[str] = []
    comparisons = {}
    for name, (run_id, local) in runs.items():
        splunk_count = indexed.get(name, 0)
        comparisons[name] = {
            "run_id": run_id,
            "local_primary_or_sibling_count": local,
            "splunk_dc_raw": splunk_count,
            "complete": local == splunk_count,
        }
        if local != splunk_count:
            failures.append(f"{name}: local {local} != Splunk dc(_raw) {splunk_count}")
    for name, result in investigations.items():
        if not result["context"] or not result["authz"] or not result["execution"]:
            failures.append(f"{name}: one or more validated investigations returned no rows")

    output = {
        "evidence_classification": "MEASURED — fresh LIVE run IDs queried in local Splunk",
        "completeness": comparisons,
        "investigations": investigations,
        "failures": failures,
    }
    OUTPUT.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(OUTPUT.relative_to(ROOT)), "failures": failures}, indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
