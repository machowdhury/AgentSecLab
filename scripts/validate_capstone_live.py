#!/usr/bin/env python3
"""Validate fresh Capstone ATTACK/RETEST packets in local Splunk.

Reads run IDs from the compact screenshot report, retrieves the corresponding
Attack Service records, and compares each sibling's local event count with
Splunk dc(_raw). Credentials remain inside the Splunk container environment.
"""

from __future__ import annotations

import csv
import io
import json
import subprocess
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CAPTURE = (
    ROOT
    / "docs"
    / "screenshots"
    / "lab-agentsec-capstone"
    / "capstone-integration_validation.json"
)
OUTPUT = (
    ROOT
    / "docs"
    / "screenshots"
    / "lab-agentsec-capstone"
    / "capstone-integration_splunk_validation.json"
)
MCP = ROOT / "learning" / "level_1" / "LAB-MCP-001" / "searches"
RAG = ROOT / "learning" / "level_1" / "LAB-RAG-CONTEXT" / "searches"
MEMORY = ROOT / "learning" / "level_1" / "LAB-MEMORY-001" / "searches"
GOAL = ROOT / "learning" / "level_1" / "LAB-AGENT-GOAL-INTEGRITY-001" / "searches"
IDENTITY = ROOT / "learning" / "level_1" / "LAB-AGENT-DELEGATION-001" / "searches"
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


def launch_record(recall_run_id: str) -> dict:
    with urllib.request.urlopen(
        f"http://127.0.0.1:5001/api/launches/{recall_run_id}", timeout=10
    ) as response:
        return json.load(response)


def main() -> int:
    capture = json.loads(CAPTURE.read_text(encoding="utf-8"))["attack_service"]
    records = {
        "attack": launch_record(capture["attack_recall_run_id"]),
        "retest": launch_record(capture["retest_recall_run_id"]),
    }
    run_counts: dict[str, tuple[str, int]] = {}
    for mode, record in records.items():
        for stage in ("retrieve", "write", "recall"):
            run_counts[f"{mode}_{stage}"] = (
                record[f"{stage}_run_id"],
                int(record[f"local_event_count_{stage}"]),
            )

    indexed: dict[str, int] = {}
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        indexed = {
            name: completeness(run_id) for name, (run_id, _local) in run_counts.items()
        }
        if all(indexed[name] == local for name, (_run_id, local) in run_counts.items()):
            break
        time.sleep(5)

    q_rag = RAG / "Q-RAG-CONTEXT-AUTHORITY.spl"
    q_memory = MEMORY / "Q-MEMORY-CONTEXT-AUTHORITY.spl"
    q_authz = MCP / "Q-MCP-AUTHZ.spl"
    q_executed = MCP / "Q-MCP-EXECUTED.spl"
    q_goal = GOAL / "Q-GOAL-INTEGRITY-AUTHORITY.spl"
    q_identity = IDENTITY / "Q-AGENT-DELEGATION-AUTHORITY.spl"

    reconstruction: dict[str, dict] = {}
    for mode, record in records.items():
        ids = [
            record["retrieve_run_id"],
            record["write_run_id"],
            record["recall_run_id"],
        ]
        reconstruction[mode] = {
            "rag": query(q_rag, __RUN_ID__=record["retrieve_run_id"]),
            "memory": query(
                q_memory,
                __WRITE_RUN_ID__=record["write_run_id"],
                __RECALL_RUN_ID__=record["recall_run_id"],
            ),
            "authorization": query(q_authz, __RUN_ID__=record["recall_run_id"]),
            "execution": query(q_executed, __RUN_ID__=record["recall_run_id"]),
            "goal_rows_by_run": {
                run_id: query(q_goal, __RUN_ID__=run_id) for run_id in ids
            },
            "identity_rows_by_run": {
                run_id: query(q_identity, __RUN_ID__=run_id) for run_id in ids
            },
        }

    failures: list[str] = []
    comparisons = {}
    for name, (run_id, local) in run_counts.items():
        count = indexed.get(name, 0)
        comparisons[name] = {
            "run_id": run_id,
            "local_event_count": local,
            "splunk_dc_raw": count,
            "complete": local == count,
        }
        if local != count:
            failures.append(f"{name}: local {local} != Splunk dc(_raw) {count}")

    attack_runtime = records["attack"]["runtime"]
    retest_runtime = records["retest"]["runtime"]
    expected = [
        (
            records["attack"]["input_fingerprint"]
            == records["retest"]["input_fingerprint"],
            "ATTACK/RETEST input fingerprints differ",
        ),
        (attack_runtime["follow_on_decision"] == "ALLOW", "ATTACK is not ALLOW"),
        (retest_runtime["follow_on_decision"] == "DENY", "RETEST is not DENY"),
        (
            attack_runtime["lookup_customer_tier_handler_count"] == 1,
            "ATTACK handler count is not 1",
        ),
        (
            retest_runtime["lookup_customer_tier_handler_count"] == 0,
            "RETEST handler count is not 0",
        ),
    ]
    failures.extend(message for passed, message in expected if not passed)

    for mode, result in reconstruction.items():
        for family in ("rag", "memory", "authorization", "execution"):
            if not result[family]:
                failures.append(f"{mode}: {family} reconstruction returned zero rows")
        if any(result["goal_rows_by_run"].values()):
            failures.append(f"{mode}: unexpected Goal Integrity rows")
        if any(result["identity_rows_by_run"].values()):
            failures.append(f"{mode}: unexpected Identity/Delegation rows")

    output = {
        "evidence_classification": "MEASURED — fresh LIVE packets queried in local Splunk",
        "records": records,
        "completeness": comparisons,
        "reconstruction": reconstruction,
        "identity_assurance": {
            "claimed": "No identity/delegation claim packet is active in this experiment.",
            "established_in_lab": (
                "Closed fixture IDs, server-owned ExperimentContext, coded policy, "
                "control outputs, run correlation, and runtime handler counts."
            ),
            "not_modeled": (
                "Cryptographic authentication, OAuth/OIDC, signed delegation, "
                "mTLS/PKI, workload identity, and production IAM."
            ),
        },
        "failures": failures,
    }
    OUTPUT.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(OUTPUT.relative_to(ROOT)), "failures": failures}, indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
