#!/usr/bin/env python3
"""Live Splunk validation for AcmeBank Incident AI-2026-001.

Credentials are read by the existing Splunk helper from environment/.env and
are never printed or written to repository evidence.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from ingest_lab_mcp_catalog_scanner_hec import splunk_search

ROOT = Path(__file__).resolve().parents[1]
SEARCHES = ROOT / "learning" / "level_1" / "LAB-BLUE-TEAM-INCIDENT-001" / "searches"
ATTACK = "2437f64a-fff4-424f-8a83-0f04285662e4"
RETEST = "8d2c016f-cadc-4463-939a-23a183221b3d"


def rows(result: str) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(result.strip())))


def load(name: str) -> str:
    return (SEARCHES / name).read_text(encoding="utf-8").strip()


def main() -> None:
    candidate_rows = rows(splunk_search(load("Q-INCIDENT-CANDIDATES.spl")))
    if [row["run_id"] for row in candidate_rows] != [ATTACK, RETEST]:
        raise AssertionError(f"unexpected candidates: {candidate_rows}")

    timeline = load("Q-INCIDENT-TIMELINE.spl")
    attack_rows = rows(splunk_search(timeline.replace("__RUN_ID__", f'"{ATTACK}"')))
    retest_rows = rows(splunk_search(timeline.replace("__RUN_ID__", f'"{RETEST}"')))
    if len(attack_rows) != 11 or len(retest_rows) != 10:
        raise AssertionError(
            f"timeline count mismatch attack={len(attack_rows)} retest={len(retest_rows)}"
        )
    if not any(row["event_name"] == "agentsec.mcp.completed" for row in attack_rows):
        raise AssertionError("ATTACK timeline lacks mcp.completed")
    if any(row["event_name"].startswith("agentsec.mcp.") for row in retest_rows):
        raise AssertionError("RETEST timeline unexpectedly contains mcp execution")

    compare = (
        load("Q-INCIDENT-COMPARE.spl")
        .replace("__ATTACK_RUN_ID__", f'"{ATTACK}"')
        .replace("__RETEST_RUN_ID__", f'"{RETEST}"')
    )
    comparison = {row["run_id"]: row for row in rows(splunk_search(compare))}
    if comparison[ATTACK]["execution_state"] != "mcp.completed":
        raise AssertionError(comparison[ATTACK])
    if comparison[RETEST]["execution_state"] != "no_indexed_followon_execution_event":
        raise AssertionError(comparison[RETEST])
    if "ALLOW" not in comparison[ATTACK]["decisions"]:
        raise AssertionError(comparison[ATTACK])
    if "DENY" not in comparison[RETEST]["decisions"]:
        raise AssertionError(comparison[RETEST])

    count_spl = f"""index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0 ("agentsec.run.id"="{ATTACK}" OR "agentsec.run.id"="{RETEST}")
| eval run_id=mvindex(mvdedup('agentsec.run.id'),0)
| stats count as indexed_count dc(_raw) as distinct_raw by run_id
| sort run_id"""
    counts = {row["run_id"]: row for row in rows(splunk_search(count_spl))}
    if counts[ATTACK] != {"run_id": ATTACK, "indexed_count": "11", "distinct_raw": "11"}:
        raise AssertionError(counts[ATTACK])
    if counts[RETEST] != {"run_id": RETEST, "indexed_count": "10", "distinct_raw": "10"}:
        raise AssertionError(counts[RETEST])

    summary = {
        "evidence_class": "MEASURED",
        "incident_id": "AI-2026-001",
        "candidate_count": len(candidate_rows),
        "attack": {
            "run_id": ATTACK,
            "indexed_count": 11,
            "distinct_raw": 11,
            "decision": "ALLOW",
            "execution_state": "mcp.completed",
        },
        "retest": {
            "run_id": RETEST,
            "indexed_count": 10,
            "distinct_raw": 10,
            "decision": "DENY",
            "execution_state": "no_indexed_followon_execution_event",
        },
        "claim_limit": "Indexed absence is corroborative only; runtime handler count is authoritative.",
    }
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
