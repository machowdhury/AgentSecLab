#!/usr/bin/env python3
"""Measure both external-evidence planes in local Splunk.

Events come only from the committed canonical Cisco and garak packs. The
validation source isolates this checkpoint without manufacturing runtime IDs
or changing either event body.
"""

from __future__ import annotations

import csv
import io
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agentsec.external_evidence.garak_pack import events_from_pack as garak_events  # noqa: E402
from agentsec.scanners.hec_events import events_from_canonical_packs  # noqa: E402
from scripts.ingest_lab_mcp_catalog_scanner_hec import post_hec, splunk_search  # noqa: E402

SOURCE = "agentsec-external-e2e-485f598"
GARAK_PACK = (
    ROOT
    / "docs"
    / "p1a-evidence"
    / "garak-aeb05718-1364-4143-8248-71dd6f27b07b"
)
PLANES_SEARCH = (
    ROOT
    / "learning"
    / "level_1"
    / "LAB-EXTERNAL-EVALUATION-GARAK"
    / "searches"
    / "Q-EXTERNAL-EVIDENCE-PLANES.spl"
)

SPL_COUNTS = f"""
index=agentsec_telemetry source={SOURCE} earliest=0
| stats count, dc(_raw) as distinct_raw_events by sourcetype
| sort sourcetype
"""

SPL_CISCO = f"""
index=agentsec_telemetry source={SOURCE} sourcetype=agentsec:scanner:finding earliest=0
| eval producer=mvindex(mvdedup('external.producer_class'),0),
       evidence_class=mvindex(mvdedup('external.evidence_class'),0),
       provider=mvindex(mvdedup('external.provider'),0),
       tool=mvindex(mvdedup('external.tool'),0),
       tool_version=mvindex(mvdedup('external.tool_version'),0),
       subject_type=mvindex(mvdedup('external.subject_type'),0),
       subject_id=mvindex(mvdedup('external.subject_id'),0),
       raw_ref=mvindex(mvdedup('external.raw_evidence_ref'),0),
       raw_sha256=mvindex(mvdedup('external.raw_evidence_sha256'),0),
       correlation_method=mvindex(mvdedup('correlation.method'),0),
       correlation_value=mvindex(mvdedup('correlation.value'),0),
       native_result=case('event.name'=="agentsec.scanner.finding",
                          mvindex(mvdedup('finding.native_severity'),0),
                          'scan.finding_count'=="0","ZERO FINDINGS",
                          true(),"SCAN COMPLETE")
| dedup scan_id, event.name
| table timestamp, scan_id, event.name, producer, evidence_class, provider, tool,
        tool_version, subject_type, subject_id, native_result, raw_ref, raw_sha256,
        correlation_method, correlation_value
| sort scan_id, event.name
"""

SPL_GARAK = f"""
index=agentsec_telemetry source={SOURCE} sourcetype=agentsec:external:evaluation earliest=0
| eval evidence_id=mvindex(mvdedup('external.evidence_id'),0),
       producer=mvindex(mvdedup('external.producer_class'),0),
       evidence_class=mvindex(mvdedup('external.evidence_class'),0),
       provider=mvindex(mvdedup('external.provider'),0),
       tool=mvindex(mvdedup('external.tool'),0),
       tool_version=mvindex(mvdedup('external.tool_version'),0),
       subject_type=mvindex(mvdedup('external.subject.type'),0),
       subject_id=mvindex(mvdedup('external.subject.id'),0),
       native_result=mvindex(mvdedup('evaluation.native_result'),0),
       raw_ref=mvindex(mvdedup('external.raw_evidence_ref'),0),
       raw_sha256=mvindex(mvdedup('external.raw_evidence_sha256'),0),
       correlation_method=mvindex(mvdedup('correlation.method'),0),
       correlation_value=mvindex(mvdedup('correlation.value'),0)
| dedup evidence_id
| table timestamp, evidence_id, producer, evidence_class, provider, tool,
        tool_version, subject_type, subject_id, native_result, raw_ref, raw_sha256,
        correlation_method, correlation_value
"""

SPL_SEPARATION = f"""
index=agentsec_telemetry source={SOURCE} earliest=0
| stats dc('agentsec.run.id') as manufactured_run_ids,
        dc('agentsec.schema.version') as runtime_schema_versions,
        values(sourcetype) as sourcetypes
"""


def csv_rows(text: str) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(text)))


def canonical_payloads() -> list[dict]:
    payloads = events_from_canonical_packs(ROOT) + garak_events(GARAK_PACK)
    isolated: list[dict] = []
    for original in payloads:
        payload = dict(original)
        payload["source"] = SOURCE
        isolated.append(payload)
    return isolated


def validate_results(results: dict[str, str]) -> None:
    counts = {row["sourcetype"]: row for row in csv_rows(results["counts"])}
    assert int(counts["agentsec:scanner:finding"]["distinct_raw_events"]) == 3
    assert int(counts["agentsec:external:evaluation"]["distinct_raw_events"]) == 1

    cisco = csv_rows(results["cisco"])
    assert len(cisco) == 3
    assert {row["evidence_class"] for row in cisco} == {"finding"}
    assert {row["producer"] for row in cisco} == {"OBSERVED_SCANNER"}
    assert {row["tool_version"] for row in cisco} == {"4.8.4"}
    assert {row["subject_type"] for row in cisco} == {"mcp.catalog.snapshot"}
    assert {row["subject_id"] for row in cisco} == {"NORMAL", "MALICIOUS", "lookup_policy"}
    assert {row["correlation_method"] for row in cisco} == {"hash_join"}
    assert all(row["timestamp"] and row["raw_ref"] and row["raw_sha256"] for row in cisco)

    garak = csv_rows(results["garak"])
    assert len(garak) == 1
    assert garak[0]["evidence_class"] == "evaluation"
    assert garak[0]["producer"] == "OBSERVED_EXTERNAL_EVALUATION"
    assert garak[0]["tool"] == "garak"
    assert garak[0]["tool_version"] == "0.17.0"
    assert garak[0]["native_result"] == "PASS"
    assert garak[0]["correlation_method"] == "identity_tuple"
    assert garak[0]["timestamp"] and garak[0]["raw_ref"] and garak[0]["raw_sha256"]

    separation = csv_rows(results["separation"])
    assert separation == [
        {
            "manufactured_run_ids": "0",
            "runtime_schema_versions": "0",
            "sourcetypes": "agentsec:external:evaluation agentsec:scanner:finding",
        }
    ]

    planes = {row["evidence_plane"] for row in csv_rows(results["planes"])}
    assert {"RUNTIME", "STATIC FINDING", "ADVERSARIAL EVALUATION"} <= planes


def run_validation() -> dict[str, str]:
    payloads = canonical_payloads()
    statuses = [post_hec(payload) for payload in payloads]
    if statuses != [200] * len(payloads):
        raise RuntimeError(f"HEC submission failed: {statuses}")
    results = {
        "counts": splunk_search(SPL_COUNTS),
        "cisco": splunk_search(SPL_CISCO),
        "garak": splunk_search(SPL_GARAK),
        "separation": splunk_search(SPL_SEPARATION),
        "planes": splunk_search(PLANES_SEARCH.read_text(encoding="utf-8")),
    }
    validate_results(results)
    return results


def main() -> None:
    payloads = canonical_payloads()
    print(
        json.dumps(
            {
                "source": SOURCE,
                "local_expected_events": len(payloads),
                "local_expected_by_sourcetype": {
                    "agentsec:scanner:finding": 3,
                    "agentsec:external:evaluation": 1,
                },
            }
        )
    )
    results = run_validation()
    for name, spl in (
        ("counts", SPL_COUNTS),
        ("cisco", SPL_CISCO),
        ("garak", SPL_GARAK),
        ("separation", SPL_SEPARATION),
        ("planes", PLANES_SEARCH.read_text(encoding="utf-8")),
    ):
        print(f"--- {name} SPL ---")
        print(spl.strip())
        print(f"--- {name} RESULT ---")
        print(results[name])
    print(json.dumps({"validated": True}))


if __name__ == "__main__":
    main()
