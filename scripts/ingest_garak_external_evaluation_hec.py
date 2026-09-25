#!/usr/bin/env python3
"""Ingest the canonical P1A garak evaluation pack into local Splunk HEC.

The HEC token is read from .env by the existing helper and is never printed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agentsec.external_evidence.garak_pack import (  # noqa: E402
    GARAK_SOURCE,
    events_from_pack,
)
from scripts.ingest_lab_mcp_catalog_scanner_hec import post_hec, splunk_search  # noqa: E402

PACK = (
    ROOT
    / "docs"
    / "p1a-evidence"
    / "garak-aeb05718-1364-4143-8248-71dd6f27b07b"
)

SPL_EVALUATION = f"""
index=agentsec_telemetry sourcetype=agentsec:external:evaluation source={GARAK_SOURCE} earliest=0
| eval evidence_class=mvindex(mvdedup('external.evidence_class'),0),
       tool=mvindex(mvdedup('external.tool'),0),
       version=mvindex(mvdedup('external.tool_version'),0),
       model=mvindex(mvdedup('external.subject.id'),0),
       native_result=mvindex(mvdedup('evaluation.native_result'),0),
       probe=mvindex(mvdedup('evaluation.probe'),0),
       detector=mvindex(mvdedup('evaluation.detector'),0),
       raw_ref=mvindex(mvdedup('external.raw_evidence_ref'),0),
       raw_sha256=mvindex(mvdedup('external.raw_evidence_sha256'),0)
| table evidence_class, tool, version, model, native_result, probe, detector,
        raw_ref, raw_sha256
"""

SPL_CORRELATION = f"""
index=agentsec_telemetry sourcetype=agentsec:external:evaluation source={GARAK_SOURCE} earliest=0
| eval method=mvindex(mvdedup('correlation.method'),0),
       correlation_key=mvindex(mvdedup('correlation.key'),0),
       correlation_value=mvindex(mvdedup('correlation.value'),0)
| table method, correlation_key, correlation_value
"""

SPL_SEPARATION = f"""
index=agentsec_telemetry source={GARAK_SOURCE} earliest=0
| stats count, dc('agentsec.run.id') as agentsec_run_ids,
        dc('agentsec.schema.version') as runtime_schema_versions,
        values(sourcetype) as sourcetypes
"""


def main() -> None:
    payloads = events_from_pack(PACK)
    statuses = [post_hec(payload) for payload in payloads]
    print(json.dumps({"submitted": len(payloads), "statuses": statuses}))
    if statuses != [200] * len(payloads):
        raise SystemExit(1)
    for name, spl in (
        ("evaluation", SPL_EVALUATION),
        ("correlation", SPL_CORRELATION),
        ("separation", SPL_SEPARATION),
    ):
        print(f"--- {name} SPL ---")
        print(spl.strip())
        print(f"--- {name} RESULT ---")
        print(splunk_search(spl))


if __name__ == "__main__":
    main()
