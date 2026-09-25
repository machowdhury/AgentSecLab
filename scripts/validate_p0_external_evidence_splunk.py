#!/usr/bin/env python3
"""Ingest P0 contract events and measure the nested fields in local Splunk.

Credentials are read by the existing scanner HEC helper and are never printed.
This intentionally uses a validation-specific source so reruns can be isolated.
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

from agentsec.scanners.hec_events import events_from_canonical_packs  # noqa: E402
from scripts.ingest_lab_mcp_catalog_scanner_hec import post_hec, splunk_search  # noqa: E402

SOURCE = "agentsec-p0-contract-validation-44f8f25"

SPL_EXTERNAL_FIELDS = f"""
index=agentsec_telemetry sourcetype=agentsec:scanner:finding source={SOURCE} earliest=0
| eval contract_version=mvindex(mvdedup('external.contract.version'),0),
       external_class=mvindex(mvdedup('external.evidence_class'),0),
       provider=mvindex(mvdedup('external.provider'),0),
       tool=mvindex(mvdedup('external.tool'),0),
       tool_version=mvindex(mvdedup('external.tool_version'),0),
       raw_ref=mvindex(mvdedup('external.raw_evidence_ref'),0),
       raw_sha256=mvindex(mvdedup('external.raw_evidence_sha256'),0)
| table scan_id, event.name, contract_version, external_class, provider, tool,
        tool_version, raw_ref, raw_sha256
| sort scan_id, event.name
"""

SPL_CORRELATION = f"""
index=agentsec_telemetry sourcetype=agentsec:scanner:finding source={SOURCE} earliest=0
| eval method=mvindex(mvdedup('correlation.method'),0),
       correlation_key=mvindex(mvdedup('correlation.key'),0),
       correlation_value=mvindex(mvdedup('correlation.value'),0),
       description_sha256=mvindex(mvdedup('artifact.description_sha256'),0)
| eval value_matches=if(correlation_value=description_sha256,"true","false")
| table scan_id, event.name, method, correlation_key, correlation_value, value_matches
| sort scan_id, event.name
"""

SPL_SEPARATION = f"""
index=agentsec_telemetry source={SOURCE} earliest=0
| stats count, dc('agentsec.run.id') as run_id_count,
        dc('agentsec.schema.version') as runtime_schema_count,
        values(sourcetype) as sourcetypes,
        values('external.evidence_class') as external_classes
"""

SPL_RUNTIME_COPY = f"""
index=agentsec_telemetry sourcetype=otel:agentic:json source={SOURCE} earliest=0
| stats count
"""


def main() -> None:
    payloads = events_from_canonical_packs(ROOT)
    statuses: list[int] = []
    for original in payloads:
        payload = dict(original)
        payload["source"] = SOURCE
        statuses.append(post_hec(payload))
    print(json.dumps({"source": SOURCE, "submitted": len(payloads), "statuses": statuses}))
    if statuses != [200] * len(payloads):
        raise SystemExit(1)

    for name, spl in (
        ("external_fields", SPL_EXTERNAL_FIELDS),
        ("correlation", SPL_CORRELATION),
        ("separation", SPL_SEPARATION),
        ("runtime_copy", SPL_RUNTIME_COPY),
    ):
        print(f"--- {name} SPL ---")
        print(spl.strip())
        print(f"--- {name} RESULT ---")
        print(splunk_search(spl))


if __name__ == "__main__":
    main()
