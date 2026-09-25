# P0 ExternalEvidence 1.0.0 live Splunk validation

**Date:** 2026-09-24
**Baseline:** `44f8f253c7c46acd3b3c1bb19f31ef3d03c696c5`
**Classification:** MEASURED
**Source used to isolate validation events:** `agentsec-p0-contract-validation-44f8f25`

Three canonical Cisco HEC payloads (NORMAL scan, MALICIOUS scan, MALICIOUS
finding) with the P0 nested contract fields were submitted. HEC returned HTTP
200 for all three.

## External fields

```spl
index=agentsec_telemetry sourcetype=agentsec:scanner:finding source=agentsec-p0-contract-validation-44f8f25 earliest=0
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
```

Measured: three rows, contract `1.0.0`, class `finding`, provider
`cisco-ai-defense`, tool `cisco-ai-mcp-scanner`, version `4.8.4`, raw ref
`raw/scanner-output.json`, and both expected raw SHA-256 values.

## Correlation

```spl
index=agentsec_telemetry sourcetype=agentsec:scanner:finding source=agentsec-p0-contract-validation-44f8f25 earliest=0
| eval method=mvindex(mvdedup('correlation.method'),0),
       correlation_key=mvindex(mvdedup('correlation.key'),0),
       correlation_value=mvindex(mvdedup('correlation.value'),0),
       description_sha256=mvindex(mvdedup('artifact.description_sha256'),0)
| eval value_matches=if(correlation_value=description_sha256,"true","false")
| table scan_id, event.name, method, correlation_key, correlation_value, value_matches
| sort scan_id, event.name
```

Measured: all three rows used `hash_join`,
`description_sha256/content.hash`, and `value_matches=true`.

## Runtime separation / no manufactured run id

```spl
index=agentsec_telemetry source=agentsec-p0-contract-validation-44f8f25 earliest=0
| stats count, dc('agentsec.run.id') as run_id_count,
        dc('agentsec.schema.version') as runtime_schema_count,
        values(sourcetype) as sourcetypes
```

Measured: `count=3`, `run_id_count=0`, `runtime_schema_count=0`, only
`agentsec:scanner:finding`.

```spl
index=agentsec_telemetry sourcetype=otel:agentic:json source=agentsec-p0-contract-validation-44f8f25 earliest=0
| stats count
```

Measured: `count=0`.

Result: nested external evidence, raw/normalized provenance, and correlation
survived actual HEC indexing without entering runtime telemetry.
