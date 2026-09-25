# Blue-Team Live Splunk Validation

Date: 2026-09-24
Classification: `MEASURED`
Incident: `AI-2026-001`

Command:

```bash
PYTHONPATH=src:scripts:. python3 scripts/validate_blue_team_incident_splunk.py
```

## Exact SPL

Candidate discovery:

```spl
index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0 "event.name"=agentsec.control.decision "agentsec.control.id"=CTRL-MCP-001
| eval run_id=mvindex(mvdedup('agentsec.run.id'),0)
| eval ts=mvindex(mvdedup('timestamp'),0)
| eval tool=mvindex(mvdedup('gen_ai.tool.name'),0)
| eval requested_scope=mvindex(mvdedup('agentsec.mcp.requested_scope'),0)
| eval allowed_scope=mvindex(mvdedup('agentsec.mcp.allowed_scope'),0)
| where ts>="2026-09-20T19:37:40Z" AND ts<="2026-09-20T19:38:00Z"
| table ts, run_id, tool, requested_scope, allowed_scope
| sort ts
```

Timeline template:

```spl
index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0 "agentsec.run.id"=__RUN_ID__
| eval run_id=mvindex(mvdedup('agentsec.run.id'),0)
| eval sequence=tonumber(mvindex(mvdedup('agentsec.sequence'),0))
| eval ts=mvindex(mvdedup('timestamp'),0)
| eval event_name=mvindex(mvdedup('event.name'),0)
| eval control_id=mvindex(mvdedup('agentsec.control.id'),0)
| eval decision=mvindex(mvdedup('agentsec.control.decision'),0)
| eval reason=mvindex(mvdedup('agentsec.control.reason'),0)
| eval memory_id=mvindex(mvdedup('agentsec.memory.id'),0)
| eval source_run_id=mvindex(mvdedup('agentsec.memory.source_run_id'),0)
| eval tool=mvindex(mvdedup('gen_ai.tool.name'),0)
| eval requested_scope=mvindex(mvdedup('agentsec.mcp.requested_scope'),0)
| eval allowed_scope=mvindex(mvdedup('agentsec.mcp.allowed_scope'),0)
| eval content_hash=mvindex(mvdedup('agentsec.content.hash'),0)
| eval outcome=mvindex(mvdedup('agentsec.outcome'),0)
| table sequence, ts, event_name, run_id, memory_id, source_run_id, control_id, decision, reason, tool, requested_scope, allowed_scope, content_hash, outcome
| sort sequence
```

The exact pair-comparison SPL is `learning/level_1/LAB-BLUE-TEAM-INCIDENT-001/searches/Q-INCIDENT-COMPARE.spl`, bound by the validation script to the two run IDs below. Keeping the canonical file authoritative avoids a second drifting copy.

Count reconciliation:

```spl
index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0 ("agentsec.run.id"="2437f64a-fff4-424f-8a83-0f04285662e4" OR "agentsec.run.id"="8d2c016f-cadc-4463-939a-23a183221b3d")
| eval run_id=mvindex(mvdedup('agentsec.run.id'),0)
| stats count as indexed_count dc(_raw) as distinct_raw by run_id
| sort run_id
```

## Result

- Candidate discovery returned exactly 2 rows in the bounded window.
- ATTACK recall `2437f64a-fff4-424f-8a83-0f04285662e4`: local expected 11; indexed 11; `dc(_raw)=11`; CTRL-MCP-001 `ALLOW`; `mcp.completed`.
- RETEST recall `8d2c016f-cadc-4463-939a-23a183221b3d`: local expected 10; indexed 10; `dc(_raw)=10`; CTRL-MCP-001 `DENY`; no indexed follow-on MCP execution event.

The equality is semantically valid for each complete recall-run event pack. It does not compare the three-run incident as one run.

## Claim boundary

The ATTACK indexed timeline corroborates invocation and completion. The RETEST indexed absence corroborates non-invocation only because the existing validated runtime source records handler count 0 and the complete local/indexed counts reconcile. Splunk did not enforce either result.
