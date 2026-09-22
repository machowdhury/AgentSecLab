# AgentSec Splunk investigation assessment

**Status:** IMPLEMENTED (Phase 17A). Search remains the notebook. Studio remains the syllabus. No new Q-* hunts. No MLTK.

S1–S8 are mapped onto Mastery Check challenges. They are not eight extra labs.

| Level | Skill | Where it is assessed |
|-------|-------|----------------------|
| S1 FIND | All events for a quoted `run.id` | Find this run |
| S2 ORDER | `sequence` + `event.name` | Find this run (hint) |
| S3 CONTROL | `control.id` / `decision` / `reason` | Decision versus execution |
| S4 AUTHORITY | requested tool, scope, which control is the PDP | MCP ALLOW is not the goal |
| S5 EXECUTION | attempted / executed / `mcp.started` / handler evidence | Decision versus execution; empty mcp.started |
| S6 CORRELATE | hashes / `source_run_id` where the lab defines them | Capstone gate; instructor may also use RAG/memory labs |
| S7 COMPARE | ATTACK vs RETEST | Same request, different defense; capstone |
| S8 PROVE | SUPPORTED / CORROBORATED / NOT PROVEN / INCORRECT | Rewrite claims; identity OBSERVE; cross-domain |

Starter when required: `index=agentsec_telemetry sourcetype=otel:agentic:json` and a quoted `agentsec.run.id`. Do not search `index=*`. Do not give final SPL on Path A.

Path B copies an existing hunt with the specimen already quoted. It is an answer key, not policy.

Incorrect Splunk conclusions to reject:

- Index presence = completeness
- `_time` as authority instead of `sequence`
- Splunk ALLOWED or DENIED
- Missing `mcp.started` independently proves prevention
- Empty dashboard = SAFE
- HEC HTTP 200 = searchable evidence
- pytest = live Splunk behavior
