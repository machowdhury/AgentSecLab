# AcmeBank Incident AI-2026-001

REPLAY blue-team investigation. This lab reuses validated AgentSec evidence; it does not add an attack, detector, control, or runtime event.

## Mission

SOC received a report that an AI-assisted banking workflow may have requested or performed an action outside its intended authority. Determine what happened without assuming the cause from a lab title.

Use the canonical method:

```text
OBSERVATION → INITIAL HYPOTHESIS → EVIDENCE REQUIRED → SEARCH → TIMELINE
→ CORRELATION → CONTROL ANALYSIS → SUPPORT / REFUTE → REVISED HYPOTHESIS
→ CONCLUSION → EVIDENCE GAPS → RECOMMENDATION
```

The shared REPLAY packet supports Guided Analyst, Investigator, and Threat Hunter levels. Start with `workshop.md`. Record conclusions in `incident-report-template.md`.

## Evidence rules

- OBSERVATION != AUTHORIZATION
- AUTHORIZATION != EXECUTION
- EXECUTION STARTED != COMPLETION
- CORRELATION != CAUSATION
- NO EVIDENCE != SAFE
- Splunk is downstream evidence, not the PDP.
- CTRL-MCP-001 remains the tool PDP.

Runtime schema is `1.9.0`. External Evidence Contract is `1.0.0`. Neither changes in this lab.
