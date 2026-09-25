# Blue-Team Investigation & Threat Hunting

Status: implemented learning experience; validation classes are recorded separately.

## Purpose

This phase changes the learner role from following a known ATTACK/RETEST answer to investigating incomplete evidence. It adds no attack, detector, PDP, runtime field, or external tool.

Canonical method:

```text
OBSERVATION → INITIAL HYPOTHESIS → EVIDENCE REQUIRED → SEARCH → TIMELINE
→ CORRELATION → CONTROL ANALYSIS → SUPPORT / REFUTE → REVISED HYPOTHESIS
→ CONCLUSION → EVIDENCE GAPS → RECOMMENDATION
```

## Canonical incident

`LAB-BLUE-TEAM-INCIDENT-001` reuses the validated Capstone RAG → memory → MCP packet as AcmeBank Incident `AI-2026-001`. The learner is not initially told the attack family, control result, or execution result.

Repository evidence:

- Learning contract: `learning/level_1/LAB-BLUE-TEAM-INCIDENT-001/investigations.json`
- Workbench builder: `scripts/build_lab_blue_team_incident_dashboard.py`
- Search artifacts: `learning/level_1/LAB-BLUE-TEAM-INCIDENT-001/searches/`
- Source validation: `docs/PHASE16B_CAPSTONE_LIVE_VALIDATION.md`
- Splunk reconciliation: `docs/PHASE16B_CAPSTONE_SPLUNK_VALIDATION.md`

## Three levels, one dataset

- Guided Analyst receives the window and suggested search.
- Investigator receives the incident and approximate window.
- Threat Hunter starts from a hypothesis without a run ID.

Hints progress from direction to source to field strategy to example SPL. Path B is a separate answer tab. The gate is pedagogical because Dashboard Studio has no durable learner-state enforcement in this repository.

## Splunk skill progression

- SEARCH: bounded index, sourcetype, time, and field discovery.
- STATS: summarize candidate behavior without calling it malicious.
- TIME: order by runtime sequence and preserve distinct run IDs.
- CORRELATION: use run ID, source run ID, and hashes only for their defined relationships.
- MULTIVALUE: normalize JSON extractions before comparison.
- EVENT SEQUENCING: reconstruct without blindly using `transaction`.
- BASELINING: compare expected `lookup_policy` execution.
- ANOMALY REASONING: `MATCH != MALICIOUS`.
- DETECTION LOGIC: produce a candidate only after ATTACK/RETEST/BASELINE analysis.
- THREAT HUNTING: begin from a falsifiable hypothesis, not an alert.

## Evidence reasoning

CTRL-MCP-001 is the tool PDP. Splunk is downstream. RAG and memory evidence may establish influence and persistence; they do not grant authority. An ALLOW event does not establish invocation. `mcp.started` does not establish completion. Missing indexed execution is not independent prevention proof.

The packet does not model authentication, direct retrieve-output-to-write causality, human approval, or universal resistance. External Cisco and garak evidence remains adjacent and has no defensible causal join to this incident.

## Reporting and threat modeling

The learner submits an evidence ledger and an analyst report with technical and executive versions. Root cause is used only when evidence establishes it; otherwise the report uses `LIKELY CONTRIBUTING FACTOR`.

The bounded threat-model bridge asks for asset, actor, entry point, trust boundary, authority, control, observability, missing evidence, and residual risk. It is not a Threat Modeling Studio.

## Security semantics

- Runtime schema: `1.9.0` unchanged.
- ExternalEvidence Contract: `1.0.0` unchanged.
- CTRL-MCP-001 remains the tool PDP.
- No external-evidence input was added to authorization.
- No saved search or detector was added.
- Capstone remains the final LIVE launcher.
