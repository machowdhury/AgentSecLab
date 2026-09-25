# Splunk Knowledge Object Review — Blue-Team Incident

SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT: `ws_lab_blue_team_incident`, `Q-INCIDENT-CANDIDATES`, `Q-INCIDENT-TIMELINE`, `Q-INCIDENT-COMPARE`
TYPE: DASHBOARD / HUNT SPL
PURPOSE: Teach hypothesis-led investigation, timeline reconstruction, comparison, and reporting from one validated REPLAY packet.

## Field contract

PASS. Runtime source is constrained to `index=agentsec_telemetry sourcetype=otel:agentic:json`. Fields used are extracted schema 1.9.0 fields already present in the validated Capstone packet: run ID, sequence, timestamp, event name, memory ID/source run, control ID/decision/reason, tool, requested/allowed scope, content hash, profile, mode, and outcome.

## Correlation contract

PASS WITH LIMITS.

- run ID groups one runtime experiment;
- sequence orders events within a run;
- source run ID links memory write to later recall;
- content-hash equality covers the defined canonical bytes;
- no field establishes direct retrieve-output-to-write causality;
- no external evidence is causally joined.

## SPL correctness

PASS — LIVE SPLUNK MEASURED. `scripts/validate_blue_team_incident_splunk.py` executed all three canonical queries. Candidate count 2; ATTACK 11/11 distinct raw; RETEST 10/10 distinct raw. Exact SPL and result are in `docs/BLUE_TEAM_LIVE_SPLUNK_VALIDATION.md`.

No `transaction`, `index=*`, macro, lookup, join, subsearch, detector, alert, or saved search was added.

## No-data semantics

PASS. Tables say `NO EVIDENCE FOUND`, identify dependency/index/pack possibilities, and explicitly reject SAFE, DENY, prevention, and causal conclusions from empty results.

## Performance

PASS for the bounded local learning dataset. Candidate search is index/sourcetype/control/time bounded. Timeline is index/sourcetype/run bound. Production-scale performance is `NOT MEASURED`.

## Duplication and governance

Three new hunts are justified by a new learner task: discover candidates without a run ID, reconstruct a selected unknown run, and compare the bounded incident pair. Existing Q-RAG/Q-MEMORY/Q-MCP hunts remain referenced learning pivots and are not duplicated.

CIM mapping: `NEEDS_EXTERNAL_VALIDATION`; not required for this local app contract.

## Detection readiness

HUNT / LEARNING ONLY. The workbench teaches candidate-detection methodology but creates no detector. `DET-MCP-001` remains unchanged.

## Verdict

PUBLISH for the bounded Academy REPLAY use. Do not represent these searches as production detections or universal incident logic.
