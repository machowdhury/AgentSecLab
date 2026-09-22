# AgentSec Splunk notebook experience (Phase 17B)

Splunk Search is the investigation notebook. Studio is the syllabus. Studio bound tables are Path B for REPLAY specimens, not a fresh LIVE launch.

## Contract

QUESTION → STARTER → learner types SPL → OUTPUT → INTERPRETATION → SECURITY CONCLUSION.

Path A is preferred. Path B is an optional answer key. Studio 10.2 cannot hide Path B; the UI discloses that.

## Starter every LIVE hunt needs

- index `agentsec_telemetry`
- sourcetype `otel:agentic:json`
- quoted `agentsec.run.id` from Attack Service (not the Studio dropdown unless you intend REPLAY)
- the field family for that lab (control.*, mcp.*, llm.*, rag.*, memory.*, goal.*, identity.*)

Hint 1 gives direction. Hint 2 gives stronger scaffolding. Neither dumps the full solution first.

## After a table

YOU SHOULD SEE the control id, decision, reason, and whether execution events exist.

THAT MEANS the named control decided. Splunk copied telemetry.

IT DOES NOT MEAN Splunk blocked the action, OBSERVE authorized it, ALLOW proved execution, or empty proved prevention.

NEXT hunt execution if you only have a decision row, or COMPARE if you already have ATTACK and RETEST.

## Empty output

LIVE: wait until Attack Service says **EVIDENCE READY**. HEC accepted is not searchable. Empty is not DENY.

REPLAY: this volume may not contain that specimen. Empty is not DENY.

## Path B

Security question, solution SPL, expected output shape, field interpretation, what it means, what it does not mean, security connection, next question.
