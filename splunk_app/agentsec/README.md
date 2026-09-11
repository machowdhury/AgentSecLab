# Query definitions for AgentSec Phase 2.
# These have NOT been executed against a live Splunk instance in this repository.
# Use local Python reconstruction (agentsec.detections) until a lab run validates them.
# Field semantics: SECURITY_EVENT_MODEL.md (Phase 1B). testbed.mode is BASELINE|ATTACK|RETEST.
# Splunk is corroborating only. Absence of llm.* is not DENY proof by itself.

## Q-RUN
Question: Did this run.id produce events?
Fields: agentsec.run.id, agentsec.incident.id, agentsec.schema.version
SPL (unvalidated):
  `agentsec_index` "agentsec.run.id"=<uuid>

## Q-DENY
Question: Was inference prevented before invocation for this run?
Fields: agentsec.control.decision, agentsec.operation.attempted, agentsec.operation.executed, agentsec.operation.outcome, agentsec.testbed.mode
Note: Filter ATTACK or RETEST. Do not use testbed.mode=LIVE. Runtime + complete local evidence are authoritative.
SPL (unvalidated):
  `agentsec_index` "agentsec.control.decision"=DENY "agentsec.operation.executed"=false "agentsec.operation.outcome"=prevented "agentsec.testbed.mode"=ATTACK
