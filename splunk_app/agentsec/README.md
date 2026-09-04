# Query definitions for AgentSec Phase 2.
# These have NOT been executed against a live Splunk instance in this repository.
# Use local Python reconstruction (agentsec.detections) until a lab run validates them.

## Q-RUN
Question: Did this run.id produce events?
Fields: agentsec.run.id
SPL (unvalidated):
  `agentsec_index` "agentsec.run.id"=<uuid>

## Q-DENY
Question: Which LIVE events have DENY and operation.executed=false?
Fields: agentsec.control.decision, agentsec.operation.executed, agentsec.testbed.mode
SPL (unvalidated):
  `agentsec_index` "agentsec.control.decision"=DENY "agentsec.operation.executed"=false "agentsec.testbed.mode"=LIVE
