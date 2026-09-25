# Adversarial model evaluation

## WHAT IS IT?

Deliberately exercise a model with adversarial inputs, then evaluate responses
using defined detectors. It is one form of negative security testing.

## WHY DOES IT EXIST?

Normal examples rarely expose instruction-following weaknesses. Adversarial
evaluation gives reproducible evidence about selected behaviors and helps
practitioners challenge assumptions.

## HOW DOES IT WORK?

garak supplies a generator interface, probe, detector, and native report.
AgentSec preserves that report, normalizes its eval row, and sends a bounded
summary to Splunk.

## WHERE DOES IT SIT IN AGENTSEC?

Outside the runtime:

```text
garak → model → native evaluation → ExternalEvidence → Splunk
```

CTRL-MCP-001 remains the runtime tool PDP.

## WHAT IS THE TRUST BOUNDARY?

The probe controls model input. Model output is untrusted evidence. It cannot
grant AgentSec tool authority.

## WHAT COULD AN ATTACKER CONTROL?

Prompts, encoded payloads, social-engineering language, and potentially model
context. They do not control the coded AgentSec grant list merely by changing
text.

## WHAT CAN GO WRONG?

False confidence from one PASS; treating a detector hit as exploitation;
confusing a model response with a tool call; losing raw provenance; or forcing
unrelated evidence into a false runtime join.

## WHAT TELEMETRY SHOULD EXIST?

Tool/version, model, probe, detector, native counts, native evaluation id,
timestamps, configuration, raw report hash, and explicit limitations.

## HOW WILL SPLUNK SHOW IT?

`agentsec:external:evaluation`, separate from static scanner findings and runtime
events. Correlation uses the genuine garak run/probe/detector/model identity
tuple—not Cisco’s content hash.

## WHAT CONTROL COULD CHANGE THE RESULT?

Model configuration or provider controls may affect model behavior. For AgentSec
tool execution, only the independent runtime authorization path can ALLOW or DENY.

## WHAT TEST PROVES THE LOGIC?

Adapter unit tests validate native eval parsing, raw hash linkage, optional
fields, and PDP isolation. Live local execution and Splunk searches measure the
actual external-tool and ingest paths.

## What I should now be able to explain

1. Why adversarial evaluation is negative testing.
2. How probe, detector, and generator differ.
3. Why one PASS is not universal safety.
4. Why one FAIL is not confirmed exploitation.
5. Why model response text is not runtime execution.
6. Why garak evidence is class `evaluation`, not `finding`.
7. Why correlation strategy depends on the evidence source.
8. How raw report hashes improve evidence quality.
9. Why garak, Splunk, and AgentSec have distinct responsibilities.
10. How this lesson transfers to pentests, fuzzers, and vulnerability scanners.
