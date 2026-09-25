# Knowledge check

1. Why run an adversarial model evaluation?
2. What did `dan.Dan_11_0` test?
3. What did `dan.DAN` observe?
4. What does native PASS mean here?
5. Why does PASSING EVALUATION != SAFE?
6. Why does FAILED EVALUATION != EXPLOIT CONFIRMED?
7. Why does MODEL RESPONSE != RUNTIME TOOL EXECUTION?
8. Which component authorizes AgentSec MCP tools?
9. Why is `identity_tuple` used instead of Cisco’s description hash join?
10. What evidence would you need before making a runtime-impact claim?

## Answers

1. To test a defined unwanted behavior and increase assurance within the tested conditions.
2. Whether one local model response adopted the requested DAN persona/marker.
3. It did not find the expected DAN marker; the native eval counted one pass.
4. One response passed one detector under this probe/configuration.
5. Other prompts, probes, detectors, generations, configurations, and risks were not tested.
6. A detector hit reports tested model behavior; exploitation and impact need additional evidence.
7. Text output is not a tool call, authorization decision, handler start, or outcome.
8. CTRL-MCP-001.
9. garak’s genuine shared identifiers are native run, probe, detector, and model—not catalog content hashes.
10. Runtime request, PDP decision/reason, tool-start/completion/failure telemetry, handler evidence, and impact.
