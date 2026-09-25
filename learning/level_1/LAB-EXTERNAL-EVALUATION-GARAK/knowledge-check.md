# Knowledge check

1. Why are Cisco mcp-scanner and garak different evidence classes?
2. What exact byte relationship does the Cisco description-hash match support?
3. Why does scanner severity HIGH not prove exploitation or DENY?
4. Why do zero scanner findings not prove safety?
5. Why run an adversarial model evaluation?
6. What did `dan.Dan_11_0` test and `dan.DAN` observe?
7. What does native PASS mean here?
8. Why does PASSING EVALUATION != SAFE?
9. Why does FAILED EVALUATION != EXPLOIT CONFIRMED?
10. Why does MODEL RESPONSE != RUNTIME TOOL EXECUTION?
11. Which component authorizes AgentSec MCP tools?
12. Why is `identity_tuple` used instead of Cisco’s description hash join?
13. What proves ALLOW, execution start, and successful completion?
14. What should a learner conclude from NO EVIDENCE FOUND?
15. Fill in ASSET, ACTOR, ENTRY POINT, TRUST BOUNDARY, CONTROL,
    OBSERVABILITY, and RESIDUAL RISK for one specimen.

## Answers

1. Cisco statically evaluates catalog bytes and emits `finding`; garak evaluates
   a model response and emits `evaluation`.
2. The SHA-256 values compare the defined UTF-8 tool-description bytes with
   runtime `content.hash`. They do not prove a shared process or request.
3. HIGH is a native scanner label. Authorization, execution, impact, and
   incident severity require separate evidence.
4. The configured scanner produced zero findings for those bytes. Other
   analyzers, weaknesses, configurations, and runtime behavior remain untested.
5. To test a defined unwanted behavior and increase assurance within the tested conditions.
6. Whether one local response adopted the requested DAN persona/marker; the
   detector did not find the marker and the native eval counted one pass.
7. One response passed one detector under this probe/configuration.
8. Other prompts, probes, detectors, generations, configurations, and risks were not tested.
9. A detector hit reports tested model behavior; exploitation and impact need additional evidence.
10. Text output is not a tool call, authorization decision, handler start, or outcome.
11. CTRL-MCP-001.
12. garak’s genuine shared identifiers are native run, probe, detector, and model—not catalog content hashes.
13. The PDP decision/reason proves ALLOW; `mcp.started` supports execution
    beginning; completion or failure telemetry establishes how that begun call ended.
14. Diagnose pack availability, HEC, Splunk, sourcetype, identifier, time range,
    and extraction. No row is not safety, prevention, or proof of absence.
15. Answers vary, but must name the protected asset, influencing actor, untrusted
    entry, trust change, governing control, evidence required, and remaining risk
    without making scanner/evaluation output the PDP.
