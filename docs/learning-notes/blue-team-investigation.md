# Blue-Team Investigation from Incomplete Evidence

## What is it?

A blue-team investigation starts with an observation, not a known answer. The analyst proposes a falsifiable explanation, identifies evidence that would support or refute it, searches, reconstructs sequence, and communicates only what the evidence permits.

## Why does it exist?

Known ATTACK/RETEST labs teach controls. An incident investigation teaches uncertainty: missing events, alternative explanations, false positives, and the difference between an observation and a conclusion.

## How does it work?

AgentSec reuses one validated Capstone packet. Beginner, intermediate, and advanced learners receive progressively less guidance while searching the same telemetry. A separate review key prevents the lab title from giving away the result.

## Where does it sit in AgentSec?

It follows the LIVE Capstone as a REPLAY Academy level. AcmeBank remains the runtime, CTRL-MCP-001 remains the tool PDP, and Splunk remains the downstream investigation workbench.

## What is the trust boundary?

Untrusted retrieved and recalled content can influence a request. The authority boundary is CTRL-MCP-001 before the tool handler. Splunk does not sit in that path.

## What could an attacker control?

In this closed packet the attacker-controlled element is the adversarial content fixture. The browser does not control coded grants, security profile, tools, or PDP logic.

## What can go wrong?

An analyst can mistake request for authorization, ALLOW for execution, invocation for completion, hash equality for causality, anomaly for attack, missing evidence for prevention, or adjacent external evidence for runtime cause.

## What telemetry should exist?

Run ID, runtime sequence, event name, content fingerprint, memory source run, requested and allowed authority, control ID/decision/reason, tool invocation, terminal event, and outcome. Authentication is intentionally not modeled.

## How will Splunk show it?

`Q-INCIDENT-CANDIDATES` finds bounded candidate runs. `Q-INCIDENT-TIMELINE` reconstructs one run. `Q-INCIDENT-COMPARE` compares the validated ATTACK and RETEST recall evidence without `transaction`.

## What control could change the result?

CTRL-MCP-001 changes authorization. The validated RETEST keeps the adversarial influence but removes the vulnerable fail-open overlay, producing `DENY tool_not_granted`.

## What test proves the logic?

Repository tests prove the workbench contract, hint order, answer separation, search presence, curriculum registration, PDP/schema invariants, and report content. A separate live Splunk execution proves the searches against indexed evidence. Offline tests do not prove live Splunk.

## Transferable principles

Least privilege, provenance, separation of duties, evidence integrity, defense in depth, incident response, and bounded claims apply equally to traditional applications, APIs, identities, and infrastructure.

## What I should now be able to explain

1. Why is a hypothesis different from a conclusion?
2. Which evidence distinguishes request, authorization, invocation, completion, and outcome?
3. Why does correlation not establish causality?
4. Why can expected activity match a broad threat hunt?
5. When should a report say `LIKELY CONTRIBUTING FACTOR` instead of root cause?
6. What does CTRL-MCP-001 decide?
7. Why is Splunk not the enforcement point?
8. Which evidence gaps are NOT MODELED versus merely NOT OBSERVED?
9. How would I explain the same incident to an engineer and an executive?
