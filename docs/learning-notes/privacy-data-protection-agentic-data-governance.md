# Learning note: Privacy and agentic data governance

## What is it?

Privacy reasoning asks what data an agent can see, infer, retrieve, remember,
send, log, retain, and expose—not only whether its action was authorized.

## Why does it exist?

An authorized tool can receive unnecessary data. A useful security log can
create another sensitive copy. Retrieval and memory can expose data without a
classic exfiltration exploit.

## How does it work in AgentSec?

`PRIV-2026-001` compares a full synthetic customer record with a purpose-
minimized record. Both receive CTRL-MCP-001 ALLOW and execute once. The learner
traces the data, investigates Splunk, classifies evidence, and designs controls
without changing the PDP.

## Where is the trust boundary?

Important boundaries include fixture-to-tool argument, agent-to-MCP authority,
tool-to-downstream processing, and runtime-to-telemetry/Splunk observation.
RAG, memory, and external providers are architectural privacy boundaries but
are not incident event stages.

## What could an attacker control?

In the bounded comparison no open attacker interface exists. The lab supplies
immutable synthetic fixtures. In a real design, users, retrieved documents,
memory, tool outputs, configuration, and dependencies may influence data.

## What can go wrong?

Over-collection, over-broad retrieval, cross-context recall, excessive tool
arguments, sensitive logs, long retention, provenance loss, and sensitive
inference can occur even when execution is legitimate.

## What telemetry should exist?

Enough to correlate request, authorization, invocation, completion, and
outcome while avoiding unnecessary content. Provenance and hashes can support
investigation; they do not make content trusted or privacy-safe.

## How will Splunk show it?

The privacy searches discover the two lab runs, reconstruct each sequence, and
compare decision, execution, preview, and hash. Splunk observes a copy; it does
not authorize, minimize, redact, or delete runtime data.

## What control could change the result?

Purpose-based field selection before tool construction produces the minimized
specimen. Other architectural controls include retrieval/memory scoping,
argument filtering, secret exclusion, telemetry access, retention, and
deletion.

## What test proves the logic?

Security tests prove fixture validation, identical ALLOW/execution semantics,
and the changed received-field set. Splunk validation measures seven indexed
events per run. Neither test proves production privacy safety.

## What I should now be able to explain

1. Why is authorized action different from authorized data use?
2. Which fields does a bounded task actually require?
3. Where does data cross boundaries in an agentic workflow?
4. Why is retrieval authorization distinct from tool authorization?
5. How does memory privacy differ from memory poisoning?
6. Why can additional telemetry increase privacy risk?
7. What can redaction not prove?
8. Which evidence proves invocation and completion?
9. Which data-handling facts remain not modeled?
10. What residual risk remains after minimization?
