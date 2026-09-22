# MCP security experiment workbench

## What is it?

A compact learner interface for testing one security question: can an agent invoke a tool outside its server-owned grant?

It is not the policy engine. The Attack Service launches a closed specimen. AcmeBank evaluates CTRL-MCP-001 and invokes—or does not invoke—the handler. OpenTelemetry transports a copy. Splunk reconstructs that evidence.

## Why does it exist?

The earlier page contained correct material but mixed orientation, documentation, launching, raw output, and investigation into one long column. Correct security text is not enough if the learner cannot quickly distinguish request, authorization, execution, and evidence.

## How does it work?

The default view shows:

```text
PRINCIPAL → AGENT → REQUEST → AUTHORIZATION → EXECUTION → EVIDENCE
```

ATTACK and RETEST use the same canonical request fingerprint. The server-owned ExperimentContext changes:

- ATTACK: vulnerable profile, labeled fail-open ALLOW, handler count 1
- RETEST: defended profile, DENY `tool_not_granted`, handler count 0

The comparison labels sameness and difference in words. Fingerprint equality proves only equality of the canonical object represented by that hash.

## Where does it sit in AgentSec?

- Academy / Studio teaches the mission and investigation.
- Attack Service launches LIVE experiments.
- AcmeBank owns CTRL-MCP-001 and runtime handler counts.
- OpenTelemetry transports evidence.
- Splunk supports reconstruction and comparison.

## What is the trust boundary?

The boundary is between an agent/tool request and server-owned coded policy. The browser may select an allowlisted specimen and mode. It cannot submit profile, grants, allowed tools, allowed scopes, policy, or a control decision.

## What could an attacker control?

Inside the closed MCP specimen: requested tool, requested scope, and arguments. This is educational deterministic input, not a general-purpose MCP proxy.

## What can go wrong?

- Treating the requested tool as a grant
- Treating ALLOW as proof that the handler started
- Treating DENY as sufficient proof that it did not
- Treating missing Splunk events as prevention
- Treating detector silence as SAFE
- Treating equal fingerprints as universal request equivalence
- Exposing the localhost launcher to an untrusted network

## What telemetry should exist?

The run should contain principal, agent, tool, requested/allowed scope, CTRL-MCP-001 decision and reason, operation state, MCP start/completion where execution occurred, run.id, sequence, profile, and mode.

## How will Splunk show it?

Path A starts with the fresh run.id. Existing Q-MCP-WHO, Q-MCP-AUTHZ, and Q-MCP-EXECUTED answer WHO, REQUEST/AUTHZ, and EXECUTION. Local event count must match Splunk `dc(_raw)` before absence is treated as corroboration.

## What control could change the result?

CTRL-MCP-001 at AcmeBank. The defended ExperimentContext denies the known-ungranted tool before handler invocation. Splunk does not change the result.

## What test proves the logic?

Security and integration tests prove the closed launch contract, pre-handler decision, and handler counts. A fresh LIVE pair plus local-count/Splunk-count equality proves the measured lab run was reconstructable. Neither proves universal MCP security.

## What I should now be able to explain

1. Why is a requested tool not a grant?
2. Why does ALLOW not prove execution?
3. What evidence proves the MCP handler began?
4. Why is runtime handler count authoritative for this lab?
5. Why is an absent `mcp.started` only corroborative in Splunk?
6. Which fields can the browser submit?
7. What changes between ATTACK and RETEST?
8. What does equal input fingerprint prove—and not prove?
9. Why is DET-MCP-001 silence not SAFE?
10. Why is Splunk an evidence plane rather than the PDP?
