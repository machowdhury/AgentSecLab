# Learning note: Multi-stage agentic incident response

## What is it?

It is the disciplined reconstruction of how influence, requests, authority,
execution, outcomes, persistence, data, and evidence interact during an
agentic incident.

## Why does it exist?

Complex incidents invite overclaiming. A suspicious document does not prove
execution; ALLOW does not prove completion; a scanner finding does not prove
causality; missing telemetry does not prove prevention.

## How does it work in AgentSec?

L9 reuses one validated RAG → memory → MCP Capstone packet. Learners start with
limited observables, discover runs, build a timeline and evidence graph,
challenge a false lead, compare ATTACK and RETEST, then design response,
detection, hunting, and architecture updates.

## Where are the trust boundaries?

External content crosses into RAG context; stored context crosses time through
memory; a request crosses the authority boundary at CTRL-MCP-001; tool output
crosses into business/data handling; telemetry crosses into Splunk.

## What could an attacker control?

Only the closed synthetic context fixture. The server owns profile, policy,
grants, tool registry, and experiment overlay. External evidence cannot change
runtime authorization.

## What can go wrong?

Influence may form a dangerous request, a vulnerable control condition may
allow it, excessive data may flow, logs may duplicate it, incomplete evidence
may distort conclusions, and unrelated findings may become false leads.

## What telemetry should exist?

Source/provenance, canonical hash, memory write/recall linkage, request, PDP
decision/reason, invocation, completion/failure, outcome, timestamp, sequence,
identity claims, correlation IDs, and bounded data evidence.

## How will Splunk show it?

Search progresses from bounded candidate discovery to per-run sequence,
ATTACK/RETEST comparison, external evidence review, candidate detection, and
behavioral hunt. Distinct `_raw` counts prevent duplicate replay indexing from
being mistaken for extra executions.

## What control changes the result?

CTRL-MCP-001 changes from the labeled vulnerable fail-open ATTACK condition to
`DENY tool_not_granted` on RETEST. RAG and Memory stay OBSERVE, proving that
influence can remain while authority is constrained.

## What test proves the logic?

Offline contracts prove artifact consistency, answer gating, evidence states,
graph semantics, control classifications, searches, and invariants. Live
Splunk validation proves only the bounded searchable copies.

## What I should now be able to explain

1. Which incident stages are proven, inferred, absent, or not modeled?
2. Why does context influence not equal authority?
3. What separately proves request, decision, invocation, completion, and outcome?
4. How does `source_run_id` support memory reconstruction?
5. Why is the scanner HIGH finding a false lead here?
6. What data impact is supported and what remains unknown?
7. Which control failed on ATTACK and succeeded on RETEST?
8. How do containment, remediation, and hardening differ?
9. How should a candidate detection be tested?
10. How should operational evidence update threat and privacy models?
