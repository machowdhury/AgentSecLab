# Splunk Defender Bridge

## What is it?

A REPLAY investigation checkpoint between the L5 Capstone and L6. You practice finding security activity without being handed a run identifier.

## Why does it exist?

Guided labs often start with `run.id` already known. Independent workshops expect you to start from a question. The missing skill is the path between those two habits.

## How does it work?

You write a hypothesis, choose the telemetry index, set a time range, inspect fields, narrow to CTRL-MCP-001 decisions, discover candidate runs, reconstruct only the events that exist, compare ATTACK / RETEST / BASELINE, and reject an external finding that cannot authorize a tool.

## Where does it sit in AgentSec?

Academy order: L5 → Splunk Defender Bridge → L6. It is not a new L-number and not an Attack Service lab.

## What is the trust boundary?

CTRL-MCP-001, in the runtime, decides tool authority. Splunk only shows what was indexed. Retrieved content, memory, scanner output, and garak output do not mint that decision.

## What could an attacker control?

In the underlying tool lab, untrusted content can influence what the agent requests. It cannot, by itself, grant the tool. On this page you are not launching that attack. You are reading evidence of earlier controlled runs.

## What can go wrong?

You can treat a pasted run identifier as the investigation. You can treat indexed copies as extra executions. You can treat a scanner HIGH or a garak result as DENY. You can fill in a missing `agentsec.mcp.started` event. You can call an empty search proof that nothing happened.

## What telemetry should exist?

Control decisions (`event.name=agentsec.control.decision`) with `agentsec.control.id`, `agentsec.control.decision`, and `agentsec.control.reason`. Tool follow-on events when they happened: `agentsec.mcp.started`, `agentsec.mcp.completed`, `agentsec.mcp.failed`. Mode in `agentsec.testbed.mode`. External planes stay on their own sourcetypes.

## How will Splunk show it?

Tables on the bridge. Search is Path A. Path B is a review key after you have tried. `count`, `dc(_raw)`, and `dc(agentsec.run.id)` answer different questions.

## What control could change the result?

CTRL-MCP-001. Splunk cannot change it. A detection saved search cannot change it. This checkpoint does not enable a detector.

## What test proves the logic?

Offline tests check placement, the absence of a supplied run identifier on the mission, hint order, answer separation, and the schema and contract versions. A Splunk run of the searches is a separate measurement and is recorded only when it actually runs.

## What I should now be able to explain

1. Why a run identifier is discovered evidence rather than the opening answer.
2. Which index and sourcetype hold AgentSec runtime telemetry.
3. How ALLOW differs from execution, and how DENY differs from a claim that the system is protected.
4. What `count`, `dc(_raw)`, and distinct run identifiers each measure.
5. Why ATTACK, RETEST, and BASELINE are controlled comparisons.
6. What a scanner finding can and cannot establish about runtime authorization.
7. The difference between how evidence was obtained and what claim strength it supports.
8. Why this checkpoint is not L6 and not a validated detector.
