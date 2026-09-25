# Advanced capstone and mastery

## What is it?

L10 is one unfamiliar investigation, MASTER-2026-001. You are not handed a run identifier or a finished attack story. You are given a business workflow, a time window, and Splunk.

## Why does it exist?

Earlier labs taught one skill at a time. This capstone asks whether you can use those skills together, and whether you can say what the evidence does not prove.

## How does it work?

AcmeBank's lending-policy assistant has an authorized task: summarize lending policy options. It may call `lookup_policy`. An untrusted instruction can propose a broader action. The goal check and the tool check are different controls. Splunk records both. A scanner finding and a model evaluation sit beside the runtime. They do not grant tools.

## Where does it sit in AgentSec?

After L9. It is a REPLAY workspace, `LAB-ADVANCED-CAPSTONE-MASTERY-001`. Attack Service does not launch it. The LIVE capstone remains the last launcher.

## What is the trust boundary?

The task contract (`agent.task.contract`) decides whether an instruction may replace the objective. The tool boundary (`acmebank.mcp.authorize`) decides whether `lookup_policy` may run. Those are not the same boundary.

## What could an attacker control?

The instruction text. Not the coded tool grant. Not Splunk. Not the scanner. Not garak.

## What can go wrong?

The tool can be allowed while the objective is wrong. A HIGH scanner row can look like the cause. A PASS evaluation can look like safety. Three indexed copies can look like three executions. A benign lookup of the same tool can look like the incident.

## What telemetry should exist?

Goal decision and reason, tool decision and reason, started and completed tool events, task and instruction fingerprints, and the effective action. Some of those fingerprints are still inside a preview string.

## How will Splunk show it?

Search the window `2026-09-18T22:47:40Z` through `2026-09-18T22:48:10Z` in `index=agentsec_telemetry` and `sourcetype=otel:agentic:json`. Count distinct `_raw` separately from indexed rows. Pivot to scanner and evaluation sourcetypes without forcing a join that the events do not have.

## What control could change the result?

`CTRL-GOAL-INTEGRITY-001` can deny an unauthorized task expansion before the handler runs, while `CTRL-MCP-001` still allows the granted summary tool.

## What test proves the logic?

The offline contract in `tests/splunk/test_advanced_capstone_mastery.py` checks registration, hypothesis disposition, the evidence gap, answer gating, and that the detection candidate is not installed. Live Splunk measurement is recorded separately and is not invented.

## What I should now be able to explain

1. Why does this investigation start from a time window instead of a run identifier?
2. Why can `CTRL-MCP-001` ALLOW and the objective still be unauthorized?
3. Which initial hypothesis does the tool decision refute?
4. Why are the scanner HIGH finding and the garak PASS not this incident?
5. What question about customer impact must stay NOT PROVEN?
6. Why is `dc(_raw)` the execution count and `stats count` not?
7. What must a valid retest preserve, and what must still work afterward?
8. Where would you place the control that stops the expanded objective?
9. What would you tell an executive without using BREACH, COMPROMISED, or SAFE?
10. What evidence would you need before you marked a mastery dimension DEMONSTRATED?
