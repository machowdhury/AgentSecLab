# How to investigate the lending-assistant capstone

A lending assistant accessed customer-tier information while it was expected to summarize lending policy. You are not told which control failed. You reconstruct SOURCE → PROVENANCE → TRUST BOUNDARY → INFLUENCE → REQUEST → AUTHORITY → POLICY DECISION → EXECUTION → TELEMETRY → SPLUNK → EVIDENCE.

## Simple picture

Someone retrieves a policy document. The runtime stores that text. Later it recalls the text and asks for a privileged tool. Retrieval and memory can influence the request. Only CTRL-MCP-001 decides whether the tool may run.

## Technical picture

Three HTTP runs keep existing contracts: retrieve (no MCP follow-on), write, later recall (MCP). Hash equality joins retrieve to write. `source_run_id` joins write to recall. Schema stays 1.9.0.

ATTACK uses a labeled lab overlay so you can see execution. RETEST keeps the same bytes and removes the overlay.

Goal Integrity and Identity are not part of this incident. Ruling them out is part of the skill.

## What I should now be able to explain

1. Why retrieved content is data even when it later shapes a request
2. Why stored memory is not a grant
3. How three run.ids correlate without a new schema field
4. Why CTRL-MCP-001 is the tool PDP in this packet
5. Why handler count is authoritative and mcp.started is corroboration
6. Why OBSERVE is not ALLOW
7. Why zero Goal or Identity rows do not prove those domains never fail
8. Why Splunk is not enforcement
9. Why one RETEST is not universal resistance
10. Which claims are SUPPORTED, CORROBORATED, NOT PROVEN, or INCORRECT
