# Goal / instruction integrity SOC investigation workshop

**Status:** Phase 13E Dashboard Studio workshop `ws_lab_agent_goal_integrity`.

## What is it?

A ten-tab Splunk Dashboard Studio class for LAB-AGENT-GOAL-INTEGRITY-001. It teaches **what a SOC can prove** from authorized-tool + unauthorized-goal evidence: task, instruction, goal decision, tool grant, and execution are different planes. Markdown teaches. Tables run Phase 13C-validated `Q-GOAL-INTEGRITY-AUTHORITY` and Q-MCP searches.

## Why does it exist?

Runtime (13B), Splunk (13C), and detection analysis (13D) already exist. Learners still need a clickable SOC path that makes AUTHORIZED TOOL != AUTHORIZED GOAL obvious. The workshop is the teaching surface, not a new control and not a new detector.

## How does it work?

Tokens: Hunt run_id defaults to the LIVE BASELINE specimen. BASELINE / ATTACK / RETEST tokens bind Phase 13C LIVE IDs. Q-GOAL and Q-MCP bind one `run.id`. DETECT right table is **SIMULATED** `makeresults`. Empty teaching is `noDataMessage`.

ATTACK and RETEST share the same task, malicious instruction, proposed expansion, and `lookup_policy` grant. The goal-integrity decision is the discriminator.

## Where does it sit in AgentSec?

After 13D analysis, as the learner-facing workshop. Visual sibling of `ws_lab_memory_security`, but **not a memory copy**: this lab is one run with a server-owned task contract. Splunk still does not authorize. No DET-GOAL. Phase 14 not started.

## What is the trust boundary?

AUTHORIZED TOOL != AUTHORIZED GOAL. AUTHORIZED TOOL != AUTHORIZED USE OF TOOL. CTRL-GOAL-INTEGRITY-001 evaluates task integrity; it does not grant the tool. Hop-1 CTRL-MCP-001 is the real tool gate. The dashboard is observe-only.

## What could an attacker control?

Untrusted **instruction text** (here, a malicious fixture proposing `extract_full_policy`). Not the coded server grant. Not Splunk. Not the LLM as an authorization authority.

## What can go wrong?

- Treating `untrusted_instruction` as malice
- Treating OBSERVE as ALLOW
- Treating proposed goal as authorized goal
- Treating MCP ALLOW as goal authorization
- Calling RETEST “MCP blocked”
- Equating missing Splunk rows with blocked
- Hunting AGENT NOTE as a production IOC
- Collapsing goal DENY into MCP DENY
- Treating DET-MCP-001 silence as SAFE
- Treating BASELINE as SAFE

## What telemetry should exist?

Already indexed: task id/hash/provenance, instruction.trust, goal.proposed, GOAL decision/reason, MCP decision, mcp.*. **Not** first-class: instruction hash, effective_action, `allowed_tools`, `gen_ai.tool.call.id`.

## How will Splunk show it?

Ten GRID tabs. COMPARE shows the same proposed `extract_full_policy` on ATTACK and RETEST. DETECT titles **DETECTION ANALYZED — NO NEW GOAL DETECTOR**.

## What control could change the result?

Defended CTRL-GOAL-INTEGRITY-001 DENY (RETEST). The MCP grant for `lookup_policy` stays ALLOW.

## What test proves the logic?

Pytest proves JSON/XML contracts. Playwright proves tabs and tokens in Splunk Web. Pytest does not prove detection effectiveness.

## What I should now be able to explain

1. Why ATTACK and RETEST share the same task hash, proposed goal, and MCP ALLOW.
2. Why MCP ALLOW does not mean the agent's goal was authorized.
3. Why RETEST still executes `lookup_policy` after a goal DENY.
4. Why DET-MCP-001 is empty on all three LIVE runs, correctly.
5. Why zero DET-MCP-001 rows does not mean SAFE.
6. Why `untrusted_instruction` is classification, not malice.
7. Why handler count is authoritative and Splunk start is corroboration.
8. Why the overlay reason is not a production IOC.
9. Why instruction hash is PARTIALLY SUPPORTED in Splunk.
10. Why ML must not grant or deny authority.
