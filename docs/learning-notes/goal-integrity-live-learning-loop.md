# Goal / instruction integrity LIVE purple-team learning loop

**Status:** Phase 15D VALIDATED 2026-09-20. Schema 1.9.0. No DET-GOAL. Official LIVE pair ATTACK `dc1f549f-ea1f-4ac5-bc25-5d7cca5b1fe9` / RETEST `624b4223-510e-4a14-88e2-85f82b32d475`.

## What is it?

The existing Goal Integrity lab, taught as a learner-driven LIVE loop. Predict, launch a closed ATTACK, copy `run.id`, hunt in Splunk Search, defend by changing **goal-integrity configuration**, retest the **same malicious instruction bytes**, compare, and state what the evidence does and does not prove.

The central lesson is **AUTHORIZED TOOL != AUTHORIZED GOAL**.

## Why does it exist?

Phase 13E already had a validated REPLAY workshop. Phase 14/15 proved the LIVE loop on PI, MCP, RAG, and Memory. Goal Integrity has different security semantics: the tool stays granted while the **purpose** changes. Collapsing RETEST into MCP DENY would hide that distinction.

## How does it work?

Attack Service picks a predefined ExperimentContext. AcmeBank evaluates a frozen TaskContract plus a closed instruction fixture. CTRL-GOAL-INTEGRITY-001 OBSERVE or DENY. lookup_policy is still requested. CTRL-MCP-001 ALLOW tool_granted. The handler is labeled in-task or wrong-goal. Splunk stores a copy. Splunk does not ALLOW or DENY.

## Where does it sit in AgentSec?

After PI-001, MCP-001, RAG-CONTEXT, and MEMORY-001 LIVE reference labs, on the existing `LAB-AGENT-GOAL-INTEGRITY-001` / `ws_lab_agent_goal_integrity` surface. Identity / Delegation is a later lab and is not this migration.

## What is the trust boundary?

Untrusted instruction → proposed action. Server-owned TaskContract → authorized purpose. Tool grant is a separate plane.

## What could an attacker control?

The instruction body (here, a closed malicious fixture). Not coded grants. Not the TaskContract. Not the browser-chosen profile.

## What can go wrong?

Treating MCP ALLOW as goal authorization; treating goal DENY as MCP DENY; treating untrusted as malicious; treating Splunk as enforcement; blocking lookup_policy instead of protecting the task boundary.

## What telemetry should exist?

task fingerprint, instruction fingerprint, proposed action, CTRL-GOAL-INTEGRITY-001, CTRL-MCP-001, effective action, mcp.started, in-task vs wrong-goal handler counts.

## How will Splunk show it?

Five planes: TASK, INSTRUCTION, GOAL DECISION, TOOL AUTHORIZATION, EXECUTION. Path A in Search. Path B `Q-GOAL-INTEGRITY-AUTHORITY` / Q-MCP on canonical REPLAY. Fresh LIVE ids stay in Search.

## What control could change the result?

CTRL-GOAL-INTEGRITY-001 on the defended ExperimentContext. Not MCP DENY of lookup_policy. Not Splunk. Not an LLM.

## What test proves the logic?

Same instruction fingerprint on ATTACK and RETEST. MCP ALLOW on both. Wrong-goal 1 vs 0. In-task 0 vs 1. Overlay does not mutate `coded_policy()` or the TaskContract.

## What I should now be able to explain

1. What is the authoritative task, and where does task authority come from?
2. Why is the instruction untrusted influence rather than a grant?
3. Why does MCP ALLOW not authorize extract_full_policy?
4. What did CTRL-GOAL-INTEGRITY-001 decide on ATTACK vs RETEST?
5. Why does RETEST still ALLOW lookup_policy?
6. What is the difference between proposed action and effective action?
7. Why is wrong-goal handler count the authoritative proof the expansion executed?
8. Why is DET-MCP-001 silence not SAFE on this lab?
9. Which claims are SUPPORTED, CORROBORATED, NOT PROVEN, or INCORRECT?
10. Why would turning RETEST into MCP DENY destroy the educational purpose of this lab?
