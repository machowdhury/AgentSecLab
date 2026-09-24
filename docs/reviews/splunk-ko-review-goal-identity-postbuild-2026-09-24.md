# Splunk knowledge-object review — Goal and Identity postbuild

**Date:** 2026-09-24
**Objects:** `ws_lab_agent_goal_integrity`, `ws_lab_agent_delegation`
**Verdict:** PASS

## Architecture

Both workshops now use:

1. MISSION
2. INVESTIGATE
3. EVIDENCE
4. PATH B · ANSWERS

The selected specimen token remains a canonical REPLAY value. Fresh LIVE run IDs are investigated in Splunk Search through the Attack Service handoff. Studio does not POST launches.

## SPL integrity

- Existing Q-GOAL, Q-AGENT-DELEGATION, and Q-MCP search files are byte-unchanged.
- Dashboard data-source query bindings remain equal to their source Q-* files after only run-id substitution.
- Every data source remains referenced by a visible table.
- No saved search was enabled.
- No DET-GOAL or DET-A2A was created.
- DET-MCP-001 context remains optional answer material and is not represented as either domain's detector.

## Goal evidence claim

The primary question is whether the wrong-goal objective executed, not whether any handler executed.

Fresh Q-GOAL results:

- ATTACK `8f5dbdef-be98-4d82-9f53-4dba0ee76a2a`: Goal OBSERVE fail-open; MCP ALLOW; `mcp.completed_observed`.
- RETEST `a00492bb-b12d-49d1-b61a-f6a25e76e9d5`: Goal DENY expansion; MCP ALLOW; `mcp.completed_observed`.

Runtime operation-specific counts provide the decisive distinction: ATTACK wrong-goal 1; RETEST wrong-goal 0 and in-task 1. Splunk corroborates the completed lookup in both modes but does not determine its goal classification.

## Identity evidence claim

The primary question separates claim attribution, claim classification, tool authority, execution, and absent authentication.

Fresh Q-AGENT-DELEGATION results:

- ATTACK `c9383fc4-3b91-45aa-81cc-95e7b00a3d9b`: Identity OBSERVE; MCP ALLOW; `mcp.completed_observed`.
- RETEST `44076225-c390-4d63-9a87-659855fc0c61`: Identity OBSERVE; MCP DENY; `no_indexed_followon_execution_event`.

No search claims that principal/caller/callee strings authenticate actors. Crypto identity, OAuth/OIDC, and signed delegation remain NOT MODELED.

## Completeness

- Goal ATTACK: local 10 / Splunk `dc(_raw)` 10
- Goal RETEST: local 10 / Splunk `dc(_raw)` 10
- Identity ATTACK: local 10 / Splunk `dc(_raw)` 10
- Identity RETEST: local 9 / Splunk `dc(_raw)` 9

This supports completeness for these four primary runs only. HEC HTTP success was not used as the completeness claim.

## Semantic limits

- Splunk is evidence, not enforcement.
- Empty results are not prevention.
- Identity OBSERVE is not authorization.
- MCP ALLOW is not execution.
- Goal DENY does not imply the permitted tool was denied.
- Deterministic fixture results do not prove universal security effectiveness.
