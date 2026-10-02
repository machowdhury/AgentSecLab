# Release lab matrix

This matrix describes v1.0.0 on `main`.

Annotated tag `v1.0.0-rc1` (peeled commit `e6115b6d1c03a1672b4364e84748c7840671fbfc`) is the historical RC1 baseline. That tag does not contain L6–L10. Tags `v1.0.0-rc2` and `v1.0.0-rc3` were not moved.

Effort text comes from `learning/academy/curriculum.json` where present. Phase numbers are not the learner model.

## How to read mode

| Mode | Meaning |
|------|---------|
| LIVE | A fresh supported execution can be launched. You get a new `run.id`. |
| REPLAY | You investigate canonical or previously captured evidence. You do not launch it. |
| STATIC REASONING | You analyze architecture, controls, privacy, or a threat model without claiming a fresh attack. |
| SIMULATED | Fixture-backed or in-process data teaches a bounded idea. It is not a production system. |

A LIVE dashboard may also show canonical specimen ids. Those ids are REPLAY or reference evidence unless Attack Service minted them in this session.

ATTACK is an attack-condition experiment, not proof of universal compromise. RETEST is a controlled defended comparison, not proof of universal safety. BASELINE is an expected comparison, not “trusted forever.”

Only seven labs are launchable. That count is the Attack Service allowlist in code: `LAB-PI-001`, `LAB-MCP-001`, `LAB-RAG-CONTEXT`, `LAB-MEMORY-001`, `LAB-AGENT-GOAL-INTEGRITY-001`, `LAB-AGENT-DELEGATION-001`, `LAB-AGENTSEC-CAPSTONE-001`. Other rows are not launchers. Do not add them by editing this table.

Names: **L5 Capstone** is Lending Assistant Investigation. **L10 Advanced Capstone** is MASTER-2026-001. **Mastery Check** is the unscored self-check. Those three are not the same exercise.

## Matrix

| Level | Exercise | Mode | Launch | Simulated / fixture | Splunk | External evidence | Learner outcome |
|-------|----------|------|--------|---------------------|--------|-------------------|-----------------|
| L0 | Orientation (Academy Home) | STATIC REASONING | NO | NO | Read-only context | NO | Explain what AgentSec is and what Splunk does not do. |
| L1 | Direct Prompt Injection (`LAB-PI-001`) | LIVE | YES | Educational payloads | YES | NO | Predict, launch ATTACK, copy this session’s `run.id`, compare RETEST. |
| L1 | Tool Authorization (`LAB-MCP-001`) | LIVE | YES | Educational tool request | YES | NO | Separate a tool request from a CTRL-MCP-001 grant. |
| L1 | Scope Escalation (`LAB-MCP-003`) | REPLAY | NO | Historical specimen | YES | NO | Read grant anatomy without launching. |
| L1 | Parameter / Resource Authorization (`LAB-MCP-004`) | REPLAY | NO | Historical specimen | YES | NO | Read parameter and resource checks without launching. |
| L2 | RAG / Retrieved Context (`LAB-RAG-CONTEXT`) | LIVE | YES | YES — fixture documents | YES | NO | See retrieval influence context. Retrieval does not mint a grant. |
| L2 | Persistent Memory (`LAB-MEMORY-001`) | LIVE | YES | YES — in-process memory | YES | NO | See recall reused as data. Recall does not mint a grant. |
| L2 | Tool Result Trust (`LAB-MCP-005`) | REPLAY | NO | Historical specimen | YES | NO | Treat a tool result as data, not as authority. |
| L2 | Tool Catalog (`LAB-MCP-CATALOG`) | REPLAY | NO | Historical specimen | YES | NO | Separate catalog content from a grant. |
| L2 | Scanner + Runtime Evidence (`LAB-SCANNER-RUNTIME-EVIDENCE`) | REPLAY | NO | Imported scanner pack | YES | YES — Cisco mcp-scanner (Cisco AI Defense), not built by AgentSec | A finding is adjacent evidence. HIGH is not DENY. Zero findings are not safe. |
| L2 | External Security Toolbox (`LAB-EXTERNAL-EVALUATION-GARAK`) | REPLAY | NO | Imported evaluation pack | YES | YES — garak (NVIDIA), not built by AgentSec | A garak result is adjacent evidence. PASS is not safe. |
| L3 | Goal / Instruction Integrity (`LAB-AGENT-GOAL-INTEGRITY-001`) | LIVE | YES | Educational instruction | YES | NO | An authorized tool is not an authorized objective. |
| L3 | Agent Identity / Delegation (`LAB-AGENT-DELEGATION-001`) | LIVE | YES | YES — educational identity claim, not authentication | YES | NO | A claim is not production identity. |
| L3 | Confused Deputy (`LAB-MCP-006`) | REPLAY | NO | Historical specimen | YES | NO | Separate delegation evidence from a tool grant. |
| L4 | Investigation craft | STATIC REASONING | NO | Practice on LIVE Path A | YES, on those labs | NO | Hunt versus detection. Zero rows is not safe. No separate page. |
| L5 | Lending Assistant Investigation (`LAB-AGENTSEC-CAPSTONE-001`) — **L5 Capstone** | LIVE | YES | Uses the educational runtime chain | YES | NO | Launch and reconstruct the integrated chain. Last LIVE launcher. |
| Checkpoint | Splunk Defender Bridge (`LAB-SPLUNK-DEFENDER-BRIDGE`) | REPLAY / static | NO | Existing indexed telemetry. No new attack. | YES | NO | Discover a candidate run from behavior. Not an eighth LIVE lab. |
| L6 | AcmeBank Incident AI-2026-001 (`LAB-BLUE-TEAM-INCIDENT-001`) | REPLAY | NO | Canonical incident evidence | YES | NO | Hypothesize, search, and state uncertainty without a fresh launch. |
| L7 | AcmeBank Agentic Customer Operations Platform (`LAB-THREAT-MODELING-001`) | STATIC REASONING | NO | Described system, not a new attack | Optional corroboration | NO | Produce a threat model with gaps and residual risk. `curriculum.json` records the workshop mode as REPLAY because it is not a launcher. The activity adds no attack. |
| L8 | AcmeBank Incident PRIV-2026-001 (`LAB-PRIVACY-DATA-GOVERNANCE-001`) | REPLAY | NO | Canonical incident evidence | YES | NO | Separate an authorized action from appropriate data use. Not a privacy certification. |
| L9 | Acme Bank Incident AGENT-2026-009 (`LAB-MULTI-STAGE-INCIDENT-001`) | REPLAY | NO | Canonical multi-stage evidence | YES | Uses indexed external evidence as a lead, not as authorization | Investigate a chain, reject false leads, and communicate bounded conclusions. |
| L10 | Acme Bank Capstone MASTER-2026-001 (`LAB-ADVANCED-CAPSTONE-MASTERY-001`) — **Advanced Capstone** | REPLAY | NO | Canonical mastery evidence | YES | Uses indexed external evidence as a lead, not as authorization | Investigate without a starting run id. Leave at least one claim NOT PROVEN. |
| — | Mastery Check (`ws_agentsec_mastery`) | STATIC REASONING | NO | Questions, not an execution | Some review searches | NO | Unscored self-check. Not L5. Not L10. Not a certification. |

## Shared rules

CTRL-MCP-001 (`coded_policy()`) is the tool policy decision point on LIVE tool use. RAG, memory, identity observation, Splunk, Cisco mcp-scanner, and garak do not mint tool grants.

Path B is visible pedagogical guidance, not access control.

Learners do not edit source, shells, or grants. Published path: Academy Home, then Attack Service only when the row says Launch YES, then Splunk Search.

Prerequisites and effort: Academy Home and `learning/academy/curriculum.json`.
