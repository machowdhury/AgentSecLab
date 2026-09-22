# AgentSec concept coverage

**Status:** DESIGN (Phase 16A). Classifies teaching coverage from repository labs.  
**Do not implement missing areas from this file.**

| Status | Meaning |
|--------|---------|
| LIVE VALIDATED | Learner-operated Attack Service + MEASURED Splunk pair |
| REPLAY ONLY | Workshop + hunts; historical packs; no 14E launcher |
| PARTIALLY SUPPORTED | Concept appears but is not the lab’s proof |
| DESIGNED | Specified, not built |
| NOT IMPLEMENTED | Absent |
| OUT OF SCOPE | Explicitly not AgentSec’s job |
| FUTURE | Named later research |

---

## Prompt / instruction security

| Concept | Coverage | Where |
|---------|----------|-------|
| Direct prompt injection | LIVE VALIDATED | LAB-PI-001 |
| Indirect prompt injection | LIVE VALIDATED as retrieved-context influence | LAB-RAG-CONTEXT (not a second PI regex) |
| Instruction hierarchy | PARTIALLY SUPPORTED | Goal lab: server-owned task vs untrusted instruction |
| Untrusted instructions | LIVE VALIDATED | Goal; also PI input |
| Goal redirection | LIVE VALIDATED | LAB-AGENT-GOAL-INTEGRITY-001 |

## Tool / authority security

| Concept | Coverage | Where |
|---------|----------|-------|
| Least privilege | LIVE VALIDATED (tool list) | MCP-001; coded_policy() |
| Tool authorization | LIVE VALIDATED | MCP-001 |
| Parameter / resource authorization | REPLAY ONLY | MCP-004 |
| Scope authorization | REPLAY ONLY | MCP-003 |
| Tool catalog poisoning | REPLAY ONLY | LAB-MCP-CATALOG |
| Confused deputy | REPLAY ONLY | MCP-006 (CTRL-DELEGATION-001). Distinct from 15E identity claims |
| Excessive agency | PARTIALLY SUPPORTED | Goal expansion; MCP-001 ungranted tool |

## Context security

| Concept | Coverage | Where |
|---------|----------|-------|
| RAG / retrieved content | LIVE VALIDATED | LAB-RAG-CONTEXT |
| Provenance | LIVE VALIDATED | document.id + content.hash |
| Trust vs authority | LIVE VALIDATED | OBSERVE then MCP |
| Indirect influence | LIVE VALIDATED | retrieve → request |

## Memory security

| Concept | Coverage | Where |
|---------|----------|-------|
| Persistent memory | LIVE VALIDATED | LAB-MEMORY-001 |
| Write vs recall | LIVE VALIDATED | two run.ids |
| Cross-run correlation | LIVE VALIDATED | source_run_id |
| Poisoning | LIVE VALIDATED (lab fixture) | malicious memory body |
| Persistence ≠ trust | LIVE VALIDATED | INV-003 |

## Identity / delegation

| Concept | Coverage | Where |
|---------|----------|-------|
| Principal / caller / callee | LIVE VALIDATED | LAB-AGENT-DELEGATION-001 |
| Identity claim | LIVE VALIDATED | CTRL-IDENTITY-001 OBSERVE |
| Delegation claim | LIVE VALIDATED | claimed scope/tool/resource |
| Authentication vs attribution | LIVE VALIDATED (teaching) | WHO AUTHENTICATED = NOT PROVEN |
| Authority amplification | LIVE VALIDATED | A+B ≠ customer:read |
| Cryptographic / OAuth / SPIFFE identity | NOT IMPLEMENTED | Explicit 15E stop |
| Real A2A transport | NOT IMPLEMENTED | In-process A2A-shaped request only |

## Goal / task integrity

| Concept | Coverage | Where |
|---------|----------|-------|
| Authoritative task | LIVE VALIDATED | Goal lab |
| Proposed task change | LIVE VALIDATED | extract_full_policy proposal |
| Authorized tool / unauthorized goal | LIVE VALIDATED | lookup_policy ALLOW both ATTACK and RETEST |
| Task expansion | LIVE VALIDATED | RETEST GOAL DENY |

## Execution

| Concept | Coverage | Where |
|---------|----------|-------|
| Attempted / executed / completed / failed / prevented | LIVE VALIDATED | MCP + PI events; Q-MCP-EXECUTED |
| Handler-level evidence | LIVE VALIDATED | runtime counts authoritative; Splunk corroborates |

## Observability

| Concept | Coverage | Where |
|---------|----------|-------|
| Traces / events / run.id / sequence | LIVE VALIDATED | all LIVE labs |
| Cross-run correlation | LIVE VALIDATED | Memory |
| Content hashes / bounded previews | LIVE VALIDATED | RAG, memory, identity, goal fingerprints |
| Provenance fields | LIVE VALIDATED | per-domain |

## SOC / detection engineering

| Concept | Coverage | Where |
|---------|----------|-------|
| Hunt vs detection | LIVE VALIDATED (taught) | every DETECT tab; DET-MCP-001 only operational pattern |
| Reconstruction | LIVE VALIDATED | Path A/B |
| Detection limitations | LIVE VALIDATED | 0 rows ≠ SAFE |
| Evidence classification | LIVE VALIDATED | PROVE tabs |
| Behavioral analytics | FUTURE | DETECT “NOT IMPLEMENTED”; no MLTK |

## AI supply chain

| Concept | Coverage | Where |
|---------|----------|-------|
| Scanner finding vs runtime | REPLAY ONLY | LAB-SCANNER-RUNTIME-EVIDENCE |
| Catalog as supply-chain-ish metadata | REPLAY ONLY | LAB-MCP-CATALOG |
| Model/package SBOM, skill scanners | NOT IMPLEMENTED / FUTURE | 8A/9A research docs |

## Agent-to-agent security

Phase 15E teaches **claims as data**. It does not teach mTLS, agent cards on the wire, or OAuth delegation. MCP-006 teaches **ambient deputy grants** (different control). Real A2A = FUTURE.

## Human approval / HITL

`REQUIRE_APPROVAL` exists in the decision vocabulary (`docs/ARCHITECTURE.md`: not used in first implementation). **NOT IMPLEMENTED** as a lab. Capstone may list HITL as NOT PROVEN. Do not fake an approval UI.
