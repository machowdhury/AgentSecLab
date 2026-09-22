# AgentSec security knowledge graph (Phase 16C)

**Status:** DESIGN. Concepts AgentSec actually teaches today, from labs not slogans.  
**Do not add a concept merely because OWASP or ATLAS names it.**

Companion: `docs/AGENTSEC_SECURITY_REASONING_MODEL.md` (16A chain). This file is the concept graph after 16B.

---

## Nodes

SOURCE · TRUST BOUNDARY · UNTRUSTED DATA · INSTRUCTION · REQUEST · IDENTITY CLAIM · DELEGATION CLAIM · TASK · GOAL · TOOL · SCOPE · RESOURCE · AUTHORIZATION · EXECUTION · MEMORY · RAG · PROVENANCE · CONTROL · PDP · TELEMETRY · OBSERVATION · DETECTION · HUNT · EVIDENCE · MITIGATION · RETEST

---

## Encoded inequalities (must remain explicit)

| Relation | Primary labs | Teaching |
|----------|--------------|----------|
| DATA ≠ AUTHORITY | RAG, Memory, MCP-005, catalog, capstone | Explicit, repeated |
| REQUEST ≠ GRANT | MCP-001, capstone | Explicit |
| IDENTITY CLAIM ≠ AUTHENTICATION | Identity | Explicit |
| DELEGATION CLAIM ≠ AUTHORIZATION | Identity, MCP-006 (deputy contrast) | Explicit |
| PROVENANCE ≠ TRUST | RAG, Memory, capstone | Explicit |
| STORED ≠ TRUSTED | Memory, capstone | Explicit |
| OBSERVE ≠ ALLOW | RAG, Memory, Identity, catalog, result, capstone | Explicit, repeated |
| ALLOW ≠ EXECUTION | MCP-001 family, capstone | Explicit |
| AUTHORIZED TOOL ≠ AUTHORIZED GOAL | Goal | Explicit |
| MISSING EVENT ≠ PREVENTION | All LIVE PROVE tabs | Explicit |
| ANOMALY ≠ INCIDENT | DETECT tabs | Explicit |
| SPLUNK ≠ ENFORCEMENT | All LIVE manifests | Explicit, repeated |
| REPLAY ≠ LIVE | Investigate dropdowns vs Attack Service | Explicit in LIVE labs; weak on Home |
| ATTACK SUCCESS ≠ UNIVERSAL VULNERABILITY | All ATTACK prediction blocks | Explicit |
| RETEST SUCCESS ≠ UNIVERSAL SECURITY | All RETEST prediction blocks | Explicit |
| SCANNER FINDING ≠ AUTHORIZATION | Scanner workshop | Explicit |
| LEARNING METADATA ≠ POLICY | manifests `not_authorization` | Explicit |

---

## Coverage by concept

| Concept | Taught | How | Notes |
|---------|--------|-----|-------|
| SOURCE | Explicit | PI input, RAG document, memory body, instruction, claim | Capstone fuses retrieve source |
| TRUST BOUNDARY | Explicit | Every LEARN tab | Names differ by lab |
| UNTRUSTED DATA | Explicit | `untrusted_data` / `untrusted_instruction` / `untrusted_claim` | Untrusted ≠ malicious |
| INSTRUCTION | Explicit | PI + Goal | Capstone does **not** fail on instruction |
| REQUEST | Explicit | MCP tool/scope/resource | |
| IDENTITY CLAIM | Explicit | Identity LIVE | Capstone: rule **out** |
| DELEGATION CLAIM | Explicit | Identity LIVE; MCP-006 REPLAY | Different mechanisms |
| TASK / GOAL | Explicit | Goal LIVE | Capstone: rule **out** |
| TOOL / SCOPE / RESOURCE | Explicit LIVE (tool); REPLAY (scope/resource) | MCP-001 LIVE; 003/004 REPLAY | Scope/resource not LIVE-launched |
| AUTHORIZATION | Explicit | CTRL-* decision rows | |
| EXECUTION | Explicit | Handler / LLM counts | Authoritative |
| MEMORY | Explicit | Memory LIVE + capstone | |
| RAG | Explicit | RAG LIVE + capstone | |
| PROVENANCE | Explicit | document/memory ids, hashes | |
| CONTROL vs PDP | Explicit | Classifier OBSERVE vs MCP/INPUT/GOAL | Identity/RAG/Memory classify; they do not grant tools |
| TELEMETRY | Explicit | schema 1.9.0 events | |
| OBSERVATION | Explicit | Splunk copy | |
| DETECTION | Explicit (narrow) | DET-MCP-001 only | |
| HUNT | Explicit | Q-* Path A/B | |
| EVIDENCE / PROOF classes | Explicit | PROVE tabs; capstone CAP-I16 | |
| MITIGATION | Explicit | RETEST ExperimentContext, not sanitizer theater | |
| RETEST | Explicit | Equivalent adversarial bytes | |

### Taught once vs repeatedly

**Repeated (keep):** DATA ≠ AUTHORITY; REQUEST ≠ GRANT; OBSERVE ≠ ALLOW; ALLOW ≠ EXECUTION; SPLUNK ≠ ENFORCEMENT; missing ≠ prevention; BASELINE ≠ SAFE.

**Once then reused:** Fail-open labeled overlay (introduced PI/MCP, reused). Two-run memory. Goal vs MCP dual decision. Identity NOT PROVEN authentication.

**Implicit only (gap):** What an LLM/agent/MCP **is** before Lab 1. LIVE vs REPLAY as a Home-level badge. Capstone’s three-run shape is explicit in the lab, implicit on Home (Home omits it).

**Not taught as a lab:** Real authentication, HITL gating, tool-output poisoning as a distinct LIVE packet (MCP-005 is the closest REPLAY), multi-agent transport, secrets theft, sandbox escape, MLTK.

---

## Chain the learner must be able to reconstruct

```text
SOURCE → PROVENANCE → TRUST BOUNDARY → INFLUENCE → REQUEST
      → AUTHORITY → POLICY DECISION → EXECUTION
      → TELEMETRY → SPLUNK → EVIDENCE / PROOF
```

Capstone is the first LIVE lab that requires the full chain across **two influence planes** (RAG then memory) without collapsing them into one “attack result” event.
