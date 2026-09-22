# AgentSec curriculum gap analysis

**Status:** DESIGN (Phase 16A).  
**Do not automatically turn a gap into a new lab.**  
**Do not start Phase 16B from this file.**

Classes:

| Class | Meaning |
|-------|---------|
| A | MUST TEACH BEFORE CAPSTONE (existing REPLAY or LIVE is enough unless noted) |
| B | CAN BE TAUGHT INSIDE CAPSTONE (as a reasoning question, not a new product) |
| C | ADVANCED / LEVEL 3 after capstone |
| D | FUTURE PRODUCT RESEARCH |
| E | OUT OF SCOPE for AgentSec the learning range |

Research first: several “gaps” are already labs.

---

## Already represented (not gaps)

| Topic | Where | Notes |
|-------|-------|-------|
| Direct PI | LAB-PI-001 LIVE | |
| Tool allow-list | LAB-MCP-001 LIVE | |
| Scope / resource | MCP-003 / 004 REPLAY | Missing LIVE launcher, not missing teaching |
| Result trust | MCP-005 REPLAY | |
| Confused deputy | MCP-006 REPLAY | Not the identity lab |
| Catalog poisoning | LAB-MCP-CATALOG REPLAY | |
| Scanner ≠ authz | Scanner workshop REPLAY | |
| RAG | LAB-RAG-CONTEXT LIVE | |
| Memory | LAB-MEMORY-001 LIVE | |
| Goal integrity | Goal LIVE | |
| Identity claims | Delegation LIVE | Not cryptographic identity |
| Hunt vs detection | DETECT tabs | DET-MCP-001 only |

---

## Prioritized gaps

| Gap | Already in repo? | Class | Recommendation |
|-----|------------------|-------|----------------|
| MCP-003/004 LIVE Attack Service | Workshop yes; launcher no | A (as **REPLAY completion**) | Learner should finish 003/004 Studio REPLAY before capstone. Do **not** require a new LIVE migration before capstone. |
| MCP-005 / catalog / scanner LIVE loop | Workshops yes | A (REPLAY) | Same: complete as REPLAY so INV-002 is not only RAG |
| MCP-006 REPLAY completion | Workshop yes | A | Required so identity ≠ confused deputy |
| Cross-domain fused experiment | Memory already two-run; no RAG→memory→MCP sequence | B | Capstone LIVE target (16B+). Until then, REPLAY packet of existing pairs |
| Multi-agent workflows | Identity in-process only | B / D | Capstone checks identity plane; real multi-agent D |
| Real A2A | Claims lab only | D | Explicit 15E stop |
| Authentication (OAuth/OIDC/JWT/SPIFFE) | NOT IMPLEMENTED | D | Do not theater it in capstone; keep NOT PROVEN |
| Human approval / HITL | Enum only | C | Optional later lab; capstone lists as NOT PROVEN |
| Tool chaining / multi-hop execution | Sequential HTTP in design only | B | Capstone sequence is the teaching; not a new orchestrator framework |
| Dynamic tool discovery | Catalog workshop REPLAY | A REPLAY / C LIVE | |
| MCP catalog **runtime mutation** (rug-pull) | Research; not a lab | D | |
| Secrets / exfiltration | NOT IMPLEMENTED | E / D | Range is a loan/policy demo; do not add real secret theft |
| Destructive actions / sandbox escape | NOT IMPLEMENTED | E | |
| Multi-tenant isolation | Attack Service states NOT MULTI-TENANT | E | |
| Vector databases | RAG is fixture retrieve | D | Embeddings optional; not INV-002 proof |
| Agent lifecycle / spawn | NOT IMPLEMENTED | D | |
| Behavioral analytics / MLTK | DETECT FUTURE panels | D | No MLTK from 16A |
| Attack campaign reconstruction | COMPARE is per-lab | B | Capstone investigation set |
| Privilege escalation beyond coded_policy overlay | Overlay is labeled lab fail-open | B | Teach overlay ≠ production IAM |
| Memory isolation between tenants | Single in-process store | C | Honest limitation |
| Model/tool provenance / AI BOM | Scanner imported evidence only | D | |
| Progress persistence (LEARNED/ATTACKED) | NOT IMPLEMENTED | C | No fake gamification store |
| Home as academy path vs workshop directory | DESIGNED 15A IA | C | Do not global-rewrite UI in 16A |

---

## Before capstone (class A checklist)

A learner should have:

1. LIVE: PI, MCP-001, RAG, Memory, Goal, Identity (the six).
2. REPLAY (Studio, honest labels): MCP-003, MCP-004, MCP-005, MCP-006, catalog, scanner.

Missing those REPLAY workshops is a **curriculum** gap, not a reason to delay capstone **design**. Capstone **implementation** (16B) may still proceed if the learner packet states REPLAY prerequisites.

## Must not become labs just to look complete

- DET-A2A, DET-RAG, DET-MEMORY, DET-GOAL, DET-CAPSTONE
- OAuth demo that sets `authenticated=true` without verification
- Kubernetes / Kafka “enterprise” scenery
- Fake HITL checkbox that does not gate the handler
