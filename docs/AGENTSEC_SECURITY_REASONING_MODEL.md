# AgentSec security reasoning model

**Status:** DESIGN. Phase 15A defined the chain. **Phase 16A** refines provenance / influence / proof language against the six LIVE labs.  
**Does not change runtime policy, schema, or detectors.**  
**Learning metadata is not authorization.**  
**Do not start Phase 16B from this file.**

## 16A refined chain

Compare the 15A chain with repository semantics after 15B–15E. Added stages that labs already emit but 15A folded into “DATA / INSTRUCTION / REQUEST / CLAIM”:

```text
SOURCE
  ↓
PROVENANCE          (where the bytes came from; not a trust decision)
  ↓
TRUST BOUNDARY
  ↓
INFLUENCE           (how untrusted bytes shaped a later request or task)
  ↓
REQUEST / PROPOSED ACTION / CLAIM
  ↓
AUTHORITY           (server-owned coded grants — not the claim)
  ↓
POLICY DECISION     (runtime PDP or OBSERVE classifier)
  ↓
EXECUTION           (handler / LLM start — runtime counts authoritative)
  ↓
TELEMETRY           (OTel → collector → HEC)
  ↓
SPLUNK INVESTIGATION
  ↓
EVIDENCE / PROOF    (SUPPORTED / CORROBORATED / NOT PROVEN / INCORRECT)
```

15A AUTHORIZATION remains the PDP step. 16A splits **provenance** (attribution of origin) from **trust** (whether the system may treat the bytes as instruction) from **authority** (whether a tool/scope/resource is granted). Identity LIVE (15E) made that split mandatory: `caller_agent_id` is provenance/attribution, not authentication, and not a grant.

The 15A chain below is still valid. Use the 16A chain when teaching Level 2 LIVE labs and the capstone.

## Progressive inequalities (do not dump all at once)

Teach in this order (matches LIVE labs):

1. LAB-PI-001: REQUEST ≠ GRANT is not yet the point; **untrusted input ≠ policy**, ALLOW ≠ EXECUTION, SPLUNK ≠ ENFORCEMENT, HEC ACCEPTANCE ≠ SEARCHABLE EVIDENCE, MISSING EVENT ≠ PREVENTION, BASELINE ≠ SAFE, RETEST ≠ UNIVERSAL SECURITY.
2. LAB-MCP-001: REQUEST ≠ GRANT, ALLOW ≠ EXECUTION, DENY ≠ PROOF OF NON-EXECUTION.
3. LAB-RAG-CONTEXT: PROVENANCE ≠ TRUST, RETRIEVED CONTENT ≠ AUTHORITY, OBSERVE ≠ ALLOW.
4. LAB-MEMORY-001: STORED MEMORY ≠ TRUSTED INSTRUCTION, persistence ≠ trust.
5. LAB-AGENT-GOAL-INTEGRITY-001: AUTHORIZED TOOL ≠ AUTHORIZED GOAL, GOAL DENY ≠ MCP DENY.
6. LAB-AGENT-DELEGATION-001: IDENTITY CLAIM ≠ AUTHENTICATION, CALLER ID ≠ GRANT, DELEGATION CLAIM ≠ AUTHORIZATION.

Always: LEARNING METADATA ≠ POLICY. ATTACK SERVICE ≠ PDP. STUDIO = SYLLABUS. SEARCH = NOTEBOOK. RUNTIME CONTROL = ENFORCEMENT.

ANOMALY ≠ INCIDENT is DETECT-tab language (goal/identity/RAG), not a first-lab inequality.

---

## The reusable chain (Phase 15A, preserved)

## The reusable chain

Every AgentSec lab is a variation of this chain. Not every lab has every stage.

```text
SOURCE
  ↓
TRUST BOUNDARY
  ↓
DATA / INSTRUCTION / REQUEST / CLAIM
  ↓
AUTHORIZATION  (runtime PDP, if this domain has one)
  ↓
EXECUTION      (handler start, if authorized)
  ↓
TELEMETRY      (OpenTelemetry → HEC)
  ↓
SPLUNK INVESTIGATION
  ↓
HUNT / DETECTION / CONTEXT CLASSIFICATION
  ↓
DEFENSE        (profile / control, not Splunk)
  ↓
RETEST
  ↓
PROOF          (with named limitations)
```

The learner’s job is to name **where the trust boundary sits** in this system, **what crossed it**, and **what was allowed to become authority**.

## What the stages are (and are not)

| Stage | Teaching meaning | Common error |
|-------|------------------|--------------|
| SOURCE | Who or what produced the bytes | Treating “user” as always trusted |
| TRUST BOUNDARY | Where trust must be re-evaluated | Assuming the model is the boundary |
| DATA | Content that may influence a request | Treating data as a grant |
| INSTRUCTION | Intended task / system policy | Treating retrieved text as instruction |
| REQUEST | What the agent asked to do | Treating request as authorization |
| CLAIM | Identity or delegation assertion | Treating claim as authentication or grant |
| AUTHORIZATION | Server-owned decision | Treating Splunk or Studio as PDP |
| EXECUTION | Handler actually started | Treating ALLOW as execution |
| TELEMETRY | Copy of what happened | Treating HEC 200 as searchable evidence |
| HUNT | Analyst-driven reconstruction | Treating hunt SPL as an alert |
| DETECTION | Repeatable notable-worthy condition | Manufacturing DET-* per lab |
| DEFENSE | Runtime control / profile | “Splunk blocked it” |
| RETEST | Equivalent adversarial input, different profile | Different payload counted as proof |
| PROOF | Claims the evidence actually supports | Universal resistance, prevention from absence |

## Domain map — where the boundary actually is

| Domain | Source | What crosses | What must not become authority | Enforcement |
|--------|--------|--------------|--------------------------------|-------------|
| Direct input | Untrusted user text | Instruction-shaped prompt | Extra authority / “ignore policy” | CTRL-INPUT-001 before LLM |
| Tool request | Agent tool call | Tool / scope / resource request | Ungranted tool/scope/resource | CTRL-MCP-001 before handler |
| Tool result | Prior authorized output | Result text | Follow-on grant | CTRL-MCP-001; RESULT-001 classifies only |
| Catalog metadata | Tool description | Description text | Grant / next-tool authority | CTRL-MCP-001; METADATA-001 classifies only |
| Scanner finding | Imported scan | Finding / severity | Runtime grant | None — scanners do not authorize |
| RAG | Retrieved document | Retrieved text | Privileged tool grant | CTRL-MCP-001; RAG-001 classifies only |
| Memory | Recalled note | Recalled text | Trusted instruction / grant | CTRL-MCP-001; MEMORY-001 classifies only |
| Identity | Delegation request | Identity / delegation claims | Authenticated identity or grant | CTRL-MCP-001; IDENTITY-001 classifies only |
| Confused deputy | Caller → deputy | Ambient deputy grants | Caller-delegated authority | CTRL-DELEGATION-001 then CTRL-MCP-001 |
| Goal | Task / instruction | Goal influence | Task authority | CTRL-GOAL-INTEGRITY-001 then CTRL-MCP-001 |

## Core security inequalities

Only inequalities that existing AgentSec design actually teaches.

| Inequality | First lab | Reinforced | Invariant | Control | Learner misconception |
|------------|-----------|------------|-----------|---------|------------------------|
| REQUEST ≠ GRANT | LAB-MCP-001 | 003, 004, 005, catalog, RAG, memory, identity, goal | INV-001 | CTRL-MCP-001 | “The agent asked for it, so it was allowed.” |
| OBSERVE ≠ ALLOW | LAB-MCP-CATALOG | RAG, memory, identity, goal (OBSERVE classifiers) | INV-002 / INV-003 / INV-005 | METADATA / RAG / MEMORY / IDENTITY `*-001` | “OBSERVE means the content is permitted.” |
| ALLOW ≠ EXECUTION | LAB-PI-001 | MCP-001 family | INV-007 | INPUT-001 / MCP-001 | “ALLOW row means the handler ran.” |
| DENY ≠ AUTOMATIC PROOF OF NON-EXECUTION | LAB-PI-001 | MCP-001 (DET-MCP-001 teaches the exception) | INV-007 | INPUT-001 / MCP-001 | “A DENY row proves the dangerous op never ran.” |
| RETRIEVED CONTENT ≠ AUTHORITY | LAB-RAG-CONTEXT | catalog, result, memory | INV-002 | CTRL-RAG-CONTEXT-001 + MCP-001 | “The knowledge base said to call the tool.” |
| MEMORY ≠ TRUSTED INSTRUCTION | LAB-MEMORY-001 | — | INV-003 | CTRL-MEMORY-CONTEXT-001 + MCP-001 | “If the agent remembered it, it is policy.” |
| TRUST ≠ AUTHORITY | LAB-RAG-CONTEXT | memory, identity | INV-002 | classifiers OBSERVE + MCP-001 | “If we labeled it untrusted we must have denied the tool.” |
| CALLER ID ≠ GRANT | LAB-AGENT-DELEGATION-001 | MCP-006 | INV-001 / INV-005 | IDENTITY-001 then MCP-001 | “The JSON named the caller, so the callee inherited power.” |
| IDENTITY CLAIM ≠ AUTHENTICATION | LAB-AGENT-DELEGATION-001 | — | INV-005 | CTRL-IDENTITY-001 | “WHO AUTHENTICATED is proven by caller_agent_id.” |
| BASELINE ≠ SAFE | LAB-PI-001 | all LIVE labs | — | — | “BASELINE had no attack, so the system is safe.” |
| DELEGATION CLAIM ≠ DELEGATED AUTHORITY | LAB-AGENT-DELEGATION-001 | MCP-006 (deputy ambient) | INV-001 | IDENTITY-001 / DELEGATION-001 then MCP-001 | “Agent A asked Agent B, so B may use A’s grants.” |
| AUTHORIZED TOOL ≠ AUTHORIZED GOAL | LAB-AGENT-GOAL-INTEGRITY-001 | — | INV-006 | CTRL-GOAL-INTEGRITY-001 | “lookup_policy is granted, so any use is fine.” |
| AUTHORIZED TOOL ≠ AUTHORITATIVE RESULT | LAB-MCP-005 | catalog | INV-002 | CTRL-MCP-RESULT-001 | “The tool was allowed, so its output is trusted as policy.” |
| METADATA ≠ AUTHORITY | LAB-MCP-CATALOG | scanner | INV-002 | CTRL-MCP-METADATA-001 | “The catalog description is the grant.” |
| SCANNER FINDING ≠ AUTHORIZATION | LAB-SCANNER-RUNTIME-EVIDENCE | catalog | INV-002 | none (scanner) | “The scanner approved the tool.” |
| UNTRUSTED ≠ MALICIOUS | LAB-PI-001 | RAG, memory | INV-002 | classifiers OBSERVE | “If it is untrusted it must be an attack.” |
| ANOMALY ≠ INCIDENT | LAB-AGENT-GOAL-INTEGRITY-001 | future MLTK | — | none | “Rare sequence = confirmed compromise.” |
| HUNT ≠ DETECTION | LAB-MCP-001 | every later lab | — | DET-MCP-001 only as exception | “My Q-* search is a detector.” |
| ATTACK ≠ ALERT | LAB-PI-001 | MCP-005, RAG | — | NONE JUSTIFIED on several labs | “Every attack lab needs DET-*.” |
| HEC ACCEPTANCE ≠ SEARCHABLE EVIDENCE | LAB-PI-001 | all LIVE labs | INV-007 | — | “200 from HEC means I can hunt it now.” |
| MISSING SPLUNK EVENT ≠ PREVENTION | LAB-PI-001 | all | INV-007 | — | “No row means the control blocked it.” |
| SPLUNK ≠ ENFORCEMENT | LAB-PI-001 | all | — | — | “Splunk authorized / blocked the tool.” |
| LEARNING METADATA ≠ POLICY | 14C/14E | all migrated labs | — | — | “The lesson YAML is the grant list.” |
| NORMAL ≠ SAFE | LAB-MCP-CATALOG / scanner | — | — | — | “NORMAL classification means the artifact is trusted.” |
| RETEST ≠ UNIVERSAL RESISTANCE | LAB-PI-001 | MCP-001 | — | profile change | “One RETEST DENY means the control always holds.” |
| TOOL GRANT ≠ SCOPE GRANT ≠ RESOURCE GRANT | LAB-MCP-003 then 004 | MCP-001 | INV-001 | CTRL-MCP-001 | “If the tool is granted, every argument is granted.” |
| DEPUTY AUTHORITY ≠ CALLER AUTHORITY | LAB-MCP-006 | identity lab | INV-001 | CTRL-DELEGATION-001 | “The deputy can do it, so the caller authorized it.” |
| GOAL DENY ≠ MCP DENY | LAB-AGENT-GOAL-INTEGRITY-001 | — | INV-006 | GOAL then MCP | “Task DENY is the same event as tool DENY.” |

Inequalities **not** claimed as current curriculum because the repository does not yet teach them as labs: live OAuth token binding, rug-pull catalog mutation as LIVE, ML-granted authority (explicitly forbidden, not a lab).

## Platform inequalities (locked 14E)

```text
STUDIO ≠ ENFORCEMENT
SEARCH ≠ ENFORCEMENT
ATTACK SERVICE ≠ POLICY STORE   (it launches frozen ExperimentDefinitions)
RUNTIME = ENFORCEMENT
SPLUNK = EVIDENCE COPY
```

## How a learner should talk about a finding

1. Name the **source**.
2. Name the **trust boundary**.
3. Classify the crossing as **data, instruction, request, or claim**.
4. Name the **PDP** (or say “classify-only / no PDP”).
5. State **ALLOW / DENY / OBSERVE / ERROR** and whether **execution started**.
6. State what Splunk **corroborates** vs what only runtime can **prove**.
7. State **limitations** (HEC lag, LLM nondeterminism, replay vs live, equivalent-input check).
