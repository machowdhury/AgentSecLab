# AgentSec curriculum coverage matrix

**Status:** DESIGN inventory from repository artifacts (2026-09-20, Phase 16A).  
**Evidence:** OBSERVED source tree + DOCUMENTED phase validation reports.  
**Do not invent LIVE, Path A/B, or detectors.**  
**Do not start Phase 16B from this file.**

Legend: **IMPLEMENTED** / **LIVE VALIDATED** / **REPLAY ONLY** / **DESIGNED** / **PARTIALLY SUPPORTED** / **NOT IMPLEMENTED** / **OUT OF SCOPE** / **FUTURE**.

PDP means the control that can ALLOW/DENY the dangerous operation. OBSERVE classifiers are not PDPs.

---

## Six LIVE domains

### LAB-PI-001 — Direct Prompt Injection

| Field | Value |
|-------|-------|
| Level (16A path) | 1 Foundations |
| Attack | ATK-001 BASELINE, ATK-002 ATTACK/RETEST |
| Security concept | Untrusted user text cannot silently become policy |
| Trust boundary | Input string → CTRL-INPUT-001 → governed LLM |
| Source | Browser / Attack Service frozen loan text |
| Provenance | `agentsec.principal.id` lab identifier |
| Trust classification | Untrusted input (not a document trust label) |
| Influence type | Direct instruction-shaped prompt |
| Requested action | Loan decision / LLM call |
| Authority source | Server-owned profile + CTRL-INPUT-001 |
| Security control | CTRL-INPUT-001 |
| PDP | CTRL-INPUT-001 |
| Decision | DENY defended RETEST; ALLOW labeled vulnerable ATTACK |
| Execution evidence | Runtime LLM call count; `llm.*` events |
| Telemetry | `index=agentsec_telemetry` `sourcetype=otel:agentic:json` |
| Splunk hunt | Q-RUN-EVENTS, Q-CONTROL-DECISION, Q-LLM-EXECUTED, Q-LLM-AFTER-DENY |
| Detector | NONE JUSTIFIED |
| LIVE / ATTACK / RETEST | LIVE VALIDATED (14D pair) |
| Path A / Path B | IMPLEMENTED (`investigations.json`) |
| COMPARE / PROVE | IMPLEMENTED (Studio + Search handoff) |
| Framework mapping | ATLAS `AML.T0054` on ATK-002 (DIRECT, existing `technique_id_for`) |
| Prerequisites | Home / orientation |
| Difficulty | GUIDED beginner |
| Expected outcome | Predict, launch, copy run.id, prove control-before-LLM, state Splunk limitations |

### LAB-MCP-001 — MCP Tool Authorization

| Field | Value |
|-------|-------|
| Level | 1 Foundations |
| Attack | MCP-001 granted BASELINE; MCP-002 ungranted ATTACK/RETEST |
| Security concept | Request ≠ grant |
| Trust boundary | Tool request → CTRL-MCP-001 → handler |
| Source | Closed MCP invoke specimen |
| Provenance | Principal + agent ids |
| Trust classification | n/a (grant anatomy, not content trust) |
| Influence type | Direct tool request |
| Requested action | ATTACK: `lookup_customer_tier` / `customer:read` |
| Authority source | `coded_policy()` allowed_tools / scopes |
| Security control | CTRL-MCP-001 |
| PDP | CTRL-MCP-001 |
| Decision | ATTACK overlay ALLOW; RETEST DENY `tool_not_granted` |
| Execution evidence | Handler invoke count; mcp.started / completed |
| Telemetry | MCP + control events, schema 1.9.0 |
| Splunk hunt | Q-MCP-WHO, Q-MCP-AUTHZ, Q-MCP-TOOL, Q-MCP-EXECUTED, Q-MCP-AFTER-DENY |
| Detector | DET-MCP-001 disabled (DENY-then-start). ATTACK is ALLOW so 0 rows. 0 ≠ SAFE |
| LIVE / ATTACK / RETEST | LIVE VALIDATED (14E pair) |
| Path A / Path B | IMPLEMENTED |
| COMPARE / PROVE | IMPLEMENTED |
| Framework mapping | ATLAS `AML.T0050` on MCP-002 (DIRECT, existing mapping) |
| Prerequisites | PI-001 recommended |
| Difficulty | GUIDED |
| Expected outcome | Reconstruct request vs grant vs execution |

### LAB-RAG-CONTEXT — Retrieved Context / RAG

| Field | Value |
|-------|-------|
| Level | 2 Context & authority |
| Attack | RAG-001 malicious fixture |
| Security concept | Retrieved content ≠ authority |
| Trust boundary | Retrieved text → CTRL-RAG-CONTEXT-001 OBSERVE → follow-on tool request → CTRL-MCP-001 |
| Source | Server-owned document fixture |
| Provenance | `rag.document.id` + content.hash |
| Trust classification | untrusted retrieval (label, not malice) |
| Influence type | Indirect (document → request) |
| Requested action | `lookup_customer_tier` |
| Authority source | coded_policy(); overlay on ATTACK only |
| Security control | CTRL-RAG-CONTEXT-001 (OBSERVE) |
| PDP | CTRL-MCP-001 |
| Decision | IDENTITY-like: OBSERVE both; MCP ALLOW overlay vs DENY |
| Execution evidence | lookup_customer_tier handler count |
| Telemetry | RAG + MCP fields |
| Splunk hunt | Q-RAG-CONTEXT-AUTHORITY + Q-MCP-* |
| Detector | NONE JUSTIFIED (no DET-RAG) |
| LIVE / ATTACK / RETEST | LIVE VALIDATED (15B pair) |
| Path A / Path B | IMPLEMENTED |
| COMPARE / PROVE | IMPLEMENTED |
| Framework mapping | RELATED OWASP LLM indirect prompt / retrieved-context; no new ATLAS id invented |
| Prerequisites | MCP-001 |
| Difficulty | GUIDED |
| Expected outcome | OBSERVE ≠ ALLOW; document did not grant the tool |

### LAB-MEMORY-001 — Persistent Agent Memory

| Field | Value |
|-------|-------|
| Level | 2 |
| Attack | MEMORY-001 malicious fixture |
| Security concept | Stored memory ≠ trusted instruction |
| Trust boundary | Write → store; later recall → OBSERVE → follow-on MCP |
| Source | Closed memory body |
| Provenance | memory.id + content.hash; recall `source_run_id` |
| Trust classification | untrusted memory |
| Influence type | Cross-run persistence |
| Requested action | lookup_customer_tier on recall |
| Authority source | coded_policy(); overlay per recall run, not stored |
| Security control | CTRL-MEMORY-CONTEXT-001 OBSERVE |
| PDP | CTRL-MCP-001 |
| Decision | OBSERVE both; MCP ALLOW overlay vs DENY |
| Execution evidence | Two run.ids; handler count on recall |
| Telemetry | memory.* + MCP |
| Splunk hunt | Q-MEMORY-CONTEXT-AUTHORITY + Q-MCP-* |
| Detector | NONE JUSTIFIED |
| LIVE / ATTACK / RETEST | LIVE VALIDATED (15C; WRITE+RECALL pair) |
| Path A / Path B | IMPLEMENTED |
| COMPARE / PROVE | IMPLEMENTED |
| Framework mapping | RELATED persistence / poisoning; UNMAPPED as a single ATLAS id in emitters (`technique_id_for` has no MEMORY-001) |
| Prerequisites | RAG or MCP-001 |
| Difficulty | GUIDED (two UUIDs) |
| Expected outcome | Cross-run correlation; memory did not mint a grant |

### LAB-AGENT-GOAL-INTEGRITY-001 — Goal / Instruction Integrity

| Field | Value |
|-------|-------|
| Level | 2 |
| Attack | GOAL-001 malicious instruction |
| Security concept | Authorized tool ≠ authorized goal |
| Trust boundary | Server-owned task vs untrusted instruction vs proposed action |
| Source | Closed instruction fixture |
| Provenance | task fingerprint + instruction hash |
| Trust classification | untrusted_instruction (not malice) |
| Influence type | Task expansion proposal |
| Requested action | Proposed `extract_full_policy`; granted tool remains `lookup_policy` |
| Authority source | Task contract + coded_policy() |
| Security control | CTRL-GOAL-INTEGRITY-001 |
| PDP | Goal control for task; CTRL-MCP-001 still ALLOWs lookup_policy on ATTACK **and** RETEST |
| Decision | ATTACK GOAL OBSERVE overlay; RETEST GOAL DENY; MCP ALLOW both |
| Execution evidence | wrong-goal vs in-task handler counts (runtime authoritative) |
| Telemetry | goal.* + MCP |
| Splunk hunt | Q-GOAL-INTEGRITY-AUTHORITY + Q-MCP-* |
| Detector | NONE JUSTIFIED |
| LIVE / ATTACK / RETEST | LIVE VALIDATED (15D) |
| Path A / Path B | IMPLEMENTED |
| COMPARE / PROVE | IMPLEMENTED |
| Framework mapping | RELATED goal hijacking / excessive agency; no invented ATLAS id |
| Prerequisites | MCP-001 |
| Difficulty | GUIDED (two PDPs, same tool ALLOW) |
| Expected outcome | MCP ALLOW did not authorize the goal |

### LAB-AGENT-DELEGATION-001 — Identity / Delegation Claims

| Field | Value |
|-------|-------|
| Level | 2 |
| Attack | A2A-001 privileged claim |
| Security concept | Identity/delegation claim ≠ authentication or grant |
| Trust boundary | Claim → CTRL-IDENTITY-001 OBSERVE → tool request → CTRL-MCP-001 |
| Source | Closed claim fixture (HTTP never accepts A2A body) |
| Provenance | principal / caller / callee **identifiers** |
| Trust classification | untrusted_claim |
| Influence type | Claimed customer:read / lookup_customer_tier |
| Requested action | lookup_customer_tier / customer:read / cust-001 |
| Authority source | coded_policy() for both agents: lookup_policy only |
| Security control | CTRL-IDENTITY-001 OBSERVE |
| PDP | CTRL-MCP-001 |
| Decision | IDENTITY OBSERVE both; MCP ALLOW overlay vs DENY |
| Execution evidence | lookup_customer_tier handler count |
| Telemetry | identity.* + MCP; WHO AUTHENTICATED = NOT PROVEN |
| Splunk hunt | Q-AGENT-DELEGATION-AUTHORITY + Q-MCP-* |
| Detector | NONE JUSTIFIED (no DET-A2A) |
| LIVE / ATTACK / RETEST | LIVE VALIDATED (15E) |
| Path A / Path B | IMPLEMENTED |
| COMPARE / PROVE | IMPLEMENTED |
| Framework mapping | RELATED agent impersonation / confused deputy **pattern**; real A2A NOT IMPLEMENTED |
| Prerequisites | MCP-001 |
| Difficulty | GUIDED |
| Expected outcome | A+B ≠ new authority; caller id ≠ authentication |

---

## REPLAY workshops (implemented Studio, no Attack Service LIVE loop)

| Lab | Concept | PDP / classifier | LIVE launcher | Path A/B loop | Detector |
|-----|---------|------------------|---------------|---------------|----------|
| LAB-MCP-003 | Scope grant | CTRL-MCP-001 | NOT IMPLEMENTED | PARTIALLY (workshop, not 14E investigations.json) | DET-MCP-001 reuse |
| LAB-MCP-004 | Resource grant | CTRL-MCP-001 | NOT IMPLEMENTED | PARTIALLY | DET-MCP-001 reuse |
| LAB-MCP-005 | Tool result ≠ authority | CTRL-MCP-RESULT-001 OBSERVE; MCP PDP | NOT IMPLEMENTED | PARTIALLY | NONE JUSTIFIED |
| LAB-MCP-006 | Confused deputy | CTRL-DELEGATION-001 then MCP | NOT IMPLEMENTED | PARTIALLY | NONE JUSTIFIED |
| LAB-MCP-CATALOG | Description ≠ grant | CTRL-MCP-METADATA-001 OBSERVE | NOT IMPLEMENTED | PARTIALLY | CANDIDATE later (not shipped) |
| LAB-SCANNER-RUNTIME-EVIDENCE | Scanner ≠ authorization | none (imported evidence) | NOT APPLICABLE | PARTIALLY | NONE JUSTIFIED |

These remain **valuable**. They are not LIVE purple-team loops. Do not relabel REPLAY as LIVE.

---

## Capstone

| Field | Value |
|-------|-------|
| LAB-AGENTSEC-CAPSTONE-001 | DESIGNED only |
| Studio / launcher / runtime composition | NOT IMPLEMENTED |
| Detector | Must not invent DET-CAPSTONE |

---

## Shared gaps (all current labs)

HITL `REQUIRE_APPROVAL`: schema vocabulary **IMPLEMENTED**; no learner lab **NOT IMPLEMENTED**.  
Real A2A transport / OAuth / OIDC / JWT / SPIFFE: **NOT IMPLEMENTED**.  
MLTK / behavioral analytics: **FUTURE** (DETECT tabs say so).  
Progress persistence (LEARNED/ATTACKED/…): **NOT IMPLEMENTED** (honest; no fake completion store).
