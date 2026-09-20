# AgentSec roadmap 2026

**Status:** Phase 8A DESIGN ONLY (historical snapshot in this file). Phase 8B–8E LAB-MCP-CATALOG completed separately. **Phase 9A DESIGN / RESEARCH ONLY** (scanner architecture). Phases **9B–9C** executed in dedicated reports (scanner static integrate + Splunk ingest). **Phase 9D DESIGN / ANALYSIS** (detection engineering; **DETECTION ANALYZED — NO NEW DETECTOR**). **Phase 9E VALIDATED** (scanner + runtime evidence workshop). **Phase 10A DESIGN / RESEARCH ONLY** (RAG / retrieved-context security). **Phase 10B IMPLEMENTED + LOCALLY VALIDATED** (LAB-RAG-001 runtime + schema 1.6.0). **Phase 10C VALIDATED** (LAB-RAG-001 Splunk; **DETECTION ANALYZED — NO NEW DETECTOR**). **Phase 10D DESIGN / ANALYSIS** (RAG detection engineering; **DETECTION ANALYZED — NO NEW DETECTOR**). **Phase 10E VALIDATED** (LAB-RAG-CONTEXT workshop). **Phase 11A DESIGN / RESEARCH ONLY** (agent memory security / INV-003). **Phase 11B IMPLEMENTED + LOCALLY VALIDATED** (LAB-MEMORY-001 runtime + schema 1.7.0). **Phase 11C VALIDATED** (LAB-MEMORY-001 Splunk; **DETECTION ANALYZED — NO NEW DETECTOR**). **Phase 11D DESIGN / ANALYSIS** (memory detection engineering; **DETECTION ANALYZED — NO NEW DETECTOR**). **Phase 11E VALIDATED** (LAB-MEMORY-001 workshop). This file does not authorize a detector, Agent Scan, rug-pull, live A2A transport, or Phase 12B.  
**Schema remains 1.4.0 until a later lab spec proposes otherwise.** Runtime emitters are **1.5.0** as of Phase 8C; 9A and **10A do not bump schema**. 10A records **SCHEMA BUMP JUSTIFIED** (proposed 1.6.0) for a later implementation phase.

Parents: `docs/AGENTSEC_EXPANSION_ARCHITECTURE.md`, `docs/AGENTSEC_LEARNING_ARCHITECTURE.md`.

Every future phase that touches SPL/KOs must include: *Apply the AgentSec Splunk engineering rule and run splunk-ko-review for all new or materially changed Splunk knowledge objects.*

---

## NEXT 2 PHASES

### Phase 8B — MCP catalog integrity / tool-description poisoning (DESIGN)

**Status:** DESIGN complete 2026-09-16. Runtime belongs to Phase 8C. Do **not** start Phase 8D from this file.

| Field | Content |
|-------|---------|
| **Security question** | Can attacker-controlled MCP tool **metadata** (description, schema text) cause a privileged follow-on that coded policy did not grant — and can we tell **scan findings** from **runtime ALLOW**? |
| **Attack concept** | EMERGING: tool-description poisoning (Invariant Labs class; OWASP ASI02 interface poison and/or ASI04 if the catalog is a malicious server). Not “MCP-007” by number. |
| **Control** | Catalog trust check **before** the model/tool planner consumes descriptions. Runtime CTRL-MCP-001 still governs execution. Scanner is **not** the control unless a tested pre-op caller exists. |
| **Telemetry** | Existing MCP events + (design) description hash / catalog version. Scanner JSON on a **separate sourcetype** if imported. No schema bump in 8B design if the first slice can use evidence files only. |
| **Splunk** | New hunt only after indexed field discovery. Question: scan verdict vs later `mcp.started` for the same tool name. Zero scan rows ≠ safe catalog. |
| **External tool** | CALL EXTERNALLY: Cisco mcp-scanner and/or Invariant mcp-scan against the **fixture** server. IMPORT OUTPUT labeled OBSERVED-cli. Default core: no cloud inspect API. |
| **Learning objective** | Tool catalogs are data (INV-002 extended). Supply-chain scan ≠ runtime authorization. |
| **Dependencies** | MCP-001–006 complete; Splunk KO governance. |
| **Risk** | Treating scanner FAIL as DENY; live-scanning public MCP servers; inventing Splunk fields. |
| **Complexity** | Medium. |

**Do not start Phase 8D automatically.**

### Phase 8C — LAB-MCP-CATALOG runtime (implementation of 8B)

**Status:** IMPLEMENTED + LOCALLY VALIDATED in Phase 8C. Schema **1.5.0**. Splunk **not** started.

Same security question as 8B. Runtime fixture, CTRL-MCP-METADATA-001 OBSERVE, per-run overlay, tests, local evidence. No SPL, Studio, scanner wire-up, or DET-MCP-CATALOG.

### Phase 9A — External agent-security scanner integration (DESIGN / RESEARCH)

**Status:** DESIGN complete 2026-09-16. **Do not start Phase 9B from this file.** Do **not** start Phase 8D from this historical 8A section (8D/8E completed in their own phases).

| Field | Content |
|-------|---------|
| **Security question** | How should AgentSec consume external AI/agent/MCP scanner findings as independent evidence without turning those tools into authorization engines? |
| **Attack concept** | N/A (architecture). Teaching property: SCANNER FINDING ≠ AUTHORIZATION DECISION. |
| **Control** | Unchanged. CTRL-MCP-001 and CTRL-MCP-METADATA-001 stay authoritative. Scanners must not become those controls. |
| **Telemetry** | Scanner output stays off `otel:agentic:json`. Future pack + candidate sourcetype `agentsec:scanner:finding`. No schema bump in 9A. |
| **Splunk** | Design only. Same index + separate sourcetype. No SPL, no invented fields, no detector. |
| **External tool** | First future INTEGRATE: Cisco mcp-scanner static YARA `--tools`. Second: Snyk Agent Scan comparison. Not executed in 9A. |
| **Learning objective** | Scan-predict vs runtime-observe. PASS ≠ trusted. FAIL ≠ DENY. Silence ≠ safe. |
| **Dependencies** | LAB-MCP-CATALOG 8A–8E complete. |
| **Risk** | Treating scanner FAIL as DENY; live stdio MCP; DefenseClaw-as-bank; schema/SPL from a design phase. |
| **Complexity** | Medium (research). 9B implementation is a later, smaller static-adapter slice. |

**Do not start Phase 9B automatically.** No rug-pull. No A2A.

### Phase 9D — Scanner + runtime detection engineering (DESIGN / ANALYSIS)

**Status:** ANALYSIS complete 2026-09-16. **DETECTION ANALYZED — NO NEW DETECTOR.** Do **not** start Phase 9E from this file.

| Field | Content |
|-------|---------|
| **Security question** | Which plane (artifact vs observation vs request vs authz vs execution) should a SOC detect, and is a new detector justified? |
| **Decision** | No DET-SCANNER. No DET-MCP-CATALOG. DET-MCP-001 unchanged (DENY-then-start only). Overlay reason REJECT as production. |
| **Splunk** | Existing Q-SCANNER / Q-MCP hunts sufficient. No new SPL, saved search, notable, or Studio. |
| **Next integrity problem** | Scan at T1 vs runtime catalog at T2 (rug-pull / `list_changed`) — **not implemented**. |

### Phase 9E — Scanner + runtime evidence workshop

**Status:** VALIDATED 2026-09-16. Learner-facing `ws_lab_scanner_runtime_evidence`. Do **not** start Phase 10, Agent Scan, rug-pull, or A2A from this **9E** section. Phase 10A RAG design is a separate named phase.

### Phase 10A — RAG / retrieved-context security (DESIGN / RESEARCH)

**Status:** DESIGN complete 2026-09-16. **Do not start Phase 10B from this file.**

| Field | Content |
|-------|---------|
| **Security question** | Can content retrieved from a knowledge source cause an agent to acquire or exercise authority that server-owned policy did not grant? |
| **Attack concept** | RAG-001: malicious retrieved document with synthetic `AGENT NOTE` → follow-on REQUEST for `lookup_customer_tier`. Indirect PI / retrieved-context injection. Not catalog poisoning. |
| **Control** | Planned CTRL-RAG-CONTEXT-001 OBSERVE `retrieved_context_is_data` + compose existing CTRL-MCP-001. Vulnerable: per-run overlay `vulnerable_profile_fail_open:retrieved_context_derived_authority` only. |
| **Telemetry** | Schema **1.5.0 insufficient** for honest RAG observation. SCHEMA BUMP JUSTIFIED (proposed 1.6.0) — **not implemented**. Reuse `content.hash` / `content.preview` when bound. |
| **Splunk** | Design questions only. No SPL. Q1–Q3/Q7–Q8 require new telemetry. Q5–Q6 supported by current MCP fields after 10B runs. No detector. |
| **Retrieval** | Deterministic local fixtures first. Embeddings optional later; not the INV-002 proof. |
| **Learning objective** | RETRIEVED CONTEXT IS DATA. Provenance ≠ trust. REQUEST ≠ GRANT. LLM compliance is not the invariant. |
| **Dependencies** | Scanner/catalog 8A–9E complete; INV-002 labs MCP-005 / catalog as pattern reuse, not copy. |
| **Risk** | Overloading RESULT-001; `trusted_document=true`; stochastic retrieval as proof; prompt-filter-as-control; starting 10B from this file. |
| **Complexity** | Medium (research). 10B is a later, smaller fixture-retriever slice. |

**Do not start Phase 10B automatically.** (Historical 10A gate. 10B completed in a dedicated named phase.) No Agent Scan. No rug-pull. No A2A. No memory poisoning.

### Phase 10B — LAB-RAG-001 runtime (IMPLEMENTED + LOCALLY VALIDATED)

**Status:** IMPLEMENTED + LOCALLY VALIDATED 2026-09-16. Schema **1.6.0**. `splunk.verified=false`. **Do not start Phase 10C from this file.**

| Field | Content |
|-------|---------|
| **Security question** | Can retrieved text authorize a tool the server did not grant? |
| **Result** | No in defended. Yes as labeled per-run overlay in ATTACK only. Global grants unchanged. |
| **Control** | CTRL-RAG-CONTEXT-001 OBSERVE `retrieved_context_is_data` for valid A/B/C. Follow-on CTRL-MCP-001. Overlay `vulnerable_profile_fail_open:retrieved_context_derived_authority`. |
| **Telemetry** | Schema **1.6.0** implemented. Reuse `content.hash` / `content.preview`. |
| **Splunk** | Not attempted. No SPL. No detector. No Studio. |
| **Evidence** | A `ec141d70-e664-40a4-b37a-2c9d1cd625ca`; B `dc3173b8-102c-4d4e-aad4-91c101e9cb76`; C `10d042c6-986e-4bf3-b102-6cf26a7e5fcf`. |
| **Risk remaining** | Starting 10C without live field discovery; treating OBSERVE as ALLOW; treating missing Splunk rows as proof. |

**Do not start Phase 10C automatically.** (Historical 10B gate. 10C completed in a dedicated named phase.)

### Phase 10C — LAB-RAG-001 Splunk (VALIDATED)

**Status:** VALIDATED 2026-09-16. Schema **1.6.0** fields indexed. Hunt `Q-RAG-CONTEXT-AUTHORITY`. DET-MCP-001 unchanged. **DETECTION ANALYZED — NO NEW DETECTOR.** **Do not start Phase 10D from this file.** No Dashboard Studio.

| Field | Content |
|-------|---------|
| **Security question** | Can indexed telemetry reconstruct retrieve → classify → request → authorize → execute without inventing fields? |
| **Result** | Yes. Transport COMPLETE. CONTEXT-001 OBSERVE on A/B/C. B/C same malicious hash. ATTACK overlay ALLOW. RETEST DENY + handler 0. |
| **Splunk** | Reuse Q-MCP-*. One new hunt `Q-RAG-CONTEXT-AUTHORITY`. No detector. No Studio. |
| **Learning objective** | RETRIEVED CONTEXT IS DATA. OBSERVE ≠ ALLOW. Splunk ≠ authorization. |
| **Evidence** | A `51f70fb9-994e-4dd4-9b36-cac6fb1e8232`; B `3a43d24f-9281-42f6-8375-1fb2efaa80ac`; C `bea97bae-491b-4b36-b52f-1417d2bad01b`. |

**Do not start Phase 10D automatically.** (Historical 10C gate. 10D completed in a dedicated named phase.)

### Phase 10D — RAG / retrieved-context detection engineering (DESIGN / ANALYSIS)

**Status:** ANALYSIS complete 2026-09-16. **DETECTION ANALYZED — NO NEW DETECTOR.** **Do not start Phase 10E from this file.** No Dashboard Studio. No DET-RAG.

| Field | Content |
|-------|---------|
| **Security question** | What should a SOC detect vs hunt vs retain as context for retrieved-context / indirect prompt injection? |
| **Decision** | No DET-RAG. DET-MCP-001 unchanged (DENY-then-start only; 0/0/0 on A/B/C is correct, not SAFE). Overlay reason and instruction-like preview REJECT as production. Ungranted-tool-after-retrieval blocked by missing `allowed_tools`. |
| **Splunk** | Existing `Q-RAG-CONTEXT-AUTHORITY` KEEP AS-IS. No new SPL, saved search, notable, or Studio. |
| **Next** | Phase 10E workshop is a later named phase. Not started here. |

**Do not start Phase 10E automatically.** (Historical 10D gate. 10E completed in a dedicated named phase.) No Agent Scan. No rug-pull. No A2A.

### Phase 10E — LAB-RAG-CONTEXT workshop (VALIDATED)

**Status:** VALIDATED 2026-09-16. View `ws_lab_rag_context`. **DETECTION ANALYZED — NO NEW RAG DETECTOR.** **Do not start Phase 11 from this file.** No DET-RAG. No embeddings. No A2A. No rug-pull.

| Field | Content |
|-------|---------|
| **Security question** | What can a SOC prove from retrieved-context evidence across four planes? |
| **Result** | Ten-tab GRID workshop. LIVE 10C ids. ATTACK/RETEST same hash visible. DET-MCP-001 unchanged. |
| **Splunk** | Bind-only Q-RAG-CONTEXT-AUTHORITY + Q-MCP-*. No new hunt file. OBSERVE sequence is Studio-only. |
| **Learning objective** | RETRIEVED CONTENT IS DATA. REQUEST != GRANT. OBSERVE != ALLOW. SPLUNK != ENFORCEMENT. |

**Do not start Phase 11 automatically.** (Historical 10E gate. 11A completed in a dedicated named phase.)

### Phase 11A — Agent memory security / INV-003 (DESIGN / RESEARCH ONLY)

**Status:** DESIGN complete 2026-09-17. Schema remains **1.6.0**. Runtime **ABSENT**. **Do not start Phase 11B from this file.** No DET-MEMORY. No embeddings. No A2A. No rug-pull.

| Field | Content |
|-------|---------|
| **Security question** | Can persisted agent memory influence a future run so authority is acquired or exercised outside server-owned policy? |
| **Attack concept** | WRITE then RECALL across two `run.id`s. MALICIOUS fixture + `AGENT MEMORY NOTE`. Same hash on ATTACK and RETEST. |
| **Control** | Planned CTRL-MEMORY-CONTEXT-001 OBSERVE `memory_context_is_data`. Grant remains CTRL-MCP-001. Overlay `vulnerable_profile_fail_open:memory_derived_authority` is LAB fail-open on recall only. |
| **Telemetry** | Concepts only. SCHEMA BUMP JUSTIFIED (proposed 1.7.0) not implemented. No invented indexed fields. |
| **Splunk** | Questions defined. No SPL. CIM NOT APPLICABLE. DET-MCP-001 unchanged. |
| **Learning objective** | MEMORY IS PERSISTED DATA. PERSISTENCE != TRUST. RECALL != GRANT. Memory ≠ RAG. |
| **Risk** | Reusing RAG controls; collapsing write/recall; MemorySink confusion; detector sprawl |

**Do not start Phase 11B automatically.** No A2A. No rug-pull.

### Phase 11B — LAB-MEMORY-001 runtime (IMPLEMENTED + LOCALLY VALIDATED)

**Status:** IMPLEMENTED + LOCALLY VALIDATED 2026-09-17. Schema **1.7.0**. Local `splunk.verified=false`. Splunk proof is Phase 11C. No DET-MEMORY. No embeddings. No A2A. No rug-pull.

| Field | Content |
|-------|---------|
| **Security question** | Can persisted agent memory influence a future run so authority is acquired or exercised outside server-owned policy? |
| **Attack** | WRITE then RECALL across two `run.id`s. MALICIOUS fixture + `AGENT MEMORY NOTE`. Same hash on ATTACK and RETEST. |
| **Control** | CTRL-MEMORY-CONTEXT-001 OBSERVE `memory_context_is_data`. Grant remains CTRL-MCP-001. Overlay `vulnerable_profile_fail_open:memory_derived_authority` is LAB fail-open on recall only. |
| **Telemetry** | Schema 1.7.0. `agentsec.memory.written` / `agentsec.memory.recalled`. `memory.source_run_id` links write→recall. |
| **Splunk** | Not attempted in 11B. See Phase 11C. |
| **Learning objective** | MEMORY IS PERSISTED DATA. PERSISTENCE != TRUST. RECALL != GRANT. SAME MEMORY / SAME REQUEST / DIFFERENT AUTHORIZATION. |

**Do not start Phase 11C automatically.** (Historical 11B gate. 11C completed in a dedicated named phase.) No A2A. No rug-pull.

### Phase 11C — LAB-MEMORY-001 live Splunk (VALIDATED)

**Status:** VALIDATED 2026-09-17 — MEMORY SECURITY SPLUNK VALIDATED. Schema **1.7.0**. **Do not start Phase 11D from this file.** No DET-MEMORY. No Dashboard Studio. No embeddings. No A2A. No rug-pull.

| Field | Content |
|-------|---------|
| **Security question** | Can an analyst reconstruct write → persist → later recall → trust → follow-on request → authorization → execution from indexed evidence, including cross-run correlation? |
| **Attack** | Fresh LIVE A/B/C two-run specimens. SAME MALICIOUS SHA-256 on ATTACK and RETEST. |
| **Control** | CTRL-MEMORY-CONTEXT-001 OBSERVE. Grant remains CTRL-MCP-001. Overlay is recall-only vulnerable fail-open. |
| **Telemetry** | Indexed `agentsec.memory.*`, SHA-256, bounded preview. Completeness `dc(_raw)` COMPLETE on six run IDs. |
| **Splunk** | Q-MCP reuse + one hunt `Q-MEMORY-CONTEXT-AUTHORITY`. DET-MCP-001 unchanged (0/0/0). CIM NOT APPLICABLE. |
| **Learning objective** | SAME MEMORY / SAME REQUEST / DIFFERENT AUTHORIZATION. Write `run.id` is the writer; recall `run.id` is the destination. |

**Do not start Phase 11D automatically.** (Historical 11C gate. 11D completed in a dedicated named phase.) No A2A. No rug-pull.

### Phase 11D — LAB-MEMORY-001 detection engineering (ANALYSIS)

**Status:** ANALYSIS complete 2026-09-18. **DETECTION ANALYZED — NO NEW DETECTOR.** **Do not start Phase 11E from this file.** No Dashboard Studio. No DET-MEMORY. No embeddings. No A2A. No rug-pull.

| Field | Content |
|-------|---------|
| **Security question** | Detect vs hunt vs context for persisted-memory influence across five planes? |
| **Attack** | 11C LIVE A/B/C. SAME MALICIOUS SHA-256 on ATTACK and RETEST. Discriminator is authorization, then execution. |
| **Control** | CTRL-MEMORY-CONTEXT-001 OBSERVE. Grant remains CTRL-MCP-001. Overlay reason REJECT as production signal. |
| **Telemetry** | Schema **1.7.0** unchanged. Grant snapshot / tenant / writer≠reader remain TELEMETRY GAP. |
| **Splunk** | KEEP AS-IS hunts. DET-MCP-001 unchanged (0/0/0 is CORRECT BEHAVIOR, not SAFE). No new SPL. |
| **Learning objective** | MEMORY IS PERSISTED DATA. Untrusted recall ≠ incident. DET-MCP-001 silence ≠ SAFE. ANOMALY ≠ INCIDENT. |

**Do not start Phase 11E automatically.** (Historical 11D gate. 11E completed in a dedicated named phase.) No A2A. No rug-pull.

### Phase 11E — LAB-MEMORY-001 learner workshop (VALIDATED)

**Status:** VALIDATED 2026-09-18. View `ws_lab_memory_security`. **DETECTION ANALYZED — NO NEW MEMORY DETECTOR.** **Do not start Phase 12 from this file.** No DET-MEMORY. No embeddings. No A2A. No rug-pull.

| Field | Content |
|-------|---------|
| **Security question** | What can a SOC prove from persistent-memory evidence across five planes and two runs? |
| **Result** | Ten-tab GRID workshop. LIVE 11C write+recall ids. ATTACK/RETEST same hash visible. DET-MCP-001 unchanged. |
| **Splunk** | Bind-only Q-MEMORY-CONTEXT-AUTHORITY + Q-MCP-*. Observe sequences are Studio-only. |
| **Learning objective** | PERSISTED MEMORY != TRUSTED INSTRUCTION. SAME MEMORY / SAME REQUEST / DIFFERENT AUTHORIZATION. SPLUNK != ENFORCEMENT. |

**Do not start Phase 12 automatically.** (Historical 11E gate. 12A completed in a dedicated named phase.) No live A2A. No rug-pull.

### Phase 12A — Agent identity, delegation & A2A trust (DESIGN / RESEARCH ONLY)

**Status:** DESIGN complete 2026-09-18. Schema remains **1.7.0**. Runtime **ABSENT**. **Do not start Phase 12B from this file.** No DET-A2A. No DET-DELEGATION. No SPL. No Studio. No OAuth. No SPIFFE. No live A2A transport.

| Field | Content |
|-------|---------|
| **Security question** | When one agent acts on behalf of a user or another agent, what identity and authority is it actually permitted to exercise? |
| **Attack concept** | A2A-001: authority amplification. Neither Agent A nor Agent B is coded `customer:read`; a vulnerable profile treats the A2A-shaped caller claim as a grant. Distinct from MCP-006 ambient confused-deputy. |
| **Control** | Proposed CTRL-IDENTITY-001 **OBSERVE**. CTRL-MCP-001 remains the tool PDP. Overlay `caller_identity_derived_authority` (lab-only). |
| **Telemetry** | Schema 1.7.0 unchanged. **SCHEMA BUMP JUSTIFIED** (proposed 1.8.0) for caller/callee/claim fields in a later implementation phase. |
| **Splunk** | Design questions only. No SPL. DET-MCP-001 unchanged. |
| **Invariant** | INV-001 reused. **No INV-009.** INV-005 / INV-004 supporting. |
| **Learning objective** | IDENTITY CLAIM != VERIFIED IDENTITY. A2A REQUEST != DELEGATED GRANT. SAME REQUEST / DIFFERENT AUTHORIZATION. |
| **Dependencies** | Memory 11A–11E complete; MCP-006 remains closed as the deputy lab. |
| **Risk** | Re-teaching MCP-006; Agent Card as grant; JWT logging; crypto theater. |
| **Complexity** | Medium (research). 12B is a later, smaller in-process runner. |

**Do not start Phase 12B automatically.** No live A2A. No rug-pull. (Historical 12A gate. 12B completed in a dedicated named phase.)

### Phase 12B — Agent identity / delegation runtime (IMPLEMENTED + LOCALLY VALIDATED)

**Status:** IMPLEMENTED + LOCALLY VALIDATED 2026-09-18. Schema **1.8.0**. Splunk **NOT VALIDATED**. Detection **NOT STARTED**. Workshop **NOT STARTED**. A2A transport **NOT IMPLEMENTED**. **Do not start Phase 12C from this file.**

| Field | Content |
|-------|---------|
| **Security question** | Can an A2A-shaped request amplify authority neither agent was granted? |
| **Attack** | A2A-001. Neither advisor-005 nor fulfillment-006 is coded `customer:read`. |
| **Control** | CTRL-IDENTITY-001 **OBSERVE**. CTRL-MCP-001 remains the tool PDP. Overlay `caller_identity_derived_authority` (lab-only). |
| **Telemetry** | Schema **1.8.0**: caller/callee ids, `untrusted_claim`, `claimed_scope`. |
| **Splunk** | Not started. No SPL. DET-MCP-001 unchanged. |
| **Invariant** | INV-001 reused. **No INV-009.** |
| **Learning objective** | IDENTITY CLAIM != VERIFIED IDENTITY. SAME REQUEST / DIFFERENT AUTHORIZATION. |
| **Dependencies** | 12A DESIGN accepted. |
| **Risk** | Re-teaching MCP-006; JWT logging; starting 12C automatically. |
| **Complexity** | Medium (smallest in-process runner). |

**Do not start Phase 12C automatically.** No live A2A. No rug-pull. (Historical 12B gate. 12C completed in a dedicated named phase.)

### Phase 12C — Agent identity / delegation Splunk validation (VALIDATED)

**Status:** VALIDATED 2026-09-18. Fresh LIVE A/B/C; `Q-AGENT-DELEGATION-AUTHORITY`; DET-MCP-001 unchanged **0/0/0**. **DETECTION ANALYZED — NO NEW DETECTOR.** Workshop **NOT STARTED**. A2A transport **NOT IMPLEMENTED**. **Do not start Phase 12D from this file.**

| Field | Content |
|-------|---------|
| **Security question** | Can Splunk reconstruct who called whom, what was claimed, what CTRL-MCP-001 decided, and whether execution was observed — without treating identity as authentication? |
| **Attack** | A2A-001 (same 12B model). |
| **Control** | CTRL-IDENTITY-001 **OBSERVE**. CTRL-MCP-001 unchanged. |
| **Telemetry** | Schema **1.8.0** identity fields **OBSERVED** in index. |
| **Splunk** | `Q-AGENT-DELEGATION-AUTHORITY` + Q-MCP reuse. No Studio. |
| **Invariant** | INV-001. **TELEMETRY GAP** `allowed_tools`. |
| **Learning objective** | IDENTITY CLAIM != VERIFIED IDENTITY. SAME REQUEST / DIFFERENT AUTHORIZATION. SPLUNK != ENFORCEMENT. |
| **Dependencies** | 12B runtime accepted. |
| **Risk** | Overlay reason as IOC; rewriting Q-MCP-DELEGATION; starting 12D/12E automatically. |
| **Complexity** | Medium (investigation engineering). |

**Do not start Phase 12D automatically.** No live A2A. No rug-pull. No detector. No Dashboard Studio.

### Phase 13A — Agent goal / instruction integrity (DESIGN ONLY)

**Status:** DESIGN complete 2026-09-18. Schema remained **1.8.0** in the design phase. Runtime belongs to 13B. **Do not start Phase 13C from this file.**

| Field | Content |
|-------|---------|
| **Security question** | Can untrusted instructions silently redefine a server-owned task while a granted tool still ALLOWs? |
| **Attack** | GOAL-001. AUTHORIZED TOOL + UNAUTHORIZED GOAL (`lookup_policy` in-task vs extract). |
| **Control** | CTRL-GOAL-INTEGRITY-001. CTRL-MCP-001 remains the tool PDP. Overlay `untrusted_instruction_derived_task_authority` (lab-only). |
| **Telemetry** | SCHEMA BUMP JUSTIFIED **1.9.0**. |
| **Splunk** | Not started. No SPL. DET-MCP-001 unchanged. **NO DETECTOR JUSTIFIED.** |
| **Invariant** | INV-002 reused. INV-006 applied. **No INV-009.** |
| **Learning objective** | TASK AUTHORITY != TOOL AUTHORITY. SAME TASK / SAME INPUT / DIFFERENT OUTCOME. |
| **Dependencies** | Identity chapter through 12C. |
| **Risk** | Retesting MCP DENY; overlay as IOC; starting 13C automatically. |
| **Complexity** | Medium. |

**Do not start Phase 13B automatically.** (Historical 13A gate. 13B completed in a dedicated named phase.)

### Phase 13B — Agent goal / instruction integrity runtime (IMPLEMENTED + LOCALLY VALIDATED)

**Status:** IMPLEMENTED + LOCALLY VALIDATED 2026-09-18. Schema **1.9.0**. Splunk **NOT VALIDATED**. Detection **ANALYZED — NO IMPLEMENTATION**. Workshop **NOT STARTED**. **Do not start Phase 13C from this file.**

| Field | Content |
|-------|---------|
| **Security question** | Same as 13A; frozen TaskContract + ProposedTaskChange + overlay + CTRL-MCP-001. |
| **Attack** | GOAL-001. Same malicious bytes on ATTACK and RETEST. |
| **Control** | CTRL-GOAL-INTEGRITY-001 OBSERVE/DENY. CTRL-MCP-001 ALLOW `tool_granted` when the tool is `lookup_policy`. |
| **Telemetry** | Schema **1.9.0**. |
| **Splunk** | Not started. No Q-GOAL. No DET-GOAL. DET-MCP-001 unchanged. |
| **Invariant** | INV-002 / INV-006. |
| **Learning objective** | SAME PROPOSED CHANGE; different profile → different execution. |
| **Dependencies** | 13A DESIGN accepted. |
| **Risk** | Collapsing goal DENY into tool DENY; starting 13C automatically. |
| **Complexity** | Medium (smallest in-process runner). |

**Do not start Phase 13C automatically.** (Historical 13B gate. 13C completed in a dedicated named phase.)

### Phase 13C — Agent goal / instruction integrity Splunk (VALIDATED)

**Status:** VALIDATED 2026-09-18. Schema **1.9.0**. Detection **ANALYZED — NO NEW DETECTOR**. Workshop **NOT STARTED**. **Do not start Phase 13D from this file.**

| Field | Content |
|-------|---------|
| **Security question** | Can Splunk reconstruct task contract → untrusted instruction → proposed change → goal decision → tool ALLOW → effective action using indexed evidence? |
| **Attack** | GOAL-001 LIVE A/B/C. Same task/instruction/proposed fingerprints on ATTACK and RETEST. |
| **Control** | CTRL-GOAL-INTEGRITY-001 OBSERVE/DENY. CTRL-MCP-001 ALLOW `tool_granted` on A/B/C. Unchanged. |
| **Telemetry** | Schema **1.9.0** field discovery OBSERVED. Instruction hash / effective action / proposed fingerprint are preview-bounded. |
| **Splunk** | `Q-GOAL-INTEGRITY-AUTHORITY` + Q-MCP reuse. DET-MCP-001 0/0/0. No Studio. |
| **Invariant** | INV-002 / INV-006. TOOL AUTHORITY != TASK AUTHORITY. |
| **Learning objective** | MCP ALLOW DOES NOT MEAN THE AGENT'S GOAL WAS AUTHORIZED. |
| **Dependencies** | 13B runtime accepted. |
| **Risk** | Treating goal DENY as tool DENY; overlay/`AGENT NOTE` as IOC; starting 13D automatically. |
| **Complexity** | Medium (investigation engineering). |

**Do not start Phase 13D automatically.** (Historical 13C gate. 13D completed in a dedicated named phase.)

### Phase 13D — Agent goal / instruction integrity detection analysis + workshop design

**Status:** DETECTION ANALYZED — NO NEW DETECTOR. Workshop **DESIGNED — NOT IMPLEMENTED** 2026-09-18. Schema **1.9.0** unchanged. Runtime **UNCHANGED**. **Do not start Phase 13E from this file.** No rug-pull. No A2A. No DET-GOAL. No Studio.

| Field | Content |
|-------|---------|
| **Security question** | Detect vs hunt vs context for authorized tool + unauthorized goal? |
| **Attack** | GOAL-001 13C LIVE A/B/C (not re-ingested). |
| **Control** | CTRL-GOAL-INTEGRITY-001; CTRL-MCP-001 sole tool PDP. |
| **Telemetry** | 1.9.0 as 13C; no schema bump. |
| **Splunk** | `Q-GOAL-INTEGRITY-AUTHORITY` REUSE. DET-MCP-001 0/0/0 correct, not SAFE. |
| **Invariant** | INV-002 / INV-006. No INV-009. |
| **Learning objective** | MCP ALLOW DOES NOT MEAN THE AGENT'S GOAL WAS AUTHORIZED. |
| **Dependencies** | 13C Splunk accepted. |
| **Risk** | Inventing DET-GOAL; treating goal DENY as tool DENY; starting 13E automatically. |
| **Complexity** | Low–medium (analysis + workshop contract). |

**Do not start Phase 13E automatically.** (Historical 13D gate. 13E completed in a dedicated named phase.) No DET-GOAL. No runtime/schema/authz change. No LLM planner. No rug-pull. No A2A.

### Phase 13E — Agent goal / instruction integrity workshop

**Status:** VALIDATED 2026-09-18. View `ws_lab_agent_goal_integrity`. **DETECTION ANALYZED — NO NEW GOAL DETECTOR.** Schema **1.9.0** unchanged. Runtime **UNCHANGED**. **Do not start Phase 14 from this file.** No rug-pull. No A2A. No DET-GOAL. No ML implementation.

| Field | Content |
|-------|---------|
| **Security question** | What can a SOC prove from authorized-tool + unauthorized-goal evidence? |
| **Attack** | GOAL-001 13C LIVE A/B/C (not re-ingested). |
| **Control** | CTRL-GOAL-INTEGRITY-001; CTRL-MCP-001 sole tool PDP. |
| **Telemetry** | 1.9.0 as 13C; no schema bump. |
| **Splunk** | `Q-GOAL-INTEGRITY-AUTHORITY` REUSE. DET-MCP-001 0/0/0 correct, not SAFE. |
| **Invariant** | INV-002 / INV-006. No INV-009. |
| **Learning objective** | AUTHORIZED TOOL != AUTHORIZED GOAL. AUTHORIZED TOOL != AUTHORIZED USE OF TOOL. |
| **Dependencies** | 13D analysis accepted. |
| **Risk** | Inventing DET-GOAL; claiming MCP blocked RETEST; starting 14 automatically. |
| **Complexity** | Medium (Studio + UI/KO review). |

**Do not start Phase 14 automatically.** No DET-GOAL. No runtime/schema/authz change. No LLM planner. No rug-pull. No A2A.

### Phase 14A — Attack Simulator + guided investigation architecture

**Status:** DESIGN / RESEARCH / CONTRACT ONLY 2026-09-19. **Not implemented.** Schema **1.9.0** unchanged. Runtime **UNCHANGED**. **Do not start Phase 14B from this file.** No new Studio views. No new SPL. No detectors.

| Field | Content |
|-------|---------|
| **Security question** | How does a learner launch an allowlisted specimen and investigate it in Splunk without treating Splunk as enforcement? |
| **Attack** | Allowlisted catalog (today ATK-002 exists). No arbitrary payloads. |
| **Control** | Unchanged CTRL-* in runtime. Attack Service remains untrusted. |
| **Telemetry** | 1.9.0. Evidence states: REQUESTED → … → WAITING_FOR_EVIDENCE → EVIDENCE_READY. HEC 200 ≠ READY. |
| **Splunk** | Reuse Q-*. Path A Open Search. Path B solution cell. No DET-*. |
| **Invariant** | Existing INV-*; Splunk ≠ enforcement. |
| **Learning objective** | UNDERSTAND → PREDICT → launch (if honest) → INVESTIGATE → PROVE → CONNECT. |
| **Dependencies** | UI/UX remediation PASS. |
| **Risk** | Studio POST; claiming LIVE RETEST; cloning PortSwigger; inventing Identity Studio. |
| **Complexity** | Medium (product + platform honesty). |

**Do not start Phase 14B automatically.** Reference lab (not implemented in 14A): LAB-PI-001. MCP-001 is the designated second.

### Phase 14B — Attack Service + first LIVE learner launch

**Status:** IMPLEMENTED + OFFLINE TESTED 2026-09-19. LIVE Splunk is a separate probe. Schema **1.9.0** unchanged. Runtime authorization **UNCHANGED**. **Do not start Phase 14C from this file.** No new Studio views. No new SPL hunts. No detectors.

| Field | Content |
|-------|---------|
| **Security question** | Can a learner launch allowlisted PI BASELINE/ATTACK, get a fresh run.id, and hunt it in Search without Studio POST or Splunk enforcement? |
| **Attack** | Catalog ATK-001 / ATK-002 only. No arbitrary payloads. |
| **Control** | Unchanged CTRL-INPUT-001. Attack Service remains untrusted. |
| **Telemetry** | 1.9.0. Evidence states implemented in-memory. HEC 200 ≠ READY. |
| **Splunk** | Reuse Q-RUN-EVENTS. Starter query + Search URL. No DET-*. |
| **Invariant** | INV-008. Splunk ≠ enforcement. |
| **Learning objective** | PREDICT → LAUNCH → copy run.id → Search. |
| **Dependencies** | 14A DESIGN accepted. |
| **Risk** | Fake LIVE RETEST; HEC-as-ready; JS token binding. |
| **Complexity** | Medium (closed contract + honest delay). |

**Do not start Phase 14C automatically.** Guided investigation Path A/B is not implemented in 14B. MCP-001 launcher is not implemented.

### Phase 14C — Guided investigation framework (LAB-PI-001)

**Status:** IMPLEMENTED + OFFLINE TESTED + LIVE SPLUNK MEASURED + UI REVIEWED 2026-09-19. Schema **1.9.0** unchanged. Runtime authorization **UNCHANGED**. **Do not start Phase 14D from this file.** No new Q-* hunts. No detectors. No MCP-001 launch.

| Field | Content |
|-------|---------|
| **Security question** | Can a learner investigate a PI run in Splunk (Path A) with an optional solution cell (Path B) without treating Splunk as enforcement? |
| **Attack** | Unchanged allowlisted ATK-001 / ATK-002. |
| **Control** | Unchanged CTRL-INPUT-001. |
| **Telemetry** | 1.9.0 after restage. |
| **Splunk** | Reuse Q-RUN-EVENTS, Q-CONTROL-DECISION, Q-LLM-EXECUTED, Q-LLM-AFTER-DENY. |
| **Invariant** | INV-008. Splunk ≠ enforcement. |
| **Learning objective** | PREDICT → LAUNCH → TRY / HINT / SOLUTION → PROVE → CONNECT. |
| **Dependencies** | 14B PASS. |
| **Risk** | Spoiler-only HUNT; JS token binding; fake RETEST. |
| **Complexity** | Medium (Studio visibility + Search handoff honesty). |

**Do not start Phase 14D automatically.** MCP-001 guided/launch pattern is not this phase.

---

## NEXT 5 PHASES (after 8B/8C)

Planning labels shifted: **9A is scanner architecture (this file), not rug-pull.** Rug-pull remains NOT STARTED.

| Phase | Intent | Security question (one line) | Complexity | External | Risk |
|-------|--------|------------------------------|------------|----------|------|
| **9B** | First scanner wire-up | Can we import mcp-scanner YARA JSON for the catalog fixture without touching authorization? | Medium | Cisco mcp-scanner static | Executing live MCP; FAIL→DENY |
| **9C** | Scanner Splunk ingest | Can scanner evidence be an independent sourcetype correlated honestly with runtime? | Medium | None new | FAIL→DENY via Splunk |
| **9D** | Detection analysis | Is a new detector justified? | Low | None | Detector sprawl |
| **9E** | Scanner + runtime workshop (done) | How does a SOC combine scanner and runtime evidence? | Low | None new | Collapsing planes |
| **9F+ rug-pull** | MCP catalog pin / `list_changed` | Did this tool’s description hash change between list and call? | Medium | Invariant pinning *idea*; not a scanner DENY | Timing theater |
| **10A** | RAG / retrieved-context DESIGN (this file) | Can retrieved text authorize a tool? (INV-002, LLM01 indirect) | Medium | None in 10A | Overload MCP-005; stochastic retrieve |
| **10B** | LAB-RAG-001 runtime (**IMPLEMENTED + LOCALLY VALIDATED**) | Same question; fixture retriever + overlay + CTRL-MCP-001 | Medium | None required | Schema 1.6.0; global grants |
| **10C** | LAB-RAG-001 Splunk (**VALIDATED**) | Honest reconstruction after field discovery | Medium | None | Invented fields |
| **10D** | RAG detection analysis (**ANALYSIS**; no new detector) | Detect vs hunt vs context for retrieved-context influence? | Low | None | Detector sprawl; overlay-reason notable |
| **10E** | RAG workshop (**VALIDATED**) | How does a SOC walk retrieve → OBSERVE → request → authz → execute? | Low | None | Collapsing planes |
| **11A** | Memory security DESIGN (**this file**) | Can persisted memory widen authority on a later run? (INV-003) | Medium | None in 11A | RAG overload; one-run collapse |
| **11B** | LAB-MEMORY-001 runtime (**IMPLEMENTED + LOCALLY VALIDATED**) | Same question; fixture store + overlay + CTRL-MCP-001 | Medium | None required | Schema 1.7.0; global grants |
| **11C** | LAB-MEMORY-001 Splunk (**VALIDATED**) | Honest cross-run reconstruction after field discovery | Medium | None | Invented fields; DET-MEMORY sprawl |
| **11D** | Memory detection analysis (**ANALYSIS**; no new detector) | Detect vs hunt vs context for persisted-memory influence? | Low | None | Detector sprawl; overlay-reason notable |
| **11E** | Memory workshop (**VALIDATED**) | How does a SOC walk write → later recall → OBSERVE → request → authz → execute? | Low | None | Collapsing planes |
| **12A** | Identity / A2A DESIGN (**this file**) | Can an A2A-shaped request amplify authority neither agent was granted? (INV-001 + INV-005) | Medium | None in 12A | Re-teach MCP-006; Agent Card as grant |
| **12B** | LAB-AGENT-DELEGATION-001 runtime (**IMPLEMENTED + LOCALLY VALIDATED**) | Same question; frozen A2A-shaped request + overlay + CTRL-MCP-001 | Medium | None required | Schema 1.8.0; global grants; MCP-006 overload |
| **12C** | LAB-AGENT-DELEGATION-001 Splunk (**VALIDATED**) | Honest reconstruction after field discovery | Medium | None | Invented fields; DET-A2A sprawl; Q-MCP-DELEGATION overload |
| **13A** | Goal / instruction integrity DESIGN (**this file**) | Can untrusted instructions redefine the task while a granted tool ALLOWs? (INV-002 / INV-006) | Medium | None in 13A | MCP DENY retest; INV-009 |
| **13B** | LAB-AGENT-GOAL-INTEGRITY-001 runtime (**IMPLEMENTED + LOCALLY VALIDATED**) | Same question; frozen TaskContract + overlay + CTRL-MCP-001 | Medium | None required | Schema 1.9.0; global grants |
| **13E** | Goal workshop (**VALIDATED**) | How does a SOC walk task → instruction → goal decision → tool grant → execution? | Low | None | Claiming MCP blocked RETEST; DET-GOAL sprawl |
| **Identity (was 10A/B)** | INV-005 deepen | **Absorbed into 12A design**; runtime remains 12B | Low–medium | None required | Crypto theater (forbid) |
| **A2A transport** | Live A2A protocol | Does an Agent Card / A2A message confer more authority than coded? | High | `a2aproject/A2A` 1.0.0; later a2a-scanner | Fake A2A regex; **DEFER** |
| **12A–D** | RAG chapter (brought forward to **10A/10B**) | See 10A. Do not run a second RAG design track. | — | — | Duplicate labs |
| **13** | Detection engineering workshop | When is a hunt allowed to become a detector? | Medium | None | Detector sprawl |

Phase numbers are planning labels, not MCP identifiers.

---

## ADVANCED TRACK (optional overlays)

| Track | When | Notes |
|-------|------|-------|
| AI BOM + skill-scanner + pickle/model provenance | After a catalog lab exists | IMPORT OUTPUT only |
| Memory poisoning (INV-003) | After RAG or an explicit store | Do not regex `WRITE_MEMORY` as a fake control |
| Credential delegation | After identity | Easy to overclaim |
| Splunk AI Toolkit counters | After event-derived metrics | Deterministic rules first |
| CDTSM anomaly | After a real metric time series | Feature preview; optional Enterprise |
| Splunk ES notable | Only with detection gate + ES present | Never core |
| Cisco AI Defense inspect API | Teach-mode overlay | No `cisco_*=FAIL` if the API was not called |
| Foundation-Sec optional model | Hunt-assist | Not authorization |
| DefenseClaw | Not in core | Overlay only with tested admission hook |
| Long-running behavioral / collusion | Last | Needs honest fan-out telemetry |

---

## RESEARCH TRACK

Operate the pipeline in `docs/AGENTSEC_ATTACK_RESEARCH_PIPELINE.md`.

First research reproductions (not scheduled as product phases):

1. Tool poisoning papers → 8B fixture
2. A2A Agent Card spoof → phase 11
3. ATLAS id revalidation for ATK-002 / MCP-002 (docs + `technique_id_for`, not a new attack)

---

## Recommended next phase (exactly one)

**Phase 14E — generalize the learning loop + LAB-MCP-001 second reference: ACCEPT as IMPLEMENTED + LIVE SPLUNK MEASURED + UI REVIEWED. Do not start Phase 15 from this file.** Schema **1.9.0**. No DET-MCP-NEW. Remaining labs not auto-migrated. Reference labs: LAB-PI-001 and LAB-MCP-001. Official MCP pair ATTACK `bf5109de-bcc0-4ca0-9916-cf4b63e77ef4` / RETEST `0cd82b2a-cefe-4fe5-86f3-4751929c3d1f`.

**Phase 14D — LIVE DEFEND / RETEST / COMPARE: ACCEPT as IMPLEMENTED (historical 14D snapshot). Do not start Phase 14E from the 14D file.** Schema **1.9.0**. PI-001 only.

**Phase 14C — Guided investigation framework: ACCEPT as IMPLEMENTED + OFFLINE TESTED + LIVE SPLUNK MEASURED (historical 14C snapshot). Do not start Phase 14D from this file.** Schema **1.9.0**. No detectors. No Studio JS. RETEST not LIVE. Reference lab LAB-PI-001.

**Phase 14B — Attack Service + first LIVE learner launch: ACCEPT as IMPLEMENTED + OFFLINE TESTED (historical 14B snapshot). Implementation of Path A/B is 14C. Do not start Phase 14C from the 14B file.** Schema **1.9.0**. No detectors. No Studio POST. RETEST not LIVE. Reference lab LAB-PI-001.

**Phase 14A — Attack Simulator + guided investigation architecture: ACCEPT as DESIGN ONLY (14A snapshot). Implementation is 14B. Do not start Phase 14B from the 14A file.** No runtime/schema/authz change in 14A. No Studio implementation in 14A. No detectors. Schema **1.9.0**. Reference lab for 14B–14E: LAB-PI-001.

**Pre-Phase-14 UI/UX remediation: ACCEPT as COMPLETE (Pass-2 2026-09-19). Phase 14A is the next named design phase. Do not start Phase 14B from this file.** Schema **1.9.0**. No DET-GOAL.

**Phase 13E — LAB-AGENT-GOAL-INTEGRITY-001 workshop: ACCEPT as VALIDATED. DETECTION ANALYZED — NO NEW DETECTOR. Workshop VALIDATED. Pre-Phase-14 UI/UX remediation is a separate named phase (now COMPLETE). Do not start Phase 14B from this file.**

Historical 13D text (kept): **Phase 13D — LAB-AGENT-GOAL-INTEGRITY-001 detection engineering + workshop design: ACCEPT as ANALYSIS. DETECTION ANALYZED — NO NEW DETECTOR. Workshop DESIGNED — NOT IMPLEMENTED. Do not start Phase 13E from this file.** (13E was completed in a dedicated named phase; this sentence remains as the 13D snapshot contract.)

Historical 13C text (kept): **Phase 13C — LAB-AGENT-GOAL-INTEGRITY-001 Splunk: ACCEPT as VALIDATED. DETECTION ANALYZED — NO NEW DETECTOR. Workshop NOT STARTED. Do not start Phase 13D from this file.** (13D was completed in a dedicated named phase; this sentence remains as the 13C snapshot contract.)

Historical 13B text (kept): **Phase 13B — LAB-AGENT-GOAL-INTEGRITY-001 runtime: ACCEPT as IMPLEMENTED + LOCALLY VALIDATED. Splunk NOT VALIDATED. Detection ANALYZED — NO IMPLEMENTATION. Workshop NOT STARTED. Do not start Phase 13C from this file.** (13C was completed in a dedicated named phase; this sentence remains as the 13B snapshot contract.)

Historical 13A text (kept): **Phase 13A — agent goal / instruction integrity: ACCEPT as DESIGN ONLY (this phase). Do not start Phase 13B from this file.** (13B was completed in a dedicated named phase; this sentence remains as the 13A snapshot contract.)

**Phase 12C — LAB-AGENT-DELEGATION-001 Splunk: ACCEPT as VALIDATED. DETECTION ANALYZED — NO NEW DETECTOR. Workshop NOT STARTED. A2A transport NOT IMPLEMENTED. Do not start Phase 12D from this file.**

Historical 12B text (kept): **Phase 12B — LAB-AGENT-DELEGATION-001 runtime: ACCEPT as IMPLEMENTED + LOCALLY VALIDATED. Splunk NOT VALIDATED. Detection NOT STARTED. Workshop NOT STARTED. A2A transport NOT IMPLEMENTED. Do not start Phase 12C from this file.** (12C was completed in a dedicated named phase; this sentence remains as the 12B snapshot contract.)

Historical 12A text (kept): **Phase 12A — agent identity / A2A trust: ACCEPT as DESIGN ONLY (this phase). Do not start Phase 12B from this file.** (12B was completed in a dedicated named phase; this sentence remains as the 12A snapshot contract.)

Historical 11E text (kept): **Phase 11E — LAB-MEMORY-001 workshop: ACCEPT as VALIDATED. DETECTION ANALYZED — NO NEW MEMORY DETECTOR. Do not start Phase 12 from this file.** (12A was completed in a dedicated named phase; this sentence remains as the 11E snapshot contract.)

Historical 11D text (kept): **Phase 11D — LAB-MEMORY-001 detection engineering: ACCEPT as ANALYSIS. DETECTION ANALYZED — NO NEW DETECTOR. Do not start Phase 11E from this file.** (11E was completed in a dedicated named phase; this sentence remains as the 11D snapshot contract.)

Historical 11C text (kept): **Phase 11C — LAB-MEMORY-001 Splunk: ACCEPT as VALIDATED. Do not start Phase 11D from this file.** (11D was completed in a dedicated named phase; this sentence remains as the 11C snapshot contract.)

Historical 11B text (kept): **Phase 11B — LAB-MEMORY-001 runtime: ACCEPT as IMPLEMENTED + LOCALLY VALIDATED. Do not start Phase 11C from this file.** (11C was completed in a dedicated named phase; this sentence remains as the 11B snapshot contract.)

Historical 11A text (kept): **Phase 11A — agent memory security / INV-003: ACCEPT as DESIGN ONLY (this phase). Do not start Phase 11B from this file.**

Historical 10E text (kept): **Phase 10E — LAB-RAG-CONTEXT workshop: ACCEPT as VALIDATED. Do not start Phase 11 from this file.** (11A was completed in a dedicated named phase; this sentence remains as the 10E snapshot contract.)

Historical 10D text (kept): **Phase 10D — RAG / retrieved-context detection engineering: ACCEPT as ANALYSIS. DETECTION ANALYZED — NO NEW DETECTOR. Do not start Phase 10E from this file.** (10E was completed in a dedicated named phase; this sentence remains as the 10D snapshot contract.)

Historical 10C text (kept): **Phase 10C — LAB-RAG-001 Splunk: ACCEPT as VALIDATED. Do not start Phase 10D from this file.** (10D was completed in a dedicated named phase; this sentence remains as the 10C snapshot contract.)

Historical 10B text (kept): **Phase 10B — LAB-RAG-001 runtime: ACCEPT as IMPLEMENTED + LOCALLY VALIDATED. Do not start Phase 10C from this file.** (10C was completed in a dedicated named phase; this sentence remains as the 10B snapshot contract.)

Historical 10A text (kept): **Phase 10A — RAG / retrieved-context security: ACCEPT as DESIGN ONLY (this phase). Do not start Phase 10B from this file.** (10B was completed in a dedicated named phase; this sentence remains as the 10A snapshot contract.)

Historical 9A text (kept): **Phase 9A — scanner architecture: ACCEPT as DESIGN ONLY.** Do **not** start Phase 9B from this file. (9B–9E were completed in dedicated phases; this sentence remains as the 9A snapshot contract.)

Historical 8A text (kept): **Phase 8D — Splunk transport / field discovery for LAB-MCP-CATALOG (not started).** Do **not** start Phase 8D from this file. (8D/8E were completed in dedicated phases; this sentence remains as the 8A snapshot contract.)

Why 9A before rug-pull, A2A, MCP-007, MLTK:

- Learning: catalog lab is complete; the missing honesty layer is **scan vs execute**.
- Architecture: adapters and evidence packs; no new protocol; no runtime change.
- Security value: lock SCANNER FINDING ≠ AUTHORIZATION before anyone wires a CLI into DENY.
- Ecosystem: Cisco mcp-scanner static `--tools` and Snyk Agent Scan exist **now** (re-verified 2026-09-16).
- Telemetry: keep findings off `security_event` 1.5.0.
- Splunk: design sourcetype isolation; no SPL until ingest + field discovery.

Not chosen as 9A implementation: rug-pull/`list_changed`, A2A, live stdio MCP, DefenseClaw embed, CDTSM.

---

## Explicit non-starts

Do not implement 8D, Phase 9B, Phase 10B, MCP-007, A2A, Cisco overlay, SPL, detections, dashboards, scanner execution, or rug-pull from this document. Schema 1.5.0 is the Phase 8C runtime bump, not an 8A/8B/9A/10A change. No rug-pull. No A2A.
