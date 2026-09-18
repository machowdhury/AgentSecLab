# AgentSec roadmap 2026

**Status:** Phase 8A DESIGN ONLY (historical snapshot in this file). Phase 8B–8E LAB-MCP-CATALOG completed separately. **Phase 9A DESIGN / RESEARCH ONLY** (scanner architecture). Phases **9B–9C** executed in dedicated reports (scanner static integrate + Splunk ingest). **Phase 9D DESIGN / ANALYSIS** (detection engineering; **DETECTION ANALYZED — NO NEW DETECTOR**). **Phase 9E VALIDATED** (scanner + runtime evidence workshop). **Phase 10A DESIGN / RESEARCH ONLY** (RAG / retrieved-context security). **Phase 10B IMPLEMENTED + LOCALLY VALIDATED** (LAB-RAG-001 runtime + schema 1.6.0). **Phase 10C VALIDATED** (LAB-RAG-001 Splunk; **DETECTION ANALYZED — NO NEW DETECTOR**). **Phase 10D DESIGN / ANALYSIS** (RAG detection engineering; **DETECTION ANALYZED — NO NEW DETECTOR**). **Phase 10E VALIDATED** (LAB-RAG-CONTEXT workshop). **Phase 11A DESIGN / RESEARCH ONLY** (agent memory security / INV-003). This file does not authorize a detector, Agent Scan, rug-pull, A2A, or Phase 11B.  
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

**Status:** IMPLEMENTED + LOCALLY VALIDATED 2026-09-17. Schema **1.7.0**. `splunk.verified=false`. **Do not start Phase 11C from this file.** No DET-MEMORY. No embeddings. No A2A. No rug-pull.

| Field | Content |
|-------|---------|
| **Security question** | Can persisted agent memory influence a future run so authority is acquired or exercised outside server-owned policy? |
| **Attack** | WRITE then RECALL across two `run.id`s. MALICIOUS fixture + `AGENT MEMORY NOTE`. Same hash on ATTACK and RETEST. |
| **Control** | CTRL-MEMORY-CONTEXT-001 OBSERVE `memory_context_is_data`. Grant remains CTRL-MCP-001. Overlay `vulnerable_profile_fail_open:memory_derived_authority` is LAB fail-open on recall only. |
| **Telemetry** | Schema 1.7.0. `agentsec.memory.written` / `agentsec.memory.recalled`. `memory.source_run_id` links write→recall. |
| **Splunk** | Not attempted. No SPL. DET-MCP-001 unchanged. |
| **Learning objective** | MEMORY IS PERSISTED DATA. PERSISTENCE != TRUST. RECALL != GRANT. SAME MEMORY / SAME REQUEST / DIFFERENT AUTHORIZATION. |

**Do not start Phase 11C automatically.** No A2A. No rug-pull.

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
| **Identity (was 10A/B)** | INV-005 identity deepen (deferred) | Can a request mint `gen_ai.agent.id` the allow-list does not own? | Low–medium | None required | Crypto theater (forbid) |
| **A2A (was 11A–D)** | A2A slice | Does an Agent Card / A2A message confer more authority than coded? (ASI07) | High | `a2aproject/A2A` 1.0.0; later a2a-scanner | Fake A2A regex |
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

**Phase 11A — agent memory security / INV-003: ACCEPT as DESIGN ONLY (this phase). Do not start Phase 11B from this file.**

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
