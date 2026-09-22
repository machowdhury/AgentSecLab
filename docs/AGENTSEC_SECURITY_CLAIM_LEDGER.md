# AgentSec security claim ledger

**Status:** Phase 17C canonical. Material learner-facing security claims only. Schema **1.9.0**.  
**Do not start Phase 17D from this file.**

SUPPORTED? uses: YES / PARTIALLY / NO (corrected) / HISTORICAL-STALE.

Evidence classes: MEASURED · OBSERVED · DOCUMENTED · SIMULATED · CORROBORATED · REPLAYED · NOT PROVEN · NOT MODELED · INCORRECT.

| CLAIM ID | LAB | SURFACE | CLAIM | TYPE | AUTHORITATIVE SOURCE | TELEMETRY | SPL | CLASS | SUPPORTED? | LIMITATION | CORRECTION | VALIDATION |
|----------|-----|---------|-------|------|----------------------|-----------|-----|-------|------------|------------|------------|------------|
| C-ARCH-001 | Home | ORIENT | Studio = syllabus; Splunk = copy, not PDP | ARCHITECTURE | academy + runtime | control.decision copied | Q-CONTROL / Q-MCP-AUTHZ | OBSERVED | YES | — | none | 16D/17B/17C |
| C-ARCH-002 | All LIVE | Attack Service | Browser does not submit profile/grants | ARCHITECTURE | ExperimentContext / launch catalog | server-owned fields | n/a | OBSERVED | YES | Allowlisted specimen only | none | launch contract |
| C-TRUST-001 | RAG | LEARN | PROVENANCE != TRUST | TRUST | CTRL-RAG-CONTEXT-001 | provenance, trust label | Q-RAG-CONTEXT-AUTHORITY | OBSERVED | YES | Exact-id fixtures | none | 15B |
| C-TRUST-002 | Memory | LEARN | STORED != TRUSTED; WRITE != RECALL | TRUST | memory pipeline | memory.written / recalled, source_run_id | Q-MEMORY-CONTEXT-AUTHORITY | OBSERVED | YES | Two run.ids | 17C: write-event is corroboration | 15C |
| C-AUTHZ-001 | MCP-001 | LEARN | REQUEST != GRANT | AUTHORIZATION | CTRL-MCP-001 + coded_policy | requested vs allowed scope | Q-MCP-AUTHZ | OBSERVED | YES | In-process JSON-RPC | none | 14E |
| C-AUTHZ-002 | MCP-001 | HUNT | ALLOW != EXECUTION | AUTHORIZATION / EXECUTION | handler_invoke_count | mcp.started | Q-MCP-EXECUTED | OBSERVED | YES | Indexed started is corroboration | 17C: do not say “execution is mcp.started” | 14E |
| C-AUTHZ-003 | RAG/Memory | HUNT | OBSERVE != ALLOW | AUTHORIZATION | classifiers vs CTRL-MCP-001 | control.id | Q-RAG / Q-MEMORY + Q-MCP-AUTHZ | OBSERVED | YES | Overlay on ATTACK | none | 15B/15C |
| C-AUTHZ-004 | Goal | PROVE | AUTHORIZED TOOL != AUTHORIZED GOAL | AUTHORIZATION | CTRL-GOAL-INTEGRITY-001 vs CTRL-MCP-001 | goal decision + MCP ALLOW | Q-GOAL + Q-MCP-AUTHZ | MEASURED | YES | RETEST MCP still ALLOW | none | 15D |
| C-AUTHZ-005 | Identity | LEARN | IDENTITY CLAIM != AUTHENTICATION | AUTHORIZATION | CTRL-IDENTITY-001 OBSERVE | who_authenticated absent | Q-AGENT-DELEGATION-AUTHORITY | NOT MODELED | YES | No OAuth/OIDC/SPIFFE | none | 15E |
| C-EXEC-001 | PI | RETEST | Defended DENY prevents LLM invoke | EXECUTION | runtime hops | llm.started=0 on complete copy | Q-LLM-EXECUTED | MEASURED | YES | Regex; paraphrases may ALLOW | none | 14D |
| C-EXEC-002 | MCP/RAG/Memory/Identity/Capstone | RETEST | Handler 0 when MCP DENY | EXECUTION | handler_invoke_count | no mcp.started on complete copy | Q-MCP-EXECUTED | MEASURED | YES | Absence not independent proof | 17C expected-defended copy | 14E–16B |
| C-TEL-001 | All | Path A | run.id is the correlation key | TELEMETRY | emitters | agentsec.run.id | Q-RUN-EVENTS | OBSERVED | YES | One UUID ≠ related write/recall | none | all |
| C-DET-001 | MCP family | DETECT | DET-MCP-001 0 rows ≠ SAFE | DETECTION | DET-MCP-001 semantics | DENY-then-start | Q-MCP-AFTER-DENY | MEASURED 0/0/0 | YES | ATTACK ALLOW is silent | none | 3E+ |
| C-DET-002 | RAG/Memory/Goal/Capstone | DETECT | No DET-RAG/MEMORY/GOAL/CAPSTONE | DETECTION | savedsearches.conf | n/a | n/a | OBSERVED | YES | Named only to reject | none | 17C |
| C-ATK-001 | PI | COMPARE | Same malicious bytes ATTACK vs RETEST | ATTACK | input.hash | input.hash | Q-RUN-EVENTS | MEASURED | YES | Hash of input object | 17C Home fingerprint wording | 14D |
| C-DEF-001 | PI | DEFEND | CTRL-INPUT-001 is the PDP; Splunk is not | DEFENSE | controls.py | control.decision | Q-CONTROL-DECISION | OBSERVED | YES | Not universal PI resistance | none | 14D |
| C-RETEST-001 | Goal | RETEST | RETEST is Goal DENY, not MCP DENY | RETEST | 15D pair | GOAL DENY + MCP ALLOW | Q-GOAL + Q-MCP-AUTHZ | MEASURED | YES | In-task handler still 1 | none | 15D |
| C-CMP-001 | All LIVE | COMPARE | Profile/mode differ; fingerprint matches | COMPARE | official pairs | hash fields | domain hunt | MEASURED | PARTIALLY | Object-specific hash only | 17C Home | pairs |
| C-EVD-001 | All | empty Search | Empty ≠ DENY / SAFE / prevented | EVIDENCE | no-data semantics | n/a | any | OBSERVED | YES | Wait EVIDENCE READY on LIVE | 17B/17C | academy |
| C-EVD-002 | Memory | BASELINE card | Canonical write/recall UUIDs are LIVE | EVIDENCE | Investigate tokens | those UUIDs | n/a | REPLAYED | NO | They are REPLAY specimens | **17C relabel REPLAY SPECIMEN** | 17C |
| C-EVD-003 | PI | LEARN | Page is LIVE EVIDENCE | EVIDENCE | mixed Studio | dropdown REPLAY | n/a | MIXED | NO as sole label | Tables are REPLAY | **17C LIVE EXPERIMENT vs REPLAY SPECIMEN** | 17C |
| C-FW-001 | PI | Attack Service | AML.T0054 is a verified ATLAS mapping | FRAMEWORK | technique_id_for | technique.id | n/a | DOCUMENTED | NO as verified | REQUIRES REVALIDATION | **17C educational qualifier** | 8A/17C |
| C-PRIV-001 | All | PROVE | Full prompts/secrets are not indexed by default | PRIVACY | evidence contract | preview ≤200, hashes | n/a | DOCUMENTED | PARTIALLY | Bounded preview exists; do not claim “no prompt bytes at all” | none (not overclaimed on current Studio) | 1B+ |
| C-CAP-001 | Capstone | INVESTIGATE | 0 Goal/Identity rows ⇒ domain not required | EVIDENCE | non-emission | 0 rows | Q-GOAL / Q-IDENT | INFERRED | NO as causal ruling | Instrumented absence | **17C NOT PRESENT IN THIS PACKET** | 16B/17C |
| C-MA-001 | Mastery | MA-PT1 Path B | Q-MCP-AUTHZ on official recall is the 15-point readout | EVIDENCE | assessments.json | recall UUID | Q-MCP-AUTHZ | REPLAYED | NO | Fragment only | **17C Path B disclaimer** | 17A/17C |
| C-DOC-001 | learning-note | how-to-learn… | Only PI-001 and MCP-001 are LIVE; capstone not built | ARCHITECTURE | stale 15A note | n/a | n/a | DOCUMENTED stale | NO current | Seven LIVE labs | **17C HISTORICAL stamp** | 17C |

## Cross-lab model (must remain true)

DATA / CONTEXT can influence behavior and does not create authority.  
REQUEST ≠ GRANT. IDENTITY CLAIM ≠ AUTHENTICATION. AUTHORIZATION ≠ EXECUTION.  
TELEMETRY does not enforce. OBSERVATION does not authorize.  
RETEST demonstrates a specific experiment outcome, not universal security.
