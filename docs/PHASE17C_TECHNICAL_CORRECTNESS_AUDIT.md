# PHASE 17C — Technical correctness, evidence & security claims audit

**Status:** IMPLEMENTED 2026-09-21. Schema **1.9.0** unchanged. Runtime authorization **UNCHANGED**. No new attack domain. No DET-*. No MLTK. No real A2A. No OAuth/OIDC/JWT/SPIFFE. Not a certificate. **Do not start Phase 17D from this file.**

**Predecessor:** 16D PASS, 17A PASS, 17B PASS.

**Question:** If a learner repeats what AgentSec taught them to a security engineer, SOC lead, architect, or CISO, can we defend those technical claims with the implementation and evidence?

## Predecessor verification

| Item | Result |
|------|--------|
| Phase 16D | PASS (`docs/PHASE16D_ACADEMY_REMEDIATION.md`) |
| Phase 17A | PASS (`docs/PHASE17A_LEARNER_MASTERY_VALIDATION.md`) |
| Phase 17B | PASS (`docs/PHASE17B_FRESH_LEARNER_VALIDATION.md`) |
| Schema | `SCHEMA_VERSION = "1.9.0"` in `src/agentsec/experiment.py`; schema const 1.9.0 |
| Architecture freeze | `coded_policy()`, all CTRL-*, Attack Service boundary, ATTACK/RETEST contracts, DET-MCP-001, schema — **not modified** |

## Published lab inventory

See `docs/AGENTSEC_LIVE_REPLAY_EVIDENCE_AUDIT.md`. Seven Attack Service LIVE labs (PI, MCP-001, RAG, Memory, Goal, Identity, Capstone) plus six REPLAY workshops (MCP-003/004/005/006, catalog, scanner). `docs/AGENTSEC_EXISTING_LAB_INVENTORY.md` remains a dated 15A snapshot.

## Security claim ledger result

`docs/AGENTSEC_SECURITY_CLAIM_LEDGER.md`. Material claims catalogued. Four HIGH teaching defects were **corrected** (not left unresolved). No CRITICAL architecture defect.

## Evidence authority result

`docs/AGENTSEC_EVIDENCE_AUTHORITY_MODEL.md`. Runtime handler / invoke counts are authoritative for execution. Control events are authoritative for that control’s decision. Splunk reconstructs a copy. HEC 200 ≠ EVIDENCE READY. HTTP 200 ≠ execution.

## SPL audit result

`docs/AGENTSEC_SPLUNK_QUERY_VALIDATION.md`. 26 published Q-* hunts. No learner hunt teaches a nonexistent field as if it were indexed (`allowed_tools`, `session.id`, `gen_ai.tool.call.id`, write-run `memory.trust`). Empty-result semantics: no indexed event matched. Path B and Mastery bind existing Q-*.

## run.id audit result

LIVE launcher UUIDs ≠ Investigate REPLAY specimens for PI, MCP-001, RAG, Memory, Goal, Identity. Capstone Investigate uses official 16B UUIDs (historical copies). Memory WRITE ≠ RECALL; `source_run_id` links them. 17C relabeled Memory BASELINE/RETEST cards that had stamped **LIVE** on REPLAY pairs.

## Hash / fingerprint result

Official pairs use domain fingerprints (input, document, memory, instruction/task/proposed, claim). Fixture-name equality is not byte proof. Home ORIENT no longer says matching fingerprints “prove equivalent input.”

## Lab audits

| Lab | Result |
|-----|--------|
| PI | CTRL-INPUT-001 is the PDP. Splunk is not credited with prevention. Regex RETEST is not universal PI resistance. LEARN banner mixed LIVE vs REPLAY. |
| MCP | REQUEST ≠ GRANT; ALLOW ≠ EXECUTION; 0 DET-MCP-001 ≠ SAFE. Indexed `mcp.started` is corroboration; handler count is authoritative. |
| RAG | Exact-id fixtures. OBSERVE ≠ ALLOW. CTRL-MCP-001 is the tool PDP. No DET-RAG. No vector DB implied on Studio LEARN. |
| Memory | Two-run. STORED ≠ TRUSTED. 17C REPLAY labels on canonical pairs. |
| Goal | AUTHORIZED TOOL ≠ AUTHORIZED GOAL. Official RETEST: Goal DENY, MCP ALLOW, in-task handler 1. Copy already says RETEST is not MCP DENY. |
| Identity | IDENTITY CLAIM ≠ AUTHENTICATION. WHO AUTHENTICATED = NOT MODELED. No OAuth/OIDC/SPIFFE implied as implemented. |
| Capstone | retrieve → persist → later recall → CTRL-MCP-001. Goal/Identity 0 rows = NOT PRESENT in this packet (17C). Not collapsed into generic prompt injection. |
| Mastery | Incorrect claims remain incorrect. MA-PT1 Path B is a fragment, not the 15-point readout (17C). |
| Path A | Real index/sourcetype/run.id. PI-I1 no longer calls a REPLAY specimen a LIVE experiment by default. |
| Path B | Prose follows output; empty/DENY not auto-translated to prevented. |

## Detection / DET-MCP-001

`docs/AGENTSEC_DETECTION_CLAIM_AUDIT.md`. One packaged detector, disabled, DENY-then-start only. Silence ≠ SAFE. No DET-RAG/MEMORY/GOAL/A2A/CAPSTONE created.

## Control ownership / trust boundary / Attack Service

`docs/AGENTSEC_CONTROL_OWNERSHIP_MATRIX.md`. OBSERVE classifiers are not PDPs. Attack Service still uses allowlisted specimens and server-owned ExperimentContext. 17C qualified PI ATLAS id and MCP/Identity/Capstone “No mcp.started” expected-defended lines.

## LIVE / REPLAY / expected output / empty / privacy / framework / terminology

LIVE vs REPLAY distinguished after 17C Memory/PI fixes. Strong verbs audited. Empty = no indexed match. Privacy: hashes and bounded previews are indexed; Studio does not claim “no prompt bytes exist.” Framework: AML.T0054 REQUIRES REVALIDATION (educational qualifier on Attack Service). Terminology: OBSERVE, GRANT, EXECUTION, AUTHENTICATION used consistently after corrections.

## Cross-lab security model

DATA ≠ AUTHORITY. REQUEST ≠ GRANT. CLAIM ≠ AUTHENTICATION. AUTHORIZATION ≠ EXECUTION. TELEMETRY ≠ ENFORCEMENT. OBSERVE ≠ ALLOW. RETEST ≠ universal security. Matches implementation.

## LIVE evidence validation (this session)

Official pairs **still present** on the current Splunk volume. Class: **17C SESSION LIVE SPLUNK MEASURED** (completeness `dc(_raw)` + schema 1.9.0 + testbed.mode). Matches 14D–16B reports. No new attacks minted.

| Pair | ATTACK dc(_raw) | RETEST dc(_raw) |
|------|-----------------|-----------------|
| PI 14D | 22 | 6 |
| MCP-001 14E | 7 | 6 |
| RAG 15B | 10 | 9 |
| Memory recall 15C | 11 | 10 |
| Goal 15D | 10 | 10 |
| Identity 15E | 10 | 9 |
| Capstone recall 16B | 11 | 10 |

Representative Q-* **bodies** this session: **STATIC SPL REVIEW**. Historical hunt results remain **LIVE SPLUNK MEASURED** in the phase reports. Hunt re-execution was not completed in this session after completeness succeeded.

## REPLAY validation

Canonical Investigate ids remain bound in Studio builders. REPLAY workshops keep REPLAY SPECIMEN / historical evidence banners (17B). Do not infer LIVE behavior from REPLAY alone.

## Technical correctness matrix

`docs/AGENTSEC_TECHNICAL_CORRECTNESS_MATRIX.md`. All major LIVE labs + Capstone + Mastery **PASS** after copy corrections.

## Corrections made

1. Memory BASELINE/RETEST/COMPARE cards: **REPLAY SPECIMEN**, not **LIVE**, on canonical UUIDs.  
2. PI LEARN: **LIVE EXPERIMENT vs REPLAY SPECIMEN** (not **LIVE EVIDENCE** alone).  
3. Attack Service PI: AML.T0054 educational / REQUIRES REVALIDATION.  
4. `how-to-learn-agentic-security-with-agentsec.md` stamped HISTORICAL (15A).  
5. MA-PT1 Path B: not the 15-point readout; listed ids official historical REPLAY.  
6. Home fingerprint: hashed bytes of the named object, not “equivalent input.”  
7. MCP “Execution is mcp.started” → runtime authoritative, indexed started corroborates.  
8. Attack Service / MCP-003/004 expected-defended: no independent “No mcp.started” prevention claim.  
9. MCP-005 “executed correctly” → authorized and handler began, result not thereby trusted.  
10. Capstone Goal/Identity 0 rows: NOT PRESENT IN THIS PACKET.  
11. Duplicate Identity Attack Service expected-defended block merged (copy only).

Telemetry `technique_id_for` **unchanged** (emitter freeze).

## Findings after correction

| Severity | Count | Notes |
|----------|-------|-------|
| CRITICAL | 0 unresolved | No architecture/authority defect requiring STOP-and-redesign |
| HIGH | 0 unresolved | Relabeled LIVE-on-REPLAY, stale 15A note, unverified ATLAS as verified, MA-PT1 Path B as readout |
| MEDIUM | remaining backlog | Studio 10.2 cannot hide Path B; Goal “Do not start Phase 15E” builder-speak (frozen by dashboard tests); Splunk hunt bodies not re-executed this session |
| LOW | remaining | REPLAY LEARN still shows lineage schema 1.1.0–1.5.0 strings required by dashboard tests; PI README schema 1.0.0 lineage |

## Security semantics / schema

Unchanged. Schema **1.9.0**. No new detector. No new attack domain. No authorization architecture change.

## Tests / UI

Offline pytest: **934 passed, 2 deselected** (`uv run --extra test python -m pytest tests -q --tb=line -m "not live_ollama and not live_splunk"`). Pytest does not prove Splunk rendering or security effectiveness.

UI: Playwright of Home ORIENT, PI LEARN, Memory BASELINE, Mastery PURPLE TEAM, Attack Service at 1440/1280/1024 after restage + Splunk restart. Studio **PASS**. Attack Service docker image was not rebuilt; Flask pytest of the 17C template **PASS**. See `docs/reviews/ui-review-agentsec-academy-17c-2026-09-21.md`.

## Known limitations

- Official pairs are historical MEASURED copies still on this volume; they are not a launch the learner just minted.  
- Goal instruction/proposed hashes in Splunk remain PARTIALLY SUPPORTED via preview.  
- Capstone `attack.id` enum is RAG-001.  
- Path B is always visible on Studio 10.2.  
- Pytest does not prove Splunk rendering, learner understanding, or production scale.

## Recommendation for Phase 17D

Do **not** start Phase 17D from this file. If later explicitly requested, a defensible 17D would be research-only ATLAS remapping design (not an emitter bump) or a Path B-hiding Studio capability study — not a new lab, detector, MLTK, HITL, real A2A, OAuth, or schema bump.

## PHASE 17C VERDICT

**PASS** after copy corrections. Learner-facing security claims are identifiable, evidence-classed, and aligned with the runtime. Unresolved CRITICAL = 0. Unresolved HIGH = 0.
