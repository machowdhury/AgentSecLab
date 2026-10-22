# Batch 5, Priority 2: security coverage traceability matrix (read-only)

## 0. Read this first: the "30 controls" list was not available

The request refers to "all 30 controls across the six security categories I supplied". **That list is not in this
conversation (searched every user message), not in the repository, and not in the session transcript.** I will not
reconstruct 30 controls from memory or from lesson titles. What follows is the evidence-based inventory of what the
repository actually contains, keyed the way the repo keys itself:

- **§2** all **32 labs** in `learning/academy/lab_registry_data.json` (each carries its domain D01–D12 and Control Plane pillar P1–P6),
- **§3** the **10 `CTRL-*` controls** (plus one grant configuration) that exist in source,
- **§4** the **17 candidate subjects** the founder listed in the Master Vision §5.

Send the 30-control list and I will map each to rows here; most will land on an existing row or in §5 (MISSING).
The six repo pillars (P1 AI-SPM/Discover, P2 Identity & Governance, P3 Guardrails & Gateways/Protect, P4 Detection &
Response, P5 Security Agents/Act, P6 Continuous Verification) may or may not be your six categories. I have not assumed so.

## 1. Classification rules (applied literally, never from a title)

| Class | Meaning here |
|---|---|
| **VERIFIED LIVE** | A launchable lab (Attack Service or the Loan Desk mission) whose enforcement code ran in this batch's stack, whose BASELINE/ATTACK/RETEST differ in the control's decision as designed, and whose events were found in Splunk. |
| **PARTIAL** | Runs live or has real code, but the control is observe-only, the differential is not shown, a stage is not exercised, or the runtime path is not reachable from the Academy. |
| **REPLAY** | Dashboard and searches over recorded or pipeline-generated evidence. No learner-launched run. |
| **CONTENT-ONLY** | Lesson, searches or dashboard with no runtime component that I could find. |
| **PLANNED / MISSING** | Named in the vision or registry but nothing exists (PLANNED when the registry says so). |

Evidence for "VERIFIED LIVE" is `live_lab_sweep.json`: 21 launches via the public `POST /api/launch` (fields `lab_id,
specimen_id, mode, execution` only), each found in Splunk (events indexed, control decisions read back). The Loan Desk
mission was verified in Batches 3–4 with run reconciliation. Indexed-count > 0 is not full reconciliation for the sweep
(the launch API does not return a local event count); the sweep matches the figures documented in earlier phases
(LAB-PI-001 baseline 22, LAB-MCP-001 attack 7 / retest 6).

## 2. Lab-by-lab matrix (32 labs)

Columns: **Enforcement** is what actually decides or merely records. **Splunk** lists the artifacts that exist (search
files `.spl` / Studio view). **Tests** is the count of test files that mention the lab id.

### 2.1 Launchable LIVE (8)

| Lab | Class | Lesson | Source | Enforcement | Attack → Defense | Splunk | Runtime evidence | Dom·Pillar | Missing |
|---|---|---|---|---|---|---|---|---|---|
| LAB-PI-001 | **VERIFIED LIVE** | workshop, README, KC | `controls.py`, `attacks.py`, `attack_app.py`, `launch_service.py` | **CTRL-INPUT-001 PDP** before the model | Direct injection → input gate DENY, zero LLM calls | 5 `.spl`, view | BASELINE 22 ev ALLOW; ATTACK 22 ALLOW; RETEST 6 DENY | D02 · P3 impl, P4/P6 partial | Gate is pattern-based; no bypass/evasion exercise; 1B model |
| LAB-MCP-001 | **VERIFIED LIVE** | workshop, README | `mcp/authorize.py`, `mcp/policy.py`, `mcp/pipeline.py` | **CTRL-MCP-001 PDP** (tool, scope, resource) | Out-of-scope tool call → DENY before handler | 13 `.spl`, 3 committed specimen packs, view | BASELINE 7 ALLOW; ATTACK 7 ALLOW; RETEST 6 DENY | D03 · P3 impl, P2/P4/P6 partial | Deterministic caller, not a model choosing tools |
| LAB-LOANDESK-001 | **VERIFIED LIVE** | 10-step mission, README, KC | `loan_desk/*`, `mission_loan_desk.py` | **CTRL-LOANDESK-001 PDP** + argument constraint (HARDENED) | Planted note rides a valid call → DENY `argument_not_allowed:note` | 7 `.spl`, view | Real model, Batch 3–4: 20/20 baseline harm, 0/20 hardened (host); Splunk-reconciled | D02 · P3 impl, P4/P6 partial | One model; hardened run may not finish the business task; verifier is a host process |
| LAB-AGENT-GOAL-INTEGRITY-001 | **VERIFIED LIVE** | workshop, README | `goal/trust.py`, `goal/*` | **CTRL-GOAL-INTEGRITY-001** (task expansion) | Instruction expands task → DENY `unauthorized_task_expansion` | 1 `.spl` | BASELINE 10 ALLOW+OBSERVE; ATTACK 10 ALLOW+OBSERVE; RETEST 10 ALLOW+**DENY** | D09 · P3 impl | Scripted proposer, not a model; one scenario |
| LAB-RAG-CONTEXT | **PARTIAL** | workshop, README | `rag/context_trust.py`, `rag/*` | CTRL-RAG-CONTEXT-001 is **OBSERVE only**; the RETEST DENY comes from CTRL-MCP-001 on the downstream tool | Poisoned doc → tool call; defense is the tool PDP, not a retrieval control | 1 `.spl`, view | BASELINE 5 OBSERVE; ATTACK 10 ALLOW+OBSERVE; RETEST 9 DENY+OBSERVE | D05 · P3 impl, P4/P6 partial | No control that stops poisoned retrieval itself; no ranking/provenance enforcement |
| LAB-MEMORY-001 | **PARTIAL** | workshop, README | `memory/trust.py`, `memory/*` | CTRL-MEMORY-CONTEXT-001 **OBSERVE only**; DENY from CTRL-MCP-001 | Poisoned memory recalled later → tool call; DENY downstream | 1 `.spl` | BASELINE 6 OBSERVE; ATTACK 11; RETEST 10 DENY | D06 · P3 impl | No memory write/recall enforcement; cross-session isolation not tested live |
| LAB-AGENT-DELEGATION-001 | **PARTIAL** | workshop (no README body) | `identity/trust.py`, `identity/*` | CTRL-IDENTITY-001 **OBSERVE only** ("not authentication"); DENY from CTRL-MCP-001 | Claimed identity/scope → DENY downstream | 1 `.spl` | BASELINE 10; ATTACK 10 ALLOW+OBSERVE; RETEST 9 DENY+OBSERVE | D04 · P3 impl, P2 partial | No authentication, no token/audience binding, identities are labels |
| LAB-AGENTSEC-CAPSTONE-001 | **PARTIAL** | workshop, README | `launch_service.py`, `memory/trust.py` | Single launch exercises only the RETRIEVE stage (RAG OBSERVE) | Full story needs three run ids (retrieve, write, recall) | view, 0 `.spl` | **BASELINE, ATTACK and RETEST each emitted the same 5 events and one OBSERVE decision**; lifecycle across 3 runs not driven here | D10 · P3 impl | Mode has no visible effect on a single launch; end-to-end 3-run lifecycle unverified this batch |

### 2.2 REPLAY (12)

| Lab | Class | Source | Enforcement | Scenario | Splunk | Evidence | Dom·Pillar | Missing |
|---|---|---|---|---|---|---|---|---|
| LAB-MCP-003 | REPLAY | `mcp/authorize.py` (scope path) | CTRL-MCP-001 exists in code and tests (8 test files) but is not launchable from the Academy | Scope escalation → DENY | 0 `.spl`, view, workshop | No committed pack | D03 · P3/P6 partial | Not launchable; specimen availability on a fresh install **not verified** |
| LAB-MCP-004 | REPLAY | `authorize_resource` | CTRL-MCP-001 resource binding; README records "validated LIVE specimens (Phase 5C)" that are **not reproducible from the Academy** | Resource/parameter authorization | 2 `.spl`, view | No committed pack | D03 · P3/P6 partial | As above |
| LAB-MCP-005 | REPLAY | `mcp/result_trust.py` | CTRL-MCP-RESULT-001 **OBSERVE only** | Tool-result poisoning | 1 `.spl`, view | No committed pack | D03 · P3 partial | No result sanitisation control |
| LAB-MCP-006 | REPLAY | `mcp/delegation_pipeline.py`, `mcp/delegation.py` | **CTRL-DELEGATION-001 PDP** (deputy grant check) in code | Confused deputy | 1 `.spl`, view | No committed pack | D07 · P2/P3 partial | Not launchable |
| LAB-MCP-CATALOG | REPLAY | `mcp/metadata_trust.py`, `scanners/catalog_export.py` | CTRL-MCP-METADATA-001 **OBSERVE only** | Tool-description poisoning | 5 `.spl`, view | No committed pack | D03 · P1/P3 partial | No pin/diff/approval control |
| LAB-AGENT-IDENTITY-NHI | REPLAY | none specific | none | Non-human identity | 3 `.spl`, view | No pack | D07 · P2 partial | No runtime |
| LAB-ADVANCED-CAPSTONE-MASTERY-001 | REPLAY | none specific | none | Incident MASTER-2026-001 | 6 `.spl` | No pack | D11 · P4/P6 partial | |
| LAB-BLUE-TEAM-INCIDENT-001 | REPLAY | none specific | none ("adds no attack, detector, control") | Incident AI-2026-001 investigation | 3 `.spl` | No pack | D11 · P4 partial | |
| LAB-MULTI-STAGE-INCIDENT-001 | REPLAY | none specific | none | Incident AGENT-2026-009 | 6 `.spl` | No pack | D11 · P4/P6 partial | |
| LAB-DETECTION-ENGINEERING | REPLAY | none specific | none; 5 positive-control searches generate data with `makeresults` (labelled SIMULATED) | Detection design | 3 `.spl`, view | Simulated positives only | D11 · P4/P6 partial | **No detection verified against a live attack run** |
| LAB-SCANNER-RUNTIME-EVIDENCE | REPLAY | `scanners/*` | external scanner evidence, no PDP | Scanner vs runtime evidence | 0 `.spl`, view | No pack | D10 · P1/P4 partial | |
| LAB-SPLUNK-DEFENDER-BRIDGE | REPLAY | none specific | none | Telemetry duplication, field quirks | 10 `.spl`, view | Reads live index | D10 · P4 partial | **Content depends on the duplicate extraction** (see STABILITY_FINDINGS §1) |

### 2.3 CONTENT-ONLY (12)

| Lab | Class | What exists | Enforcement | Dom·Pillar | Notes |
|---|---|---|---|---|---|
| LAB-HITL-APPROVAL | CONTENT-ONLY | `evidence.packet.json` labelled "SIMULATED / REPLAYED", `approval_authority: NOT PROVEN`, 1 search, view | none | D09 · P2/P3 partial | No approval workflow exists in `src/` |
| LAB-A2A-AUTH-DELEGATION | CONTENT-ONLY | view, 1 search | none | D04 · P2 partial | No A2A protocol endpoint exists |
| LAB-ASSET-INVENTORY | CONTENT-ONLY | view | none | D12 · P1 partial | No inventory data |
| LAB-CHANGE-BOUNDS | CONTENT-ONLY | view | none | D09 · P2/P3 partial | |
| LAB-CODE-AGENT-BOUNDS | CONTENT-ONLY | view | none | D09 · P2/P3 partial | No code-agent exists |
| LAB-COMPONENT-PROVENANCE | CONTENT-ONLY | view | none | D12 · P1 partial | |
| LAB-CREDENTIAL-LIFETIME | CONTENT-ONLY | view, 1 search | none | D07 · P2 partial | No credential issuance or expiry in the lab |
| LAB-EXTERNAL-EVALUATION-GARAK | CONTENT-ONLY (registry) | README, workshop, 2 searches; adapter code under `external_evidence/` exists but a garak run was **not exercised** in this audit | none | D12 · P6 partial | Registry tier kept; not upgraded without a run |
| LAB-PRIVACY-DATA-GOVERNANCE-001 | **registry says CONTENT-ONLY; code says more** | `privacy/pipeline.py` runs one tool through the MCP PDP with a synthetic record (`run_privacy_specimen`); a CLI exists. Not launchable from the Academy; not run in this audit | CTRL-MCP-001 via `privacy_policy()` | D08 · P1/P3 partial | **Registry tier looks stale**; treat as PARTIAL pending a run |
| LAB-RAG-PURPOSE | CONTENT-ONLY | view, 1 search | none | D05 · P3 partial | |
| LAB-RECALL-ISOLATION | CONTENT-ONLY | view, 1 search | none | D06 · P3 partial | |
| LAB-THREAT-MODELING-001 | CONTENT-ONLY (README says REPLAY / architecture) | README, templates | none | D12 · P1 partial, P6 **planned** | Only entry with a `planned` pillar status |

Totals (32): **4 VERIFIED LIVE**, **4 PARTIAL** (live), **12 REPLAY**, **12 CONTENT-ONLY** by registry tier (one of those,
PRIVACY, probably belongs under PARTIAL). No lab is MISSING because the registry only contains labs that exist; MISSING lives in §4.

## 3. The 10 `CTRL-*` controls (and one grant config) that exist in source

| Control | File | Kind | Decision | Used by | Runtime evidence this batch |
|---|---|---|---|---|---|
| CTRL-INPUT-001 | `controls.py` | **Enforcement** (PDP before the model) | ALLOW / DENY | PI-001 | ALLOW×2, DENY×1 in Splunk |
| CTRL-MCP-001 | `mcp/authorize.py` | **Enforcement** (sole tool PDP) | ALLOW / DENY | MCP-001, RAG, MEMORY, DELEGATION, PRIVACY, capstone | ALLOW and DENY seen live |
| CTRL-GOAL-INTEGRITY-001 | `goal/trust.py` | **Enforcement** (task expansion only) | OBSERVE / DENY | GOAL | DENY seen live |
| CTRL-LOANDESK-001 | `loan_desk/policy.py` | **Enforcement** (+ argument constraint) | ALLOW / DENY | Loan Desk | Real model, Batches 3–4 |
| CTRL-DELEGATION-001 | `mcp/delegation.py` | **Enforcement** (deputy gate) | ALLOW / DENY | MCP-006 | not exercised live |
| CTRL-RAG-CONTEXT-001 | `rag/context_trust.py` | Observation | OBSERVE | RAG, capstone | OBSERVE seen live |
| CTRL-MEMORY-CONTEXT-001 | `memory/trust.py` | Observation | OBSERVE | MEMORY | OBSERVE seen live |
| CTRL-IDENTITY-001 | `identity/trust.py` | Observation ("not authentication") | OBSERVE | DELEGATION | OBSERVE seen live |
| CTRL-MCP-RESULT-001 | `mcp/result_trust.py` | Observation | OBSERVE | MCP-005 | not exercised live |
| CTRL-MCP-METADATA-001 | `mcp/metadata_trust.py` | Observation | OBSERVE | MCP-CATALOG | not exercised live |
| `coded_policy()` | `mcp/policy.py` | Grant configuration, not a decision | none | all MCP labs | n/a |

Five controls decide (INPUT, MCP, GOAL, LOANDESK, DELEGATION). **Five record only.** A learner can be told a control
"defends" when it only observes; the lab text already says so for some (identity), so the matrix keeps the distinction.
Other `CTRL-*` strings found in `docs/` (`CTRL-AUTHN-001`, `CTRL-HITL-001`, `CTRL-DATA-003`, `CTRL-A2A-005`,
`CTRL-RUNTIME-004`) have **no implementation in `src/`**; they are design text.

## 4. Master Vision §5 subjects (the 17 the founder listed)

| # | Subject | Best current coverage | Class |
|---|---|---|---|
| 1 | Direct and indirect prompt injection | Direct: PI-001, Loan Desk (stored note). Indirect via RAG/memory: partial | **VERIFIED LIVE** (direct, stored); PARTIAL (indirect) |
| 2 | Tool-output poisoning | MCP-005 | REPLAY (observe-only control) |
| 3 | MCP misuse / confused deputy | MCP-001 live; MCP-006 | VERIFIED LIVE / REPLAY |
| 4 | Agent identity and authorization failures | DELEGATION-001, NHI | PARTIAL / REPLAY |
| 5 | Delegation and privilege escalation | MCP-003, DELEGATION-001 | REPLAY / PARTIAL |
| 6 | Agent-to-agent trust boundaries | A2A-AUTH-DELEGATION | CONTENT-ONLY. No A2A runtime: **MISSING live** |
| 7 | RAG document poisoning | RAG-CONTEXT | PARTIAL |
| 8 | Memory poisoning and persistence | MEMORY-001 | PARTIAL |
| 9 | Goal hijacking / task expansion | GOAL-INTEGRITY-001 | VERIFIED LIVE (scripted proposer) |
| 10 | Sensitive-data exposure and exfiltration | PRIVACY (data minimisation); no exfiltration channel | PARTIAL / **MISSING** (exfil) |
| 11 | Credential, OAuth and secret misuse | CREDENTIAL-LIFETIME | CONTENT-ONLY / **MISSING live** |
| 12 | Supply chain in tools and dependencies | MCP-CATALOG, COMPONENT-PROVENANCE, scanners | REPLAY / CONTENT-ONLY |
| 13 | Unsafe autonomous actions | Loan Desk (`issue_loan_offer` never granted) | VERIFIED LIVE for one action; CODE-AGENT-BOUNDS CONTENT-ONLY |
| 14 | Human-in-the-loop approval failures | HITL-APPROVAL | CONTENT-ONLY (simulated); **MISSING live** |
| 15 | Runtime forensics / incident reconstruction | BLUE-TEAM, MULTI-STAGE | REPLAY |
| 16 | Detection engineering / SOC investigation | DETECTION-ENGINEERING | REPLAY, simulated positives only |
| 17 | Risk-based correlation / response automation | none | **MISSING** |

## 5. Gaps summarised
- **Model-driven live labs: 1 of 8.** Only the Loan Desk has a real model choosing actions. Every other LIVE launch except PI-001 returned in under 0.1 s, i.e. ran no model inference (PI-001 calls a 1B model for text, not for action choice), so those labs teach the control, not the failure of a model.
- **Controls that only observe: 5 of 10.** RAG, memory, identity, result and metadata trust do not prevent anything.
- **No live detection.** No lab fires a Splunk detection against a live attack run; detection teaching rests on simulated positives and replay.
- **Specimen availability on a fresh install:** only LAB-MCP-001 has committed REPLAY packs (3). The other 11 REPLAY labs' dropdowns depend on data that this audit could not show a fresh learner would have.
- **Registry drift:** LAB-PRIVACY-DATA-GOVERNANCE-001 is understated; LAB-AGENTSEC-CAPSTONE-001's launch does not differentiate modes.
