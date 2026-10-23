# AgentSecLab curriculum inventory and coverage matrix

**Inventory date: 2026-10-23.** Read from the repository at the commit that adds this file (branch `feature/academy-react-shell`). Nothing in this file was executed or re-validated while writing it.

The authoritative scope is the original 12-domain curriculum and the 32 labs registered in `learning/academy/lab_registry_data.json`. This document keeps five claims apart. A lab can be one of the first four, and only some have the fifth:

| Term | Meaning | Source of truth |
|---|---|---|
| **Registered** | Listed in the lab registry with a primary domain and a tier. Registration says nothing about execution. | `learning/academy/lab_registry_data.json` |
| **Launchable** | On the Attack Service allowlist, so a live BASELINE / ATTACK / RETEST can be started through `/api/launch`. Seven labs. | `src/agentsec/launch_catalog.py` (`known_lab_ids()`), `docs/AGENTSEC_RELEASE_LAB_MATRIX.md` |
| **Replay** | Recorded evidence only. No live run. | registry tier `REPLAY` |
| **Content only** | Reading and knowledge checks. No execution. | registry tier `CONTENT-ONLY` |
| **Independently validated** | Documented as measured by a review. See section 4: this is narrower than "registered" or "launchable". | `docs/reviews/`, `docs/releases/` |

The registry tiers map to the Academy labels as: `GUIDED MISSION` = Guided, `WORKBENCH` = Workbench, `REPLAY` = Replay, `CONTENT-ONLY` = Content only. **Registry membership is not verified execution.**

Domain names follow the original curriculum. `learning/academy/taxonomy.json` titles D10 "Observability / forensics" and D12 "Risk / assurance"; the exported data keeps both names.

## 1. Coverage matrix by domain

Counts: Guided / Workbench / Replay / Content only. "Assets" are files the repository defines for the lab (hunt queries in `searches/`, specimens in `specimens/`, a Splunk Dashboard Studio view, knowledge-check questions in `knowledge-check.md`); their presence is not evidence that a run exists.

| Domain | Registered labs | G / W / R / C | Native in the React Academy | Missing or thin |
|---|---|---|---|---|
| D01 AI & Agent Foundations | 0 | 0 / 0 / 0 / 0 | Foundations lessons (4) | no registered lab; no assessment beyond the Mastery checks |
| D02 Prompt Injection | 2 | 1 / 1 / 0 / 0 | Loan Desk (guided) | PI-001 not integrated |
| D03 MCP & Tool Security | 5 | 1 / 0 / 4 / 0 | MCP-001 (guided) | 4 replay labs not integrated |
| D04 A2A & Delegation | 2 | 0 / 1 / 0 / 1 | none | both labs not integrated; A2A lab is content only |
| D05 RAG & Knowledge | 2 | 0 / 1 / 0 / 1 | none | both not integrated |
| D06 Memory & State | 2 | 0 / 1 / 0 / 1 | none | both not integrated |
| D07 Identity & Secrets | 3 | 0 / 0 / 2 / 1 | none | no live exercise; MCP-006 domain confidence is `review` |
| D08 Data Protection | 1 | 0 / 0 / 0 / 1 | none | single content-only lab |
| D09 Runtime Governance | 4 | 0 / 1 / 0 / 3 | none | 3 of 4 labs content only; GOAL-INTEGRITY domain confidence is `review` |
| D10 Agent Observability | 3 | 0 / 1 / 2 / 0 | none | only the capstone is launchable; scanner and bridge labs are replay |
| D11 Detection & Response | 4 | 0 / 0 / 4 / 0 | none | all four labs are replay; no live detection practice |
| D12 Risk & Assurance | 4 | 0 / 0 / 0 / 4 | none | all four labs are content only; no runnable evidence |

## 2. Lab inventory (32 registered labs)

`Launch` = on the Attack Service allowlist. `Hunts`, `Specimens` and `Checks` are counts of the lab's own files. `Sections` is how many of the 10 educational sections the Academy could source from the lab's files (the rest are shown as "not documented"). `Dash.` is a Splunk Dashboard Studio view that mentions the lab.

| Domain | Lab | Availability | Launch | Level | Hunts | Specimens | Checks | Sections | Dash. | Domain confidence |
|---|---|---|---|---|---|---|---|---|---|---|
| D02/D09 | `LAB-LOANDESK-001` | Guided | no | L1 | 8 | 0 | 4 | 3/10 | yes | content-verified |
| D02/D09 | `LAB-PI-001` | Workbench | yes | L1 | 12 | 4 | 14 | 10/10 | yes | content-verified |
| D03 | `LAB-MCP-001` | Guided | yes | L1 | 28 | 3 | 13 | 10/10 | yes | content-verified |
| D03 | `LAB-MCP-003` | Replay | no | L1 | 0 | 4 | 12 | 8/10 | yes | content-verified |
| D03 | `LAB-MCP-004` | Replay | no | L1 | 5 | 7 | 15 | 8/10 | yes | content-verified |
| D03/D02 | `LAB-MCP-005` | Replay | no | L2 | 3 | 4 | 10 | 9/10 | yes | content-verified |
| D03/D02 | `LAB-MCP-CATALOG` | Replay | no | L2 | 12 | 3 | 13 | 5/10 | yes | content-verified |
| D04/D07 | `LAB-A2A-AUTH-DELEGATION` | Content only | no | - | 1 | 0 | 0 | 2/10 | yes | content-verified |
| D04/D07 | `LAB-AGENT-DELEGATION-001` | Workbench | yes | L3 | 3 | 3 | 10 | 10/10 | yes | content-verified |
| D05/D02 | `LAB-RAG-CONTEXT` | Workbench | yes | L2 | 3 | 3 | 20 | 10/10 | yes | content-verified |
| D05/D08 | `LAB-RAG-PURPOSE` | Content only | no | - | 1 | 0 | 0 | 2/10 | yes | content-verified |
| D06/D02 | `LAB-MEMORY-001` | Workbench | yes | L2 | 3 | 6 | 30 | 10/10 | yes | content-verified |
| D06/D08 | `LAB-RECALL-ISOLATION` | Content only | no | - | 1 | 0 | 0 | 2/10 | yes | content-verified |
| D07 | `LAB-AGENT-IDENTITY-NHI` | Replay | no | - | 3 | 0 | 0 | 2/10 | yes | content-verified |
| D07 | `LAB-CREDENTIAL-LIFETIME` | Content only | no | - | 1 | 0 | 0 | 2/10 | yes | content-verified |
| D07/D03 | `LAB-MCP-006` | Replay | no | L3 | 3 | 3 | 12 | 9/10 | yes | review |
| D08 | `LAB-PRIVACY-DATA-GOVERNANCE-001` | Content only | no | L8 | 3 | 0 | 15 | 2/10 | yes | content-verified |
| D09/D02 | `LAB-AGENT-GOAL-INTEGRITY-001` | Workbench | yes | L3 | 3 | 3 | 20 | 10/10 | yes | review |
| D09 | `LAB-CHANGE-BOUNDS` | Content only | no | - | 0 | 0 | 0 | 2/10 | yes | content-verified |
| D09 | `LAB-CODE-AGENT-BOUNDS` | Content only | no | - | 0 | 0 | 0 | 2/10 | yes | content-verified |
| D09/D07 | `LAB-HITL-APPROVAL` | Content only | no | - | 1 | 0 | 0 | 2/10 | yes | review |
| D10/D05 | `LAB-AGENTSEC-CAPSTONE-001` | Workbench | yes | L5 | 1 | 9 | 10 | 9/10 | yes | review |
| D10/D03 | `LAB-SCANNER-RUNTIME-EVIDENCE` | Replay | no | L2 | 0 | 4 | 15 | 3/10 | no | content-verified |
| D10/D11 | `LAB-SPLUNK-DEFENDER-BRIDGE` | Replay | no | - | 10 | 0 | 0 | 2/10 | yes | content-verified |
| D11/D12 | `LAB-ADVANCED-CAPSTONE-MASTERY-001` | Replay | no | L10 | 6 | 3 | 7 | 2/10 | yes | review |
| D11/D10 | `LAB-BLUE-TEAM-INCIDENT-001` | Replay | no | L6 | 3 | 7 | 12 | 3/10 | yes | content-verified |
| D11 | `LAB-DETECTION-ENGINEERING` | Replay | no | - | 3 | 0 | 0 | 2/10 | yes | content-verified |
| D11/D10 | `LAB-MULTI-STAGE-INCIDENT-001` | Replay | no | L9 | 6 | 11 | 14 | 2/10 | yes | review |
| D12 | `LAB-ASSET-INVENTORY` | Content only | no | - | 0 | 0 | 0 | 2/10 | yes | review |
| D12/D09 | `LAB-COMPONENT-PROVENANCE` | Content only | no | - | 0 | 0 | 0 | 2/10 | yes | review |
| D12/D02 | `LAB-EXTERNAL-EVALUATION-GARAK` | Content only | no | L2 | 2 | 0 | 15 | 3/10 | yes | content-verified |
| D12 | `LAB-THREAT-MODELING-001` | Content only | no | L7 | 0 | 0 | 15 | 3/10 | yes | content-verified |

Loan Desk (`LAB-LOANDESK-001`) is registered as Guided but is not on the Attack Service allowlist: it runs through its own mission service in AcmeBank, proxied by the Attack Service under `/api/missions/loan-desk/*`.

Sources per lab: `learning/level_1/<LAB>/{README,workshop,evidence,dashboard,knowledge-check}.md`, `lab-manifest.json`, `specimens/`, `searches/`, and `splunk_app/agentsec/default/data/ui/views/ws_lab_*.xml`. The exporter `scripts/export_curriculum.py` records the exact file for every sentence the Academy shows.

## 3. Reusable infrastructure and content

- React Academy shell, `StageGuide`, `StepList` / `RunProgress`, Mastery framework, and `scripts/export_academy_content.py` (Foundations and workshop checks).
- Template-only SPL gateway over the host verifier bridge (`src/agentsec/loan_desk/search.py`, `verifier.py`, `verify_bridge.py`) with signed receipts. Currently bound to Loan Desk run ids and fields.
- Generic launch API (`/api/launch`, `/api/launches/<id>`, `/api/launches/<id>/evidence`, `/api/compare-handoff`) used by the guided MCP exercise.
- 37 Splunk Dashboard Studio views (32 `ws_lab_*`), 3 saved searches (`Q-RUN`, `Q-DENY`, and the MCP execution-after-deny detection), 20 `knowledge-check.md` files, `learning/academy/assessments.json` (self-assessed competencies for L6 to L10), and `learning/academy/curriculum.json` (levels L0 to L10).
- Scanner and evidence code: `src/agentsec/scanners/` (pinned Cisco MCP scanner adapter, evidence model, HEC events), `src/agentsec/external_evidence/` (garak), `src/agentsec/goal/`, `src/agentsec/privacy/`.

## 4. Validation evidence that exists (as documented, not re-run here)

- **Seven launchable labs.** `docs/releases/V1_0_0_RC1_REPRODUCIBILITY.md` records the seven-lab ATTACK and RETEST pairs as MEASURED at RC1. `docs/reviews/AGENTSEC_INDEPENDENT_RC2_VALIDATION.md` (the "Allowlist check") records that the allowlist has 7 labs, each with ATTACK, BASELINE and RETEST, class MEASURED; the same review states it did not re-execute live Splunk. Treat these as historical to their phases.
- **Loan Desk and MCP-001 in the React Academy.** Accepted on the EC2 deployment on 2026-10-23 (attack and defended retest, host-verifier receipts for Loan Desk, MCP launch records). There is no repository report for that acceptance yet.
- **All other labs.** No validation record was found by this inventory. Absence of a record is not a finding that a lab fails.

## 5. Advanced tooling mapped as potential integrations (nothing is installed)

The progression is Learn (beginner), Practice (intermediate), Prove (advanced). External tooling belongs to Prove, and always as *evidence to interpret*, never as enforcement.

| Tool | Where it would sit | Status in the repository |
|---|---|---|
| Uber ADR, <https://github.com/uber/ADR> | Advanced / Prove for D10 Agent Observability and D11 Detection & Response | Requested by the owner on 2026-10-23. Not installed; its scope was not reviewed in this inventory. Evaluate license, runtime needs, data model and sandboxing before any integration. |
| Cisco mcp-scanner | D03, D10 | Integrated and pinned (`src/agentsec/scanners/cisco_mcp_scanner.py`); `docs/AGENTSEC_BUILD_VS_INTEGRATE.md`: INTEGRATE, call externally and import output |
| Cisco a2a-scanner | D04 | `docs/AGENTSEC_BUILD_VS_INTEGRATE.md`: INTEGRATE, call externally after an A2A lab; not installed |
| Cisco skill-scanner | D03, D12 | same document: INTEGRATE when a skill lab exists; not installed |
| Cisco AI-BOM | D12 | same document: INTEGRATE, import output; `LAB-ASSET-INVENTORY` is explicitly not an AI-BOM |
| garak | D02, D12 | external-evidence adapter exists (`src/agentsec/external_evidence/`); `LAB-EXTERNAL-EVALUATION-GARAK` is content only |
| PyRIT, promptfoo, llm-guard | D02, D09 | mentioned in repository documents as candidates; not integrated |

## 6. Provenance and regeneration

`scripts/export_curriculum.py` generates `academy-ui/src/content/curriculum.json` from the sources named above. Learner explanations are authored in `learning/academy/explainers/<LAB>.json` (currently `LAB-PI-001` and `LAB-CREDENTIAL-LIFETIME`); each block names its sources and lists facts that the tests verify word for word against them. The explanation prose itself is written for learners and is labelled as such in the Academy. A test (`tests/test_curriculum_explorer.py`) checks that the export matches its sources, that every registered lab and domain appears exactly once, that availability equals the registry tier, and that every sentence shown to learners appears verbatim in the file it cites. This document's lab table was generated from that export on the inventory date.
