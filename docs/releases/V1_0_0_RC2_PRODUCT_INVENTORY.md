# AgentSec v1.0.0-rc2 — product inventory

Counted from the RC2 candidate tree. Not copied from the RC1 inventory. Schema **1.9.0**. ExternalEvidence **1.0.0**. Package **1.0.0rc2**. Splunk app **1.0.0-rc2**.

## Academy

`learning/academy/curriculum.json` has levels L0 through L10 (11) plus a separate Mastery Check view `ws_agentsec_mastery`.

| Level | Title | Launch |
|-------|-------|--------|
| L0 | Orientation | No. Academy Home |
| L1 | Input and tool authority | Two LIVE, two REPLAY |
| L2 | Context and evidence are data | Two LIVE, four REPLAY |
| L3 | Intent and identity | Two LIVE, one REPLAY |
| L4 | Investigation craft | No separate workshop |
| L5 | Integrated purple team | LIVE Capstone |
| L6 | Blue-team investigation and threat hunting | REPLAY |
| L7 | Threat modeling and security architecture | Static reasoning. Curriculum mode field is REPLAY because it is not a launcher. The lab adds no attack |
| L8 | Privacy, data protection and agentic data governance | REPLAY |
| L9 | Multi-stage agentic attack, investigation and defense | REPLAY |
| L10 | Advanced capstone and mastery | REPLAY |

## LIVE labs (7)

From `known_lab_ids()` / `EXPERIMENT_DEFINITIONS`. Each has ATTACK, BASELINE, and RETEST.

1. `LAB-PI-001` Direct Prompt Injection (L1)
2. `LAB-MCP-001` Tool Authorization (L1)
3. `LAB-RAG-CONTEXT` RAG / Retrieved Context (L2)
4. `LAB-MEMORY-001` Persistent Memory (L2)
5. `LAB-AGENT-GOAL-INTEGRITY-001` Goal / Instruction Integrity (L3)
6. `LAB-AGENT-DELEGATION-001` Agent Identity / Delegation (L3)
7. `LAB-AGENTSEC-CAPSTONE-001` Lending Assistant Investigation (L5)

## REPLAY workshops (11 curriculum rows whose activity is investigation of canonical evidence)

`LAB-MCP-003`, `LAB-MCP-004`, `LAB-MCP-005`, `LAB-MCP-CATALOG`, `LAB-SCANNER-RUNTIME-EVIDENCE`, `LAB-EXTERNAL-EVALUATION-GARAK`, `LAB-MCP-006`, `LAB-BLUE-TEAM-INCIDENT-001`, `LAB-PRIVACY-DATA-GOVERNANCE-001`, `LAB-MULTI-STAGE-INCIDENT-001`, `LAB-ADVANCED-CAPSTONE-MASTERY-001`.

## Static / reasoning

L0 Orientation, L4 investigation craft (practiced on LIVE Path A), L7 threat modeling (no fresh attack), Mastery Check (unscored questions).

## Studio dashboards

21 XML views under `splunk_app/agentsec/default/data/ui/views/`:

`ws_agentsec_home`, `ws_agentsec_mastery`, `ws_lab_pi_001`, `ws_lab_mcp_001`, `ws_lab_mcp_003`, `ws_lab_mcp_004`, `ws_lab_rag_context`, `ws_lab_memory_security`, `ws_lab_mcp_005`, `ws_lab_mcp_catalog`, `ws_lab_scanner_runtime_evidence`, `ws_lab_external_evaluation_garak`, `ws_lab_agent_goal_integrity`, `ws_lab_agent_delegation`, `ws_lab_mcp_006`, `ws_lab_agentsec_capstone`, `ws_lab_blue_team_incident`, `ws_lab_threat_modeling`, `ws_lab_privacy_data_governance`, `ws_lab_multi_stage_incident`, `ws_lab_advanced_capstone`.

RC1 inventory recorded 15 views. The difference is the later academy views, not a rename of the RC1 set.

## Attack Service

Closed launcher. It does not authorize tools. Allowlist length is the seven LIVE labs above.

## Runtime controls

Tool PDP: CTRL-MCP-001 (`coded_policy()`). RAG, memory, and identity observation do not mint tool grants. Goal control can refuse task expansion and does not mint a tool grant. Splunk does not authorize.

## Detectors

Inspected `splunk_app/agentsec/default/savedsearches.conf`.

| Object | State | Class |
|--------|-------|-------|
| `AgentSec - MCP Execution After Authorization Deny` (DET-MCP-001) | `disabled = 1`, `enableSched = 0` | Packaged detector, not enabled |
| `Q-RUN` | `disabled = 1` | Placeholder saved search |
| `Q-DENY` | `disabled = 1` | Placeholder saved search |

Installed and enabled detectors: **none**.

Candidate detection logic and educational SPL live in workshop searches (`learning/**/searches/`). Those files are not installed saved searches. Zero rows from DET-MCP-001 are not safe.

## External tools

| Tool | Creator | Pin | Adapter | Evidence class | Sourcetype | RC2 execution |
|------|---------|-----|---------|----------------|------------|---------------|
| mcp-scanner | Cisco AI Defense, https://github.com/cisco-ai-defense/mcp-scanner | cisco-ai-mcp-scanner 4.8.4 | `src/agentsec/external_evidence/cisco.py` | finding | `agentsec:scanner:finding` | REPLAYED / pack-based. Not a fresh CLI run for this release |
| garak | NVIDIA, https://github.com/NVIDIA/garak | 0.17.0 | `src/agentsec/external_evidence/garak.py` | evaluation | `agentsec:external:evaluation` | REPLAYED / pack-based. Native garak run id is not an `agentsec.run.id` |

Neither tool calls CTRL-MCP-001. The pin license string for garak is not a closed legal review. See `docs/EXTERNAL_VALIDATION_BACKLOG.md`.

Contract: `EXTERNAL_CONTRACT_VERSION = "1.0.0"`.

## Splunk

| Item | Value |
|------|-------|
| Index | `agentsec_telemetry` (`indexes.conf`) |
| Runtime sourcetype | `otel:agentic:json` (macro `agentsec_index`) |
| Scanner sourcetype | `agentsec:scanner:finding` |
| Evaluation sourcetype | `agentsec:external:evaluation` |
| Saved searches | 3 stanzas, all disabled |
| LIVE path | Attack Service mint, copy `run.id`, Search |
| REPLAY path | Specimen id on the workshop, Search |

HEC health is not searchable completeness. Indexed row count is not execution count when duplicate copies exist. `dc(_raw)` is the bounded completeness check.

## Schema and contracts

Runtime schema `1.9.0` (`SCHEMA_VERSION` in `src/agentsec/experiment.py`). ExternalEvidence `1.0.0`. Neither was bumped for RC2.

## Learner documentation

README, Quickstart, Getting Started, release lab matrix, LIVE vs REPLAY, product boundary, known limitations, instructor guide, this inventory, the RC2 release notes, and the RC2 validation report.
