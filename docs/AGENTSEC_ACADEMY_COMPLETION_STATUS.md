# Academy completion status (after Increment 11C)

Source of truth: `learning/academy/lab_registry_data.json` (32 entries) and the exported curriculum. Registry tiers are unchanged; nothing here promotes a lab to LIVE.

**17 of 32 have a native Academy experience:** 8 native (PI, MCP-001, Loan Desk, RAG, Memory, Goal, Delegation, Capstone), 3 recorded-evidence (MCP-003/004/005, Increment 11B) and 6 recorded-evidence (MCP-006, MCP-CATALOG, Scanner + Runtime Evidence, Blue-Team Incident, Multi-Stage Incident, Advanced Capstone, Increment 11C).

## Blocked on missing committed Splunk search-result evidence

| Lab | Why it is blocked |
|---|---|
| LAB-SPLUNK-DEFENDER-BRIDGE | The lab consists of 10 SPL searches and a dashboard. It has no specimens and no evidence packet, and no Splunk search result is committed. The searches run only against a live index. |
| LAB-DETECTION-ENGINEERING | 3 SPL searches (broad, tuned, events) and a dashboard. No specimens, no packet, no committed search result. A coverage claim would need real results. |

Acceptance criteria are not weakened. No search result, detection or coverage figure may be written by hand. What unblocks them: a committed export of real search results from a verified Splunk run, with its provenance.

## Remaining 15 entries

**Simulated security and governance checkpoints (9)** — each has an `evidence.packet.json` labelled SIMULATED / REPLAYED or DOCUMENTED, with `not_runtime_*` flags. A simulated-packet explorer would reuse the recorded-evidence components and label everything SIMULATED.
LAB-A2A-AUTH-DELEGATION, LAB-ASSET-INVENTORY, LAB-CHANGE-BOUNDS, LAB-CODE-AGENT-BOUNDS, LAB-COMPONENT-PROVENANCE, LAB-CREDENTIAL-LIFETIME (partial explainer exists), LAB-HITL-APPROVAL, LAB-RAG-PURPOSE, LAB-RECALL-ISOLATION.

**Existing-runtime opportunities (1)**
LAB-PRIVACY-DATA-GOVERNANCE-001 — `src/agentsec/privacy/pipeline.py` implements PRIVACY-001 and is covered by `tests/security/test_l8_privacy_runtime.py`, but the lab is CONTENT-ONLY and not on the launch allowlist.

**Evidence-blocked investigations (3)**
LAB-SPLUNK-DEFENDER-BRIDGE and LAB-DETECTION-ENGINEERING (above), and LAB-AGENT-IDENTITY-NHI, which is in the same condition: REPLAY tier, 3 SPL searches, no specimens and no packet. Its status is not yet decided.

**Other incomplete entries (2)**
- LAB-THREAT-MODELING-001 — structured exercise (`architecture.json`, `threat-catalog.json`); no execution or recorded run.
- LAB-EXTERNAL-EVALUATION-GARAK — CONTENT-ONLY; the only recorded garak run (one probe, one model) lives in `docs/p1a-evidence/`, outside the lab directory.
