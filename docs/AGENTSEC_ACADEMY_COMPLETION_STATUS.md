# Academy completion status (after Increment 11D)

Source of truth: `learning/academy/lab_registry_data.json` (32 entries) and the exported curriculum. Registry tiers are unchanged; nothing here promotes a lab to LIVE.

**26 of 32 have a native Academy experience:**
- 8 native: PI, MCP-001, Loan Desk, RAG, Memory, Goal, Delegation, Capstone.
- 3 recorded-evidence (Increment 11B): MCP-003, MCP-004, MCP-005.
- 6 recorded-evidence (Increment 11C): MCP-006, MCP-CATALOG, Scanner + Runtime Evidence, Blue-Team Incident, Multi-Stage Incident, Advanced Capstone.
- 9 simulated or documented checkpoints (Increment 11D): A2A Authentication and Delegation, Human Approval and Action Binding, Short-Lived Credential Lifetime, Code Agent Bounds, Change Bounds, RAG Purpose Authorization, Memory Ownership and Isolation, Component Provenance (simulated packets) and AI Asset Inventory (a documented component list). Each is labelled with its packet's own classification and "NOT A LIVE RUN".

## Blocked on missing recorded evidence

| Lab | Why it is blocked |
|---|---|
| LAB-SPLUNK-DEFENDER-BRIDGE | The lab consists of 10 SPL searches and a dashboard. It has no specimens and no evidence packet, and no Splunk search result is committed. The searches run only against a live index. |
| LAB-DETECTION-ENGINEERING | 3 SPL searches (broad, tuned, events) and a dashboard. No specimens, no packet, no committed search result. A coverage claim would need real results. |
| LAB-AGENT-IDENTITY-NHI | REPLAY tier with 3 SPL searches and a dashboard. No specimens, no evidence packet and no committed search result of its own. |

Acceptance criteria are not weakened. No search result, detection, coverage figure or identity record may be written by hand. What unblocks them: a committed export of real search results from a verified Splunk run, or a committed packet or specimen set for the lab, with its provenance.

## Remaining 6 entries

**Evidence-blocked investigations (3):** LAB-SPLUNK-DEFENDER-BRIDGE, LAB-DETECTION-ENGINEERING, LAB-AGENT-IDENTITY-NHI (above).

**Existing-runtime opportunity (1):** LAB-PRIVACY-DATA-GOVERNANCE-001. `src/agentsec/privacy/pipeline.py` implements PRIVACY-001 and is covered by `tests/security/test_l8_privacy_runtime.py`, but the lab is CONTENT-ONLY and not on the launch allowlist.

**Other incomplete entries (2):**
- LAB-THREAT-MODELING-001: a structured exercise (`architecture.json`, `threat-catalog.json`); no execution or recorded run.
- LAB-EXTERNAL-EVALUATION-GARAK: CONTENT-ONLY; the only recorded garak run (one probe, one model) lives in `docs/p1a-evidence/`, outside the lab directory.
