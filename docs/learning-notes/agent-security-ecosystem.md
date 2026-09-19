# Agent security ecosystem 101

**Status:** Phase 8A learning note. Design/research only.  
**Parents:** `docs/AGENTSEC_EXPANSION_ARCHITECTURE.md`, `docs/AGENTSEC_OPEN_SOURCE_SECURITY_ECOSYSTEM.md`.

---

## WHAT IS IT?

A map of how AgentSec relates to the rest of the agent-security world: Cisco AI Defense OSS scanners, red-team harnesses, A2A, Splunk analytics, and AgentSec’s own MCP labs.

## WHY DOES IT EXIST?

After MCP-006, the next temptation is either “build MCP-007” or “paste scanner links into a UI.” This note is so you can explain why neither is the architecture.

## HOW DOES IT WORK?

AgentSec **builds** the property, the control placement, the telemetry, and the workshop. It **calls** mature scanners and eval tools and **imports** their JSON as evidence with an honesty label. Splunk investigates. Splunk does not authorize.

## WHERE DOES IT SIT IN AGENTSEC?

Process and roadmap (`docs/AGENTSEC_ROADMAP_2026.md`). Schema stays 1.4.0. No new runtime.

## WHAT IS THE TRUST BOUNDARY?

Runtime CTRL-* remain the only things that may DENY an LLM or MCP handler. A scanner verdict is **data** until a later lab proves a pre-op caller.

## WHAT COULD AN ATTACKER CONTROL?

In the next proposed lab: MCP tool **descriptions** and catalog documents — not only arguments and results (already taught).

## WHAT CAN GO WRONG?

- Scanner FAIL displayed as DENY
- ATLAS ids copied from old AgentSec code without revalidation
- A2A simulated with regex
- Antares used as a SOC analyst
- Zero Splunk rows called “safe”

## WHAT TELEMETRY SHOULD EXIST?

Today: control, hop, LLM, MCP, delegation, result-trust events. Later: optional scanner sourcetype; A2A/RAG/memory only with a lab.

## HOW WILL SPLUNK SHOW IT?

Not in 8A. Future hunts only after QUESTION → EVIDENCE → FIELD CONTRACT → `/splunk-ko-review`.

## WHAT CONTROL COULD CHANGE THE RESULT?

A catalog-integrity check before descriptions are trusted. CTRL-MCP-001 still sits before the handler.

## WHAT TEST PROVES THE LOGIC?

Phase 8A is design. `tests/unit/test_phase8a_design.py` checks the documents exist and stay DESIGN ONLY. It does not prove a scanner integration.

---

## What I should now be able to explain

1. Why AgentSec must not become a tool-link page.
2. What mcp-scanner, aibom, and DefenseClaw actually are (three different jobs).
3. Why Antares is not the next Splunk model.
4. CALL EXTERNALLY vs WRAP vs DO NOT INTEGRATE.
5. Why tool-description poisoning is the ranked next domain after MCP-006.
6. Why A2A needs `a2aproject/A2A`, not a fake protocol.
7. Why DET-MCP-001 must not become an anomaly model.
8. What CDTSM is (Splunk AI Toolkit preview) and when it is premature.
9. How ESTABLISHED vs AGENTSEC HYPOTHESIS must be labeled.
10. The exact recommended next phase name and why it is not MCP-007.
