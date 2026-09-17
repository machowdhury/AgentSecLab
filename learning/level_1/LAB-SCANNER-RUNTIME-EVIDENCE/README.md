# LAB-SCANNER-RUNTIME-EVIDENCE

**Level:** 1  
**Difficulty:** GUIDED  
**Schema:** `agentsec.security_event` 1.5.0 (runtime). Scanner sourcetype `agentsec:scanner:finding` is independent.  
**Invariant:** INV-002 (Data Cannot Grant Authority)  
**Controls:** CTRL-MCP-METADATA-001 (OBSERVE) then CTRL-MCP-001 (authorization). Scanner is not a control.  
**Status:** Phase 9E Dashboard Studio workshop (`ws_lab_scanner_runtime_evidence`). **DETECTION ANALYZED — NO NEW DETECTOR.** No DET-SCANNER. No DET-MCP-CATALOG.

This workshop teaches one question: **when an external security scanner flags agent/tool metadata, what can the SOC actually conclude from that evidence?**

It is not a second catalog-poisoning runtime. LAB-MCP-CATALOG already taught whether malicious metadata can influence a request without becoming authority. Phase 9E teaches how a SOC combines:

1. external scanner evidence
2. runtime metadata evidence
3. authorization evidence
4. execution evidence

without collapsing any of them.

SCANNER FINDING != AUTHORIZATION DECISION  
SCANNER HIGH != HIGH-SEVERITY INCIDENT  
ZERO FINDINGS != SAFE  
METADATA OBSERVED != AUTHORIZED  
REQUEST != GRANT  
ALLOW != EXECUTION  
mcp.started != SUCCESS  
DENY + NO SPLUNK EVENT != INDEPENDENT PROOF OF NON-EXECUTION  
SPLUNK != ENFORCEMENT

## Learner objectives

After this lab you should be able to:

1. Name the three evidence planes and what each can prove.
2. Read ZERO FINDINGS as scan-executed-with-zero-findings, not SAFE.
3. Keep scanner-native HIGH as scanner-native severity.
4. Correlate scanner and runtime evidence with description SHA-256, not artifact.sha256.
5. Show ATTACK and RETEST used the same malicious description hash.
6. Explain ATTACK execution as the vulnerable profile, not scanner HIGH.
7. Explain RETEST non-execution as CTRL-MCP-001 DENY plus runtime handler count 0.
8. Explain why DET-MCP-001 returns 0 for ATTACK and 0 for RETEST.
9. State Phase 9D: DETECTION ANALYZED — NO NEW DETECTOR.
10. Say what a SOC would still need before promoting this hunt to a production detection.

## Prerequisite knowledge

- LAB-MCP-CATALOG workshop (`ws_lab_mcp_catalog`).
- Phase 8D runtime Splunk evidence.
- Phase 9C scanner Splunk evidence.
- Phase 9D detection analysis.

Not required: Snyk Agent Scan, rug-pull / `list_changed`, A2A, MCP-007, Phase 10.

## Lab architecture

```text
MCP catalog
    |
    +----> Cisco mcp-scanner ----> Artifact Evidence  (PLANE 1)
    |
    +----> Agent runtime
               |
               +--> Metadata Observation  (PLANE 2)
               |
               +--> Follow-on Request --> CTRL-MCP-001  (PLANE 3)
                                          ALLOW --> execution
                                          DENY  --> X
```

External security evidence and runtime authorization answer different questions. Scanner evidence does not feed CTRL-MCP-001.

## Validated evidence (do not rerun to prettify)

Runtime (Phase 8D):

- BASELINE `d95717ed-ffd2-46c0-a130-9a5d7d539a5d` NORMAL hash `sha256:8a76d34c6c21fda0dc930fa2f64fe87c3216f23cbc73ca357c47b0927850d9c3`
- ATTACK `a0937bff-31a5-453a-99bf-47d7b5148ce4` MALICIOUS hash `sha256:9d0745320ca79852f2fbd7145bf074fcd353e290c18ba16fd02d801f9f3375b1` ALLOW + handler 1
- RETEST `23c222ea-6a87-40b7-a3e9-f12a5b572fa1` **same MALICIOUS hash** DENY `tool_not_granted` handler 0

Scanner (Phase 9B/9C):

- NORMAL `b3061c4e-7a81-445c-8fd8-3108dd14c419` finding_count=0
- MALICIOUS `7ae3ea64-4e7a-40fe-943f-3e582bce5ee8` finding_count=1 native HIGH PROMPT INJECTION

## How to run the workshop

Open Splunk → AgentSec → **LAB-SCANNER-RUNTIME Scanner + Runtime Evidence**. Tabs match LEARN → PROVE.

Rebuild: `python3 scripts/build_lab_scanner_runtime_evidence_dashboard.py`

## Files

| File | Purpose |
|------|---------|
| `workshop.md` | Ten-step instructor/learner flow |
| `evidence.md` | Evidence hierarchy and planes |
| `knowledge-check.md` | Questions and answers |
| `dashboard.definition.json` | Studio source |

No new SPL. Reuse Q-SCANNER-* and Q-MCP-*. Do not create DET-SCANNER or DET-MCP-CATALOG.
