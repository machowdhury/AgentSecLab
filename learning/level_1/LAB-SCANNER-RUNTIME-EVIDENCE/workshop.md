# Workshop flow — scanner + runtime evidence

Ten stages. This is not a duplicate of LAB-MCP-CATALOG.

LAB-MCP-CATALOG: can malicious metadata influence a request without becoming authority?  
Phase 9E: how does a SOC combine scanner and runtime evidence to investigate it?

## LEARN

Three planes. Scanner evidence informs investigation. Scanner evidence does not feed CTRL-MCP-001.

This lab is **REPLAY**: canonical Phase 9B packs plus historical runtime copies. It is not live runtime scanning.

Cisco `mcp-scanner` is an **external evidence adapter**. Pipeline:

```text
mcp-scanner raw output → Cisco adapter → ExternalEvidence (finding) → pack → HEC → Splunk
```

Producer class on the indexed event is `OBSERVED_SCANNER` (honesty label). Contract `evidence_class` is `finding`. Correlation method is `hash_join` on `description_sha256` / `content.hash`. Hash match means the compared canonical content matched. It does not prove the same process, request, execution, or decision.

CTRL-MCP-001 remains the tool PDP. FINDING != AUTHORIZATION. SCANNER HIGH != DENY. ZERO FINDINGS != SAFE. EXTERNAL TOOL != PDP. SPLUNK != PDP.

Learner questions:

1. What did mcp-scanner report?
2. What artifact did it inspect?
3. What evidence class is this?
4. How is it correlated with runtime evidence?
5. What does the hash match establish?
6. Did the scanner authorize anything?
7. Which control actually made the authorization decision?
8. What runtime execution occurred?
9. What does Splunk prove?
10. What remains unproven?

Copy full LIVE ids from the first canvas. Input fields may ellipsize UUIDs.

## BASELINE

NORMAL scan executed. finding_count=0. finding_state=`scan_executed_zero_findings`.

Zero findings means this scanner produced zero findings for this artifact under this scan configuration. Not SAFE. Not trusted. Not approved. Do not display PASS.

Correlate NORMAL description hash to BASELINE runtime: METADATA-001 OBSERVE, lookup_policy ALLOW, mcp.started, mcp.completed, no follow-on.

## ATTACK

MALICIOUS scan: finding_count=1, native PROMPT INJECTION, native HIGH, tool lookup_policy, yara_analyzer.

Same malicious hash on ATTACK runtime. METADATA-001 OBSERVE. Follow-on lookup_customer_tier. CTRL-MCP-001 ALLOW `vulnerable_profile_fail_open:metadata_derived_authority`. mcp.started, mcp.completed. Handler 1.

Label: INTENTIONALLY VULNERABLE LAB PROFILE.

The scanner independently identified suspicious metadata. The vulnerable AgentSec profile independently allowed metadata-derived authority. Do not treat native HIGH as the cause of execution.

## OBSERVE

Four sections, not a story:

- ARTIFACT: scanner, scan_id, artifact hash, description hash, finding count, native severity
- RUNTIME: run_id, agent, metadata trust, description hash
- AUTHORIZATION: tool, decision, reason
- EXECUTION: mcp.started, terminal event

Indexed telemetry only. No `_raw`. No full descriptions.

## HUNT

Pivot: scanner → description hash → runtime → authorization → execution.

Primary: Q-SCANNER-WHO, Q-SCANNER-ARTIFACT, Q-SCANNER-FINDINGS, Q-SCANNER-RUNTIME-CORRELATION.

Reuse: Q-MCP-AUTHZ, Q-MCP-EXECUTED, Q-MCP-CATALOG-AUTHORITY.

Hunt run.id defaults to BASELINE. Hunt scan defaults to NORMAL.

## DETECT

DETECTION ANALYZED — NO NEW DETECTOR.

DET-MCP-001: ATTACK = 0 (no DENY). RETEST = 0 (DENY then no later mcp.started). Correct behavior. Not detector failure. Not SAFE.

Classification: scanner finding CONTEXT/HUNT; finding+metadata HUNT; finding+request HUNT; finding+ALLOW LAB HUNT ONLY; finding+execution FUTURE RESEARCH / TELEMETRY DEPENDENT; overlay reason REJECT as production; DENY then execution is DET-MCP-001.

SIMULATED positive-control table is makeresults, not LIVE.

## DEFEND

Scanner does not block the tool. Splunk does not block the tool. Metadata trust does not grant authority. CTRL-MCP-001 DENY `tool_not_granted` → handler count 0.

Do not claim the scanner prevented execution.

## RETEST

Same malicious description hash as ATTACK. Scanner finding unchanged (native HIGH).

METADATA-001 OBSERVE. Same follow-on request. CTRL-MCP-001 DENY `tool_not_granted`. Runtime handler count 0. No follow-on mcp.started on COMPLETE Splunk copy.

Runtime handler count is authoritative non-execution proof. Missing Splunk execution event is corroboration.

## COMPARE

Three cards:

- BASELINE: NORMAL, ZERO FINDINGS, no follow-on
- ATTACK: MALICIOUS, scanner HIGH, vulnerable ALLOW, execution
- RETEST: SAME MALICIOUS, SAME scanner HIGH, defended DENY, no execution

Fingerprint (hash, not preview): `sha256:9d0745320ca79852f2fbd7145bf074fcd353e290c18ba16fd02d801f9f3375b1`

THE SCANNER EVIDENCE FOR ATTACK AND RETEST IS THE SAME. THE AUTHORIZATION OUTCOME IS DIFFERENT. Therefore scanner finding != authorization decision.

## PROVE

Fifteen evidence questions. Answers in `knowledge-check.md`.
