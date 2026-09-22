# Phase 15B — RAG Attack Service launch contract

**Schema:** 1.9.0. Learning metadata is not authorization. Splunk is not enforcement.

## Allowlist

Lab id: `LAB-RAG-CONTEXT`  
Specimens: `RAG-BASELINE` (BASELINE), `RAG-001` (ATTACK and RETEST)  
Execution: `live` only.

Browser may send only:

```json
{"lab_id":"LAB-RAG-CONTEXT","specimen_id":"RAG-001","mode":"ATTACK","execution":"live"}
```

Unknown fields are ERROR, never DENY or ALLOW. Rejected examples: `profile`, `allowed_tools`, `allowed_scope`, `grant`, `policy`, `document_id`, `trusted_document`, `trusted_context`, `content`, `python`, `spl`, `AGENTSEC_SECURITY_PROFILE`.

## Server-owned mapping

LaunchCatalog → ExperimentDefinition → immutable ExperimentContext → `POST /rag/retrieve` with `{document_id, user_id, experiment_id}`.

The learner does not choose grants, profile, document body, or trust labels.

## Before launch the page explains

OBJECTIVE, WHY THIS MATTERS, WHAT THE ATTACKER CONTROLS (closed malicious fixture), WHAT THEY DO NOT CONTROL, TRUST BOUNDARY, EXPECTED VULNERABLE / DEFENDED BEHAVIOR, WHAT TO PREDICT, WHAT EVIDENCE TO EXPECT.

Actions: Launch BASELINE (LIVE), Launch ATTACK (LIVE), Launch RETEST (LIVE).

## After launch

Fresh `run.id`. Copy run.id. Open Splunk Search. Investigate this run.

For an ATTACK/RETEST pair: Copy ATTACK run.id, Copy RETEST run.id, Open ATTACK in Search, Open RETEST in Search, Open ATTACK vs RETEST in Search.

Studio tokens are **not** written by custom browser JavaScript.

## Expected runtime

ATTACK: CONTEXT-001 OBSERVE; follow-on ALLOW overlay; `lookup_customer_tier_handler_count=1`.  
RETEST: CONTEXT-001 OBSERVE; follow-on DENY `tool_not_granted`; handler 0.  
Same `document.id`, `content.hash`, provenance, requested tool, requested scope.

Malicious hash: `sha256:c565f364c7c5fba3cf25d235bb8e2bee7d9433daa9f07d5e097ab6d2a82a97ef`.
