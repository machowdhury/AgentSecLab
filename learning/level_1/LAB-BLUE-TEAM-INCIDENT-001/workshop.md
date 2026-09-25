# Blue-Team Investigation Workshop

## Incident

AcmeBank incident `AI-2026-001`: an AI-assisted lending workflow may have attempted or performed an action outside its intended authority during `2026-09-20T19:37:40Z`–`19:38:00Z`.

Do not assume Prompt Injection, RAG, Memory, Goal, Identity, or MCP failure. Test each required link.

## Choose one level

### Level 1 — Guided Analyst

Run `Q-INCIDENT-CANDIDATES.spl`. For each candidate, bind `Q-INCIDENT-TIMELINE.spl` to the quoted run ID. Answer WHO, WHAT, WHEN, WHERE, AUTHORITY, EXECUTION, OUTCOME, EVIDENCE, and UNKNOWN.

### Level 2 — Investigator

Use only the incident description and approximate window. Discover fields, candidate runs, control decisions, and execution evidence. Do not open Path B until you have a written initial hypothesis.

### Level 3 — Threat Hunter

Hypothesis: an agent may have requested a privileged tool outside its intended task during the window.

Submit:

1. hypothesis;
2. evidence required;
3. search strategy;
4. candidate runs;
5. pivots;
6. supporting and contradicting evidence;
7. revised hypothesis and conclusion;
8. limitations.

## Progressive hints

1. Start with tool-control decisions. A request is not execution.
2. Pivot by run ID and order by `agentsec.sequence`, not `transaction`.
3. Inspect memory ID, source run ID, and content hash. A join is not causality.
4. Use `Q-INCIDENT-CANDIDATES`, `Q-INCIDENT-TIMELINE`, then `Q-INCIDENT-COMPARE`.

## Evidence ledger

For every material claim record:

- Claim
- Classification: FACT / INFERENCE / HYPOTHESIS / UNKNOWN
- Evidence and source
- Confidence: HIGH / MEDIUM / LOW, with reason
- Alternative explanation
- Missing evidence

Do not assign numerical confidence without a method.

## Timeline

Build the timeline yourself. Keep each retrieve, write, and recall run ID distinct. `source_run_id` links write to recall. Matching SHA-256 values establish equality of the compared canonical bytes; schema 1.9.0 does not model direct retrieve-output-to-write causality.

## Attack / retest comparison

Determine:

- what bytes and request remained equivalent;
- which control changed its decision;
- whether invocation began;
- whether a terminal event exists;
- what one retest cannot establish.

Runtime handler count from the validated source run is authoritative for invocation begin. Indexed `mcp.started` corroborates it on a complete copy.

## False-positive challenge

A broad hunt for `mcp.started` also finds expected `lookup_policy` execution. Compare the real baseline run `db514fd8-dbf4-49f3-a2cb-6bd2bfe92987`, where `policy:read` was requested and granted. Tool execution alone is not malicious:

```text
MATCH != MALICIOUS
```

Context, authority, task, control reason, and outcome change interpretation.

## External evidence

Cisco scanner findings and garak evaluations may suggest hypotheses. Keep their sourcetypes separate from `otel:agentic:json`. This packet has no defensible Cisco hash join and garak has no AgentSec run ID. External evidence causing or blocking the runtime incident is `NOT OBSERVED`.

## Detection-engineering bridge

After reaching a defensible conclusion:

```text
KNOWN INCIDENT → OBSERVABLES → CANDIDATE SPL → ATTACK → RETEST
→ BASELINE → FALSE-POSITIVE ANALYSIS → DETECTION CANDIDATE
```

Do not create a saved search here. A query that finds this specimen is not yet a production detector.

## Threat-model bridge

Answer: asset, actor, entry point, trust boundary, available authority, control placement, observability, missing telemetry, and residual risk.

## Transferable fundamentals

Connect your findings to least privilege, authentication versus authorization, provenance, separation of duties, defense in depth, secure defaults, monitoring, incident response, evidence integrity, containment, and recovery. Authentication is `NOT MODELED` in this packet; do not infer it from an agent ID.
