# Privacy, Data Protection & Agentic Data Governance

## Purpose

L8 teaches how to reason about data in an agentic workflow. Its central
distinction is:

```text
AUTHORIZED ACTION != AUTHORIZED DATA USE
```

This is security/privacy education, not legal advice, certification,
compliance validation, or a general-purpose DLP system.

## Learning method

The learner inventories scenario-relevant data, traces each modeled flow,
identifies purpose and necessity, investigates evidence, minimizes data,
places controls, records gaps, and communicates residual risk.

```text
COLLECT → INGEST → CLASSIFY → USE → RETRIEVE → INFER → ACT
→ STORE / REMEMBER → LOG → SHARE → RETAIN → DELETE
```

Stages absent from a workflow remain `NOT MODELED`.

## Bounded incident

`PRIV-2026-001` uses a synthetic customer-support fixture. The legitimate task
is to confirm a preferred contact-channel type. Two specimens use the same
tool, scope, policy, and fixture-backed execution:

- ATTACK supplies a full record containing required and unnecessary fields.
- RETEST supplies only `customer_id` and `preferred_channel`.

CTRL-MCP-001 returns `ALLOW / tool_granted` and the handler completes once in
both. The comparison changes data handling, not authorization semantics.

## Agentic data lifecycle and boundaries

The modeled trace is:

```text
SYNTHETIC FIXTURE
  → TOOL ARGUMENT
  → CTRL-MCP-001
  → FIXTURE-BACKED TOOL
  → RESULT
  → TELEMETRY
  → SPLUNK COPY
```

RAG, model context, memory, external-provider processing, production storage,
retention, deletion, authentication, human approval, and cryptographic
delegation are not modeled in this incident. Their privacy questions remain in
the workbench as architectural reasoning, not fabricated event evidence.

## Minimization and exposure

Purpose determines necessity. The full record includes synthetic email,
postal address, account-balance band, and an internal note that the task does
not require. The minimized record removes those fields before the tool
argument and telemetry copy. Cosmetic hiding after collection is not
minimization.

Redaction can reduce a bounded disclosure. It cannot establish purpose,
prevent all inference, guarantee deletion, repair retrieval authorization, or
prove isolation.

## RAG, memory, prompts, and tools

Retrieval authorization is distinct from tool authorization. CTRL-MCP-001 does
not authorize document retrieval. Memory privacy asks whether data should be
written, persisted, recalled, reused, and deleted; this differs from memory
poisoning. Prompt privacy asks what data needs to enter model context. For an
authorized tool, every argument field still requires a purpose and
need-to-know analysis.

## Logging privacy

Observability is itself a privacy boundary. Content previews improve a bounded
investigation but duplicate data into telemetry and Splunk. Logging design
must balance investigative value, sensitivity, access, retention, redaction,
provenance, and correlation. Secrets and credentials should not enter ordinary
model context or telemetry.

## Privacy threat model and control placement

For each concern record:

```text
ASSET → SOURCE → PROCESSOR → BOUNDARY → PURPOSE → EXPOSURE
→ PERSISTENCE → CONTROL → TELEMETRY → RESIDUAL RISK
```

Candidate controls include input minimization, retrieval and memory scoping,
argument filtering, secret exclusion, bounded redaction, access control,
retention, telemetry access, deletion, and monitoring. L8 teaches placement;
it does not implement a production control suite.

## Evidence discipline

Conclusions use `OBSERVED`, `MEASURED`, `DOCUMENTED`, `INFERRED`,
`NOT OBSERVED`, `NOT MODELED`, and `NOT PROVEN`. Empty search results are
`NO EVIDENCE FOUND`, never `SAFE`. Authorization evidence does not establish
data appropriateness, invocation, completion, outcome, retention, or deletion.

## Privacy by design

Before deployment ask what data is needed, why, where it goes, who sees it,
how long it is required, what is logged, how investigation can avoid
over-collection, and how data is removed when no longer needed.

## Framework context

All framework relationships are `EDUCATIONAL MAPPING`. See
`PRIVACY_FRAMEWORK_VALIDATION.md`. They are not legal determinations,
certification, complete coverage, or compliance validation.

## Limitations

The records and handler are synthetic. No provider behavior, production
customer exposure, breach, secure deletion, tenant isolation, or universal
control effectiveness is established. Schema remains `1.9.0`; ExternalEvidence
remains `1.0.0`; CTRL-MCP-001 remains the tool PDP.
