---
name: splunk-ko-review
description: >-
  Review AgentSec Splunk knowledge objects (investigation searches, hunts,
  saved searches, detections, alerts, reports, lookups, macros, field
  extractions, tags, event types, CIM, data models, Dashboard Studio data
  sources, dashboards, app config) against the AgentSec evidence model and
  official Splunk Agent Skills. Use when the user says /splunk-ko-review,
  asks for a Splunk KO review, or creates or materially changes SPL or Splunk
  app artifacts.
disable-model-invocation: true
paths:
  - "splunk_app/**"
  - "learning/**/searches/**"
  - "learning/**/dashboard.definition.json"
  - "docs/**/*SPLUNK*"
  - "docs/**/*DETECTION*"
  - "docs/**/*WORKSHOP*"
---

# Splunk Knowledge Object Review

Official catalog: https://splunkbase.splunk.com/skills

Read `.cursor/rules/33-splunk-agent-skills.mdc` first. Official skill names and when to consult them: [reference.md](reference.md). Inventory: `docs/SPLUNK_KNOWLEDGE_OBJECT_INVENTORY.md`.

Do **not** redesign runtime, schema, or validated SPL during a review unless a demonstrated correctness or security defect exists.

Do **not** implement until the review is written when the user asked for review-before-fix.

## When to use

Before publishing or materially changing any persistent Splunk artifact, and as an acceptance gate for any phase that touches SPL, saved searches, detections, alerts, extractions, CIM, data models, lookups, macros, Studio data sources, or Splunk app configuration.

Also run `/spl-validate` (`.cursor/skills/spl-validate/SKILL.md`) for SPL correctness. For learner UI, separately run `/ui-review` and `/logic-proof`.

## Workflow (mandatory)

Reject “write SPL first and make the evidence fit later.”

```text
SECURITY / OPERATIONAL QUESTION
→ EVIDENCE REQUIREMENT
→ VALIDATED TELEMETRY
→ INDEXED FIELD DISCOVERY
→ FIELD CONTRACT
→ KNOWLEDGE OBJECT DESIGN
→ SPL
→ SPL CORRECTNESS REVIEW
→ PERFORMANCE REVIEW
→ LIVE SPLUNK VALIDATION
→ DASHBOARD / DETECTION / WORKSHOP CONSUMER
```

Dashboard implementation order:

```text
FIELD CONTRACT
→ SPL REVIEW
→ SPLUNK KO REVIEW
→ LIVE VALIDATION
→ DASHBOARD IMPLEMENTATION
→ /ui-review
→ /logic-proof
```

## Classify the object

Pick one primary type. Persistence must be justified in PURPOSE.

INVESTIGATION SEARCH · HUNT · REPORT · SAVED SEARCH · DETECTION · ALERT · LOOKUP · MACRO · FIELD EXTRACTION · EVENT TYPE · TAG · DATA MODEL · DASHBOARD · DASHBOARD DATA SOURCE · APP CONFIGURATION

Not every useful query becomes a persistent KO. Prefer reuse and parameterization (`__RUN_ID__`, Studio tokens).

Cover all of: investigation searches, hunts, saved searches, detections, alerts, reports, lookups, macros, field extractions, tags/event types, CIM mapping, data models, Dashboard Studio data sources, dashboards, app packaging/configuration.

## Field-contract gate

Before writing new production or learner-facing SPL, require all ten:

1. Security or operational question
2. Evidence needed to answer it
3. Actual telemetry source
4. Actual indexed field discovery
5. Field semantics
6. Multivalue behavior
7. Correlation keys
8. Sequence/time semantics where relevant
9. No-data semantics
10. Evidence limitations

If required telemetry is absent: **STOP.** Record `TELEMETRY GAP — QUERY NOT DEFENSIBLE`. Do not invent fields. Do not derive a proxy merely to make a dashboard work.

## SPL review gate

Review substantial SPL for: index restriction, sourcetype restriction, time bounds, selective predicates, field normalization, multivalue duplication, `mvdedup`/`mvindex` assumptions, cardinality, correlation keys, event ordering, sequence semantics, null behavior, boolean representation, expensive wildcards, unnecessary `rex`/`spath`/`join`/`transaction`/`map`/`append`, fields carried longer than necessary, `stats`/`eventstats` correctness, security semantics, no-data semantics.

Performance optimization must **never** change the security question. Consult **Search Performance Optimizer** only on existing searches, from evidence.

## AgentSec safety

- ALLOW does not mean execution
- `mcp.started` means execution began, not success
- `mcp.failed` means execution occurred and failed, not prevention
- DENY cannot be inferred solely from missing execution telemetry
- Zero rows do not mean safe
- Zero detection rows do not mean no attack
- Splunk is the investigation/evidence plane, not the runtime authorization layer
- SIMULATED evidence is not OBSERVED runtime behavior
- Pytest does not prove SPL executed correctly in Splunk

## Detection engineering gate

A hunt must **not** automatically become a detection.

Require: SECURITY PREDICATE, REQUIRED TELEMETRY, CORRELATION CONTRACT, NEGATIVE SPECIMENS, POSITIVE CONTROL, FALSE-POSITIVE ANALYSIS, FALSE-NEGATIVE ANALYSIS, PERFORMANCE ASSESSMENT, SEVERITY JUSTIFICATION, TIME WINDOW, SCHEDULE RATIONALE, THROTTLE DECISION, LIVE SPLUNK VALIDATION.

If unmet: `DETECTION ANALYZED — DO NOT PUBLISH` or `DETECTION BLOCKED BY TELEMETRY GAP`. Do not create a detector because the phase number suggests one.

## CIM

Consult **Field Extraction and CIM Mapping** when mapping is in scope.

Classify every meaningful CIM decision: CIM MAPPED · CIM PARTIALLY APPLICABLE · CIM NOT APPLICABLE · CIM DEFERRED.

Do not force emerging agentic-security concepts into unrelated CIM fields. AgentSec-specific fields may remain AgentSec-specific. Document the reason.

## KO governance

Consult **Knowledge Object Governance**. Review: duplicate searches, redundant saved searches, naming, ownership, app context, permissions, scheduling, disabled/enabled state, description quality, dependencies (lookup/macro/dashboard), stale/deprecated objects.

## Existing validated content

Classify findings BLOCKER / HIGH / MEDIUM / LOW. Do not mass-edit validated SPL for style. Change existing validated content only for a demonstrated correctness or security defect. Document performance/style suggestions for later review.

## Output (verbatim template)

Write the review to `docs/reviews/` unless the user names another path. One block per object.

```text
SPLUNK KNOWLEDGE OBJECT REVIEW

OBJECT:
TYPE:
PURPOSE:

SECURITY / OPERATIONAL QUESTION:

EVIDENCE REQUIRED:

TELEMETRY SOURCE:

INDEXED FIELDS VERIFIED:
YES / NO

FIELD CONTRACT:
PASS / FAIL

CORRELATION CONTRACT:
PASS / FAIL / NOT APPLICABLE

SPL CORRECTNESS:
PASS / FAIL

NO-DATA SEMANTICS:
PASS / FAIL

PERFORMANCE:
PASS / FAIL / NOT MEASURED

CIM:
MAPPED / PARTIAL / NOT APPLICABLE / DEFERRED

KO DUPLICATION:
NONE / FOUND

DETECTION READINESS:
READY / HUNT ONLY / NOT APPLICABLE / BLOCKED

LIVE SPLUNK VALIDATION:
PASS / NOT RUN

DASHBOARD CONSUMER:
YES / NO

LIMITATIONS:

VERDICT:
PUBLISH
REVISE
DO NOT PUBLISH
```

If INDEXED FIELDS VERIFIED is NO and the query needs those fields: VERDICT is **DO NOT PUBLISH** and record `TELEMETRY GAP — QUERY NOT DEFENSIBLE`.

## Official skills

Do not invent Splunk skills. Use current catalog names. Consult only skills relevant to the artifact. Full mapping: [reference.md](reference.md).
