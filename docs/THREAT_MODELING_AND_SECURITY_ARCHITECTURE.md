# Threat Modeling & Security Architecture

**Status:** IMPLEMENTED educational REPLAY / ARCHITECTURE phase
**Lab:** `LAB-THREAT-MODELING-001`
**Studio:** `ws_lab_threat_modeling`
**Scenario:** AcmeBank Agentic Customer Operations Platform

## Purpose

This phase teaches the learner to model an unfamiliar agentic architecture before selecting controls. It adds no attack family, runtime control, detector, identity system, cryptography, risk score, or compliance result.

## Method

```text
UNDERSTAND SYSTEM
→ IDENTIFY ASSETS
→ IDENTIFY ACTORS
→ MAP COMPONENTS
→ MAP DATA FLOWS
→ DRAW TRUST BOUNDARIES
→ IDENTIFY AUTHORITY
→ IDENTIFY ATTACK SURFACE
→ ENUMERATE THREATS
→ MAP CONTROLS
→ IDENTIFY TELEMETRY
→ TEST ASSUMPTIONS
→ IDENTIFY GAPS
→ RESIDUAL RISK
```

The learner, not the workbench, performs prioritization. The threat catalog is a bounded set of questions rather than an answer generator.

## Educational system model

The bounded model contains a human operations user, AcmeBank application, agent pipeline, Ollama model dependency, exact-ID RAG, process-local memory, in-process MCP server, CTRL-MCP-001, registered tools, fixture-backed banking records, OpenTelemetry export, Splunk, and adjacent Cisco/garak evidence.

Repository evidence and implementation status are recorded in `learning/level_1/LAB-THREAT-MODELING-001/architecture.json`. Fixture-backed downstream behavior is `LAB-SIMULATED`. Authentication, human approval, cryptographic delegation, real A2A transport, and production IAM are `NOT MODELED`.

## Assets and actors

Assets are selected by relevance, not by checking every category:

- data: customer records, prompts, retrieved documents, and memory;
- authority: tool, scope, and resource grants;
- system: coded policy and allow-ticket integrity;
- business: lending workflow and availability;
- security evidence: decisions, provenance, telemetry, and investigation artifacts.

Actors distinguish people, threat actors, software actors, and dependencies. Treating an agent as an architectural actor does not make it a person or authenticated principal.

## Data flows and trust boundaries

The model traces request, model/context, RAG, memory, tool request, allow ticket, downstream action, telemetry, and external-evidence flows. For each, the learner asks what data moves, who supplied it, whether it is trusted or persisted, whether it influences decisions, whether it can exercise authority, and where evidence exists.

Seven boundaries focus review on HTTP input, retrieved context, persistent memory, tool authority, downstream records, observability, and external evidence. Crossing a boundary does not prove compromise.

## Authority model

The agent/orchestrator requests a tool, scope, and resource. CTRL-MCP-001 in `McpServer.authorize` applies coded exact-membership policy. `McpServer.execute` requires an opaque allow ticket minted only after ALLOW. This ordering keeps the security check before handler invocation.

Influence does not create authority. RAG, memory, prompts, model output, scanner findings, and Splunk records cannot mint a tool grant.

## Threat and control reasoning

For each selected threat, the learner binds:

```text
asset → actor/source → boundary/flow → precondition
→ influence or authority → consequence → control and placement
→ telemetry → evidence gap → residual risk
```

Controls may be preventive, detective, corrective, or recovery. They must also be classified as `OBSERVE` or `ENFORCE`. Prompt/context controls address influence. CTRL-MCP-001 enforces authorization. Splunk observes and supports investigation. External scanners produce assessment evidence.

## Observability and evidence gaps

The learner specifies event, source, timestamp, identity claim, request, decision, invocation, completion, outcome, correlation identifier, and provenance where relevant. Each source must be accompanied by what it proves and does not prove.

Missing evidence uses precise states: `NOT LOGGED`, `NOT MODELED`, `NOT OBSERVED`, `NOT CORRELATED`, `NOT CRYPTOGRAPHICALLY ESTABLISHED`, and `NOT PROVEN`.

## Framework layer

`docs/THREAT_MODEL_FRAMEWORK_VALIDATION.md` records official-source validation dated 2026-09-25. OWASP, MITRE ATLAS, CSA MAESTRO, and NIST are presented as different lenses.

Every learner-facing relationship is labeled **EDUCATIONAL MAPPING**:

```text
This is not certification.
This is not compliance validation.
This is not complete framework coverage.
```

No specific AgentSec-to-framework technique identifier is claimed. Such detailed mappings remain `NEEDS_EXTERNAL_VALIDATION`.

## Progressive learning

- Guided: architecture, examples, prompts, four hints.
- Practitioner: architecture, objective, artifact template, minimal hints.
- Architect Challenge: business description, architecture, constraints.

All levels use one architecture. Path B is a pedagogical review key, not access control. Progress is self-assessed and not persisted.

## Deliverable

`threat-model-template.md` requires purpose/scope, assets, actors, flows, boundaries, authority, threats, controls and placement, telemetry, evidence gaps, residual risks, recommendations, and engineering/SOC/leadership communication. It explicitly disclaims compliance assessment.

## Security semantics

- Runtime schema: `1.9.0` unchanged.
- ExternalEvidence contract: `1.0.0` unchanged.
- CTRL-MCP-001 remains the tool PDP.
- Splunk remains downstream.
- External security evidence remains adjacent.
- No new saved search or detector.
- No live Splunk query is required to validate this static architecture exercise; existing validated runtime and Blue-Team evidence are referenced.

## Limitations

- Studio gating is pedagogical; users can open Path B directly.
- No learner-answer persistence or automated scoring exists.
- The diagram is bounded markdown, not a general graph editor.
- Framework lenses are not complete coverage.
- Browser screen-reader validation is not claimed unless separately recorded.
- The exercise does not establish production banking, identity, privacy, or cryptographic properties.
