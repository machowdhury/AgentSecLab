# Threat-Model Framework Validation

Validation date: 2026-09-25

Scope: authoritative-source verification for the bounded AgentSec educational framework layer. This is not a compliance assessment, certification, complete mapping, or framework-coverage claim.

## OWASP

Status: `EXTERNALLY VALIDATED` for framework identity, publication date, and role.

- Framework: OWASP Top 10 for Agentic Applications 2026
- Official source: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- Official publication date: 2025-12-09
- AgentSec educational relationship: application and agentic-risk lens; prompts learners to challenge goals, tool use, privilege, memory, supply chain, inter-agent communication, and human-agent trust.
- Limitation: AgentSec does not claim complete OWASP coverage and does not claim that a lab result validates an OWASP category.

Specific risk identifiers are intentionally not attached to individual AgentSec threats in this phase. Such mappings remain `NEEDS_EXTERNAL_VALIDATION` until separately reviewed against the official publication.

## MITRE ATLAS

Status: `EXTERNALLY VALIDATED` for framework identity, current collection version, and role.

- Framework: MITRE ATLAS
- Official source: https://atlas.mitre.org/
- Official data source: https://github.com/mitre-atlas/atlas-data
- Current collection observed during review: `2026.05`
- AgentSec educational relationship: adversarial-behavior, technique, mitigation, and case-study lens for AI-enabled systems.
- Limitation: no ATLAS technique identifier is asserted for the AcmeBank challenge. Educational technique mappings remain `NEEDS_EXTERNAL_VALIDATION`.

The current collection is living content. A later review must re-check version and relationship semantics before publishing identifiers.

## MAESTRO

Status: `EXTERNALLY VALIDATED` for framework identity, v2 publication, and architectural role.

- Framework: MAESTRO — Multi-Agent Environment, Security, Threat, Risk, and Outcome
- Official source: https://labs.cloudsecurityalliance.org/maestro/
- Official v2 artifact: https://cloudsecurityalliance.org/artifacts/maestro-v2
- AgentSec educational relationship: layered agentic-architecture and cross-layer threat-modeling lens.
- Limitation: AgentSec does not reproduce MAESTRO's complete layer model, run its Threat Analyzer, or claim complete MAESTRO coverage.

No AgentSec component-to-MAESTRO-layer identifier mapping is asserted. Detailed mappings remain `NEEDS_EXTERNAL_VALIDATION`.

## NIST

Status: `EXTERNALLY VALIDATED` for publication identity, date, voluntary status, and risk-management role.

- Framework: NIST AI Risk Management Framework 1.0
- Companion: NIST AI 600-1, Artificial Intelligence Risk Management Framework: Generative Artificial Intelligence Profile
- Official source: https://www.nist.gov/itl/ai-risk-management-framework
- Official profile source: https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence
- NIST AI 600-1 publication date: 2024-07-26
- AgentSec educational relationship: voluntary Govern / Map / Measure / Manage risk-management lens; links business purpose, system context, evidence, controls, and residual risk.
- Limitation: this phase is not an AI RMF profile, assessment, conformity test, or governance implementation.

Specific subcategory mappings remain `NEEDS_EXTERNAL_VALIDATION`.

## Learner-facing label

Every framework reference in the workbench must display:

**EDUCATIONAL MAPPING**

```text
This is not certification.
This is not compliance validation.
This is not complete framework coverage.
```
