# Privacy Framework Validation

Validation date: 2026-09-25

Scope: official-source verification for the educational framework lenses used
in L8. This is not certification, compliance validation, legal advice, or
complete framework coverage.

## NIST Privacy Framework

- Final framework used: NIST Privacy Framework 1.0 (Version 1.0).
- Publication date: 2020-01-16.
- Official publication:
  https://www.nist.gov/publications/nist-privacy-framework-tool-improving-privacy-through-enterprise-risk-management
- Official document:
  https://doi.org/10.6028/NIST.CSWP.01162020
- Educational relationship: voluntary privacy-risk management lens for data
  processing, governance, communication, and protective activities.
- Limitation: AgentSec does not implement a Framework Profile, Tier assessment,
  conformity evaluation, or jurisdiction-specific legal analysis.

NIST Privacy Framework 1.1 was still an **Initial Public Draft** on the
validation date. NIST's official page lists the final 1.1 as forthcoming:

https://www.nist.gov/privacy-framework/new-projects/privacy-framework-version-11

L8 therefore does not present 1.1 as a finalized framework.

## NIST AI Risk Management Framework

- Framework: NIST AI RMF 1.0.
- Publication date: 2023-01-26.
- Official source:
  https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-ai-rmf-10
- Educational relationship: privacy-enhanced AI, data minimization,
  third-party data/dependency mapping, and documented privacy risk.
- Limitation: AgentSec does not claim implementation of AI RMF outcomes or
  complete trustworthiness evaluation.

The NIST AI RMF describes privacy as a trustworthiness characteristic and
recognizes inference risk and data-minimizing methods. AgentSec uses those
ideas as prompts, not as a scored mapping.

## OWASP

- Source: OWASP Top 10 for Agentic Applications 2026.
- Official source:
  https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- Source: OWASP AI Agent Security Cheat Sheet.
- Official source:
  https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html
- Educational relationship: sensitive-data exposure through context, tools,
  memory, logs, and outputs; minimization, isolation, redaction, retention, and
  secret-handling design prompts.
- Limitation: L8 does not claim complete OWASP coverage, production DLP, or
  validation of an OWASP risk identifier.

Specific identifier-level mappings remain `NEEDS_EXTERNAL_VALIDATION` unless
individually verified and bounded to an AgentSec claim.

## Mandatory learner label

Every relationship shown in the workbench is:

**EDUCATIONAL MAPPING**

```text
This is not certification.
This is not compliance validation.
This is not legal advice.
This is not legal determination.
This is not complete framework coverage.
```
