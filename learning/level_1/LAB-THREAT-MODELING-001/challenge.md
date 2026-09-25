# Architect Challenge — AcmeBank Agentic Customer Operations Platform

## Business description

AcmeBank wants an internal customer-operations assistant that summarizes lending policy and may perform explicitly authorized read-only lookups. It uses an application, an agent pipeline, a local model service, retrieved policy documents, process-local memory, an in-process MCP server, registered tools, fixture-backed banking records, runtime telemetry, Splunk, and adjacent external security evidence.

The platform is a learning environment, not a production banking architecture.

## Constraints

- Customer and policy information should be disclosed only through authorized operations.
- Retrieved content and memory can influence requests but cannot grant authority.
- CTRL-MCP-001 is the sole tool PDP.
- A handler may start only with an allow ticket minted after ALLOW.
- Splunk and external tools observe or assess; they do not authorize runtime actions.
- Authentication is `NOT MODELED`.
- Human approval is `NOT MODELED`.
- Cryptographic delegation is `NOT MODELED`.
- The downstream banking system is fixture-backed and `LAB-SIMULATED`.

## Learner task

Produce:

1. system purpose;
2. critical assets;
3. actors and components;
4. important data flows;
5. trust and authority boundaries;
6. authority map;
7. attack surface;
8. a defensible set of top threats — not an arbitrary Top 10;
9. existing and missing controls;
10. control placement;
11. telemetry requirements;
12. evidence gaps;
13. residual risks;
14. recommendations;
15. engineering, SOC, and executive explanations.

## Challenge rules

- Do not treat every listed component as equally important.
- Do not call every boundary crossing a compromise.
- Separate influence from authority.
- Separate authentication, authorization, execution, outcome, detection, and prevention.
- A scanner finding is not exploitation.
- An evaluation pass is not safety.
- Absence of evidence is not evidence of absence.
- Do not assign a numerical risk score.
- Label facts, assumptions, evidence gaps, and recommendations.
