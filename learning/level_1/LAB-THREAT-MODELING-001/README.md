# Threat Modeling & Security Architecture

REPLAY / architecture learning lab. This lab adds no attack, runtime control, detector, schema field, identity system, approval workflow, or compliance score.

## Objective

Given an unfamiliar agentic system, determine:

```text
WHAT ARE WE PROTECTING?
HOW DOES DATA MOVE?
WHERE DOES TRUST CHANGE?
WHAT CAN INFLUENCE THE AGENT?
WHAT AUTHORITY DOES IT HAVE?
WHO AUTHORIZES ACTION?
WHAT COULD GO WRONG?
WHERE SHOULD CONTROLS LIVE?
HOW WOULD WE KNOW?
WHAT CAN AND CANNOT BE PROVEN?
WHAT RISK REMAINS?
```

## Start

1. Read `challenge.md`.
2. Use `architecture.json` as evidence, not as an automatically completed threat model.
3. Choose Guided, Practitioner, or Architect Challenge in `investigations.json`.
4. Draft `threat-model-template.md`.
5. Use `threat-catalog.json` only after your first threat pass.
6. Complete `knowledge-check.md`.

## MAESTRO track (CSA)

The lab's hands-on exercise follows the Cloud Security Alliance's MAESTRO method (Ken Huang, 2025-02-06) on the AcmeBank architecture. In the Academy open **Practice** on this lab and use the MAESTRO workbench:

1. scope the model, then place every AcmeBank element on one of the **seven layers** (Foundation Models, Data Operations, Agent Frameworks, Deployment and Infrastructure, Evaluation and Observability, Security and Compliance, Agent Ecosystem) and mark the **trust boundaries**;
2. record **layer-specific threats**, starting from the article's list for each layer and tailoring it (a custom threat is allowed when you say why);
3. chain them into **cross-layer attack paths**;
4. judge **inherent and residual risk** with the Risk Center's qualitative matrix, name the controls that exist and a mitigation, and rank the register;
5. link each threat to the AgentSecLab scenarios that show it (MCP, prompt injection, memory, RAG, delegation);
6. **Check my model** against the rubric, compare with the **worked example** (load it any time), and **download** your report (Markdown) and model (JSON).

Content: `maestro.json` (layers, threat lists, AcmeBank decomposition, example, rubric). The MAESTRO Threat Analyzer is **NOT RUN** by this lab. Limits: the example judgments are the lab author's, not CSA's; MAESTRO v2 is not implemented; nothing here is compliance or certification.

Runtime schema remains `1.9.0`. ExternalEvidence remains `1.0.0`. CTRL-MCP-001 remains the tool PDP. Splunk remains downstream.
