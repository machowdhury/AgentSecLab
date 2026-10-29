# Benefits, architecture and security guide

What AgentSecLab is good for, how the lab is built, where its trust boundaries are, and, just as important, what it does not do. Diagrams are in the [Visual guide](VISUAL_GUIDE.md).

## Why agentic AI security is different

A traditional web application runs code its authors wrote. An **agent** adds a component that *decides what to do next from text*: a language model reads a request, a retrieved document, a memory or a tool result and proposes an action. That changes the security problem in five ways, and each one has a workshop:

| Difference | What goes wrong | Where you see it |
|---|---|---|
| **Instructions and data share one channel.** Text a user, a document or a tool returns can look like an instruction | Prompt injection, poisoned retrieval, poisoned memory | LAB-PI-001, LAB-RAG-CONTEXT, LAB-MEMORY-001, LAB-MCP-005 |
| **The model proposes; something else must authorize.** A model has no reliable concept of "not allowed" | An action is attempted because the model was persuaded, not because it was permitted | LAB-MCP-001, LAB-MCP-003, LAB-MCP-004, the Loan Desk |
| **Authority is delegated and claimed.** Agents act for users and for other agents | Confused deputy, a claimed scope taken as a granted scope | LAB-AGENT-DELEGATION-001, LAB-MCP-006, CTF Confused Deputy Relay |
| **Goals can be rewritten in-band.** A task is itself text | Goal hijacking, instruction integrity failures | LAB-AGENT-GOAL-INTEGRITY-001 |
| **Behaviour is non-deterministic and spans systems.** The same input can produce different proposals, across model, tools and data | You must reconstruct what happened from evidence, not from the code | Every live workshop; the Splunk investigations |

The lab's organising rule, shown on the Academy home page, is: **a control decision is not an execution, and an execution is not observed evidence.** Keeping those three facts apart is most of the skill.

## What you get, by role

### Security architects and threat modelers
- A concrete reference system (AcmeBank) with documented trust boundaries, to practise decomposition on instead of an abstract diagram.
- **A CSA MAESTRO workbench** (see below): seven-layer decomposition, a layer-by-layer threat register, cross-layer attack paths, a qualitative risk register with mitigation and residual risk, a self-check against a worked example, and a downloadable Markdown and JSON report.
- Realistic use cases: run a threat-modeling session for an agent project, or compare your own model with the worked example and discuss where you disagree.

### SOC analysts and detection engineers
- Real telemetry for every live run, with one `agentsec.run.id` and a defined event sequence, in a Splunk index you can search.
- Practice at **reconstructing a run from events** and at stating what the evidence cannot show. The workshops include hunt searches and a detection-engineering exercise.
- Realistic use cases: onboard a new agent data source; write a detection for "denied, then started"; explain why silence in an alert is not proof of safety.

### AI developers and agent builders
- See, with the same request run three times, how a **server-owned security profile** changes the outcome, and why the defence is code outside the model.
- Concrete patterns to copy or reject: tool, scope and resource authorization; an opaque allow ticket between the decision and the handler; closed request bodies; classifying retrieved and recalled text as data.
- Realistic use cases: review your own agent's tool grants against the MCP workshops; ask "what would the allowlist say here?" for each tool.

### Solutions engineers and technical instructors
- A self-contained, local demo and classroom environment with a catalog of 33 workshops, three CTF challenges and clear labels for what is live and what is recorded.
- Instructor material: [Instructor guide](INSTRUCTOR_GUIDE.md) and the workshop [catalog](WORKSHOP_CATALOG.md).
- Realistic use cases: a 90-minute prompt-injection and tool-authorization session (L1); a half-day Splunk investigation lab (L5 to L6); a CTF warm-up. The estimated efforts in the catalog come from the curriculum file and are guidance, not measurements.

## Architecture in one page

```text
learner -> HTTPS gateway -> Attack Service + Academy -> AcmeBank -> Ollama (language model)
                                   |                        |
                                   |                        +-> OpenTelemetry -> Splunk (HEC)
                                   +------ optional REST search ---------------> Splunk
```
Diagram 1 in the [Visual guide](VISUAL_GUIDE.md#3-deployment-and-trust-boundaries) has the detail. The parts:

| Part | Role | Notes |
|---|---|---|
| **Academy** (React) | The learner interface: workshops, predictions, workbenches, the CTF page, the Loan Desk, Risk, EVAL and Governance centers | Served by the Attack Service; your progress is stored in your browser only |
| **Attack Service / Attack UI** | Launches attacks from a closed allowlist; chooses the security profile on the server; runs the CTF; checks evidence | The browser cannot send a payload, a tool name, a Splunk search or a profile |
| **AcmeBank** | The deliberately simple target: an agent pipeline, an in-process MCP tool layer, a RAG retriever, a memory store, the Loan Desk | Synthetic data only |
| **Ollama** | The local language model runtime | `llama3.2:1b` for the pipeline labs, `llama3.2:latest` for the Loan Desk |
| **Security controls** | Deterministic code in AcmeBank and the gateway (table below) | The controls are the lesson; they are not a product |
| **OpenTelemetry + Splunk** | Events out, search and dashboards in | Splunk observes; it enforces nothing |

## Trust boundaries and who decides

### The central distinction: LLM-generated versus deterministic

| | **LLM-generated** | **Deterministic enforcement** |
|---|---|---|
| What it is | The model's text and its *proposal* of a tool call | Ordinary code: allowlists, pattern checks, schema validation, role checks, policy engines |
| Can it be persuaded? | Yes. That is the premise of the attacks | No: it runs the same rules for the same input |
| What it decides | Nothing that matters for security. It suggests | ALLOW or DENY, and what executes |
| Examples in this lab | The agent's reply; "call `lookup_policy` with these arguments"; the Loan Desk's note text | CTRL-INPUT-001, CTRL-MCP-001, CTRL-LOANDESK-001, the request contract, the gateway's roles and quota |

A DENY from a deterministic control, in the *defended* profile, is why the same attack that succeeds in ATTACK fails in RETEST. The ATTACK profile is intentionally **fail-open** to show what happens when the control is missing, and the page says so.

### Trust boundaries (from the MAESTRO model of AcmeBank)
| ID | Boundary | Between layers | What crosses it |
|---|---|---|---|
| TB-01 | HTTP input | ecosystem, agent framework | applicant and operator text |
| TB-02 | Retrieved context | data, agent framework | RAG text, as data |
| TB-03 | Persistent memory | data, agent framework | recalled text, as data |
| TB-04 | Tool authority | agent framework, ecosystem | a proposed tool call and its allow decision |
| TB-05 | Downstream system | ecosystem, data | tool effects on records and the underwriter queue |
| TB-06 | Observability | agent framework, observability | events about runs |
| TB-07 | External evidence | observability | scanner and garak evidence packs |
| TB-M01 | Model service | agent framework, foundation model | prompts and model output |
| TB-M02 | Gateway edge | ecosystem, infrastructure | authenticated HTTPS requests |
| TB-M03 | Container network | infrastructure, agent framework | service-to-service calls |

### The controls (all code in the repository)
| Control | Class | What it does |
|---|---|---|
| CTRL-INPUT-001 | ENFORCE | input pattern control before the model call (defended profile) |
| CTRL-MCP-001 | ENFORCE | tool, scope and resource authorization; issues an opaque allow ticket |
| CTRL-LOANDESK-001 | ENFORCE (hardened) | argument-level authorization for the Loan Desk's note |
| CTRL-DELEGATION-001 | ENFORCE (defended) | delegated-authority check |
| CTRL-GOAL-INTEGRITY-001 | OBSERVE (vulnerable), DENY (defended) | goal and instruction integrity |
| CTRL-RAG-CONTEXT-001, CTRL-MEMORY-CONTEXT-001, CTRL-IDENTITY-001, CTRL-MCP-RESULT-001, CTRL-MCP-METADATA-001 | OBSERVE | classify retrieved text, recalled text, identity claims, tool results and tool descriptions as data. They **record; they do not block** |
| Request contract, SPL policy | ENFORCE | closed request bodies and strict JSON; read-only searches only |
| Gateway edge | ENFORCE (stand-in) | basic authentication, roles, same-origin check, 6 state-changing calls per minute |

## The topics in the lab

### MCP and tool authorization
A tool request is not a grant. The MCP workshops separate **granting a tool**, **granting a scope** and **authorizing a resource**, and show a tool *result* and a tool *catalog* as untrusted data. **Limit:** the MCP layer is an in-process JSON-RPC model of MCP semantics, not stdio or HTTP MCP transport, and the allowlist is a lab policy, not production MCP IAM.

### Identity, delegation and the confused deputy
A claim of authority ("I act for the regional director") is data. The delegation workshops show a low-privilege caller reaching a restricted resource through a more privileged agent, and the control that stops it. **Limit:** the A2A and delegation material is simulated with coded agents; there is no A2A transport or agent card.

### RAG and memory
Retrieved and recalled text can carry instructions. The labs use an exact-ID local retriever and a process-local memory store, so the failure is reproducible and the evidence is small. Classification is OBSERVE: it records the problem; the defended outcome comes from the other controls. **Limit:** this does not model a vector database, embedding attacks or cross-tenant retrieval at scale.

### Goal hijacking
A task description is text and can be rewritten in-band. The goal workshop compares the vulnerable and defended profiles against a server-held task contract.

### Agent observability and evidence reconstruction
Every live run emits events that all carry `agentsec.run.id`, the testbed mode (BASELINE, ATTACK or RETEST), the security profile, control decisions, hops and model or tool events. You rebuild the story from them and say what they cannot prove. Three states keep you honest: the Academy marks evidence as **LIVE**, **RECORDED** or **SIMULATED**, and a run is **VERIFIED**, **NOT VERIFIED** or **VERIFICATION UNAVAILABLE** against Splunk.

### Splunk's role
Splunk is the investigation and detection workbench: the telemetry index, the hunts, the dashboards and the detection exercises. It is **downstream**. It cannot allow, deny or stop anything, and its absence changes no security outcome. A recorded run is one run, not a rate.

## CSA MAESTRO

[MAESTRO](https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro) (Multi-Agent Environment, Security, Threat, Risk, and Outcome) is the Cloud Security Alliance's agentic-AI threat-modeling framework by Ken Huang (2025-02-06). It has **seven layers**: 1 Foundation Models, 2 Data Operations, 3 Agent Frameworks, 4 Deployment and Infrastructure, 5 Evaluation and Observability, 6 Security and Compliance (vertical, across all layers), 7 Agent Ecosystem; a per-layer list of threats; and **cross-layer threats** (supply chain attacks, lateral movement, privilege escalation, data leakage, goal-misalignment cascades). Its method has six steps: decomposition, layer-specific threat modeling, cross-layer identification, risk assessment, mitigation planning, implementation and monitoring.

What AgentSecLab adds (workshop `LAB-THREAT-MODELING-001`, Practice tab): a workbench that carries a learner through those steps on AcmeBank. You place 23 components on the seven layers, identify 10 trust boundaries, add threats per layer from the article's lists (or a justified custom threat), chain them into cross-layer paths, judge inherent and residual risk with the lab's qualitative impact and likelihood matrix, name existing controls and a mitigation, run an eight-criterion self-check, and download a Markdown and JSON report. A 16-threat worked example is included.

What it is **not**: it does **not** run or embed CSA's MAESTRO Threat Analyzer (which calls a language model and was **not run**); it is **not** MAESTRO v2; it defines no risk scoring beyond the lab's own qualitative matrix (MAESTRO defines none); and the worked example's judgments and the component-to-layer mapping are **the lab author's analysis, not CSA material and not externally validated**. The self-check measures structure and honesty, not the quality of your reasoning. Reports are labelled `LOCAL_DRAFT_NOT_APPROVED`.

## What AgentSecLab does not implement or claim

- **Not a product and not production.** It is an educational lab with intentionally vulnerable profiles, synthetic data and one local participant.
- **No compliance, certification or framework conformance claim.** Governance and framework relationships are educational links.
- **Not a measure of any real model's or system's security.** "Same input, different configuration, different outcome" is shown for one request; it is not a rate and not universal resistance.
- **Not every workshop runs an agent.** 13 of the 33 workshops are live; 19 are recorded or simulated analyses; one is reading. The three CTF challenges use a scripted agent, not a language model, not MCP and not A2A.
- **Not real MCP or A2A transports.** In-process models only.
- **Splunk REST verification (VERIFIED) is not on by default.** It needs a matching management certificate, a trusted CA and a token (see the [installation guide](INSTALLATION_AND_DEPLOYMENT.md#63-turning-on-rest-verification-verified-for-the-bundled-splunk-tested-once-on-a-disposable-host)).
- **Not everything is behind one address.** Splunk Web and the real AcmeBank are not routed through the gateway.
- **Authentication is a stand-in.** Basic authentication with two roles, no SSO, no login throttling.
- **Untested:** Windows and macOS deployment for RC2, organization-managed certificates, non-loopback deployment, an external Splunk Enterprise or Splunk Cloud against a real service.
- **Models:** two small local Llama models; results depend on the model, the Ollama version and sampling. No model comparison or upgrade is part of RC2.
