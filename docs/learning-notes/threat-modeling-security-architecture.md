# Learning note: threat modeling agentic systems

## What is it?

Threat modeling is a structured way to understand a system, identify what matters, examine where trust and authority change, anticipate unwanted behavior, place controls, design evidence, and state what risk remains.

It is not a vulnerability checklist and it does not require an attack to have already occurred.

## Why does it exist?

Security controls fail when the team protects the wrong asset, misunderstands the data flow, confuses influence with authority, or places a control after the dangerous action. A threat model makes those assumptions visible before implementation or incident response.

## How does it work?

Start with business purpose and scope. Select relevant assets and actors. Trace important data flows. Mark boundaries where trust, authority, or system ownership changes. Ask separately what can influence behavior and what can exercise authority. Form threats as causal stories, map controls to the right layer, and specify evidence that would support or refute the story.

Finish with gaps and residual risk. A control reduces risk under assumptions; it does not erase risk.

## Where does it sit in AgentSec?

It follows the Blue-Team phase. Blue Team starts from observations and reconstructs behavior. Threat modeling starts from architecture and asks what might happen and what evidence would be needed. Existing Prompt, RAG, Memory, Goal, Identity, MCP, Capstone, external-evidence, and Blue-Team labs provide teaching evidence; this phase does not rebuild them.

## What is the trust boundary?

Important AgentSec boundaries include:

- human request to application;
- retrieved document to context;
- persistent memory to later context;
- agent request to MCP authorization;
- tool to downstream records;
- runtime telemetry to Splunk;
- external assessment evidence to the investigation plane.

A boundary is a review point, not proof of compromise.

## What could an attacker control?

Depending on the scenario, an attacker may supply request text, retrieved content, memory content, identity/delegation claims, or dependency inputs. In the closed AgentSec experiments the browser cannot choose grants, policy, security profile, arbitrary tools, or control outcomes.

## What can go wrong?

Untrusted data may change a request; persisted content may influence later work; an authorized tool may serve an unauthorized goal; claims may be mistaken for authenticated identity; an agent may have excessive scope; external evidence may be overclaimed; and missing or uncorrelated telemetry may prevent reconstruction.

## What telemetry should exist?

Record relevant event, source, timestamp, identity claim, request, authorization decision and reason, invocation, completion/failure, downstream outcome, correlation identifier, and provenance. Distinguish evidence for each stage.

## How will Splunk show it?

Splunk can search and correlate emitted copies. It can show control decisions and execution events when those events are present and complete. It does not grant authority, prove that missing events mean prevention, or turn scanner findings into exploitation evidence.

## What control could change the result?

Control placement follows the threat:

- source/ingestion/context controls reduce untrusted influence;
- goal controls constrain business purpose;
- CTRL-MCP-001 authorizes tool, scope, and resource before execution;
- downstream controls limit final effects;
- logging and monitoring improve detection and response.

## What test proves the logic?

Deterministic tests should verify control ordering, exact authorization semantics, allow-ticket requirements, schema contracts, and evidence fields. Workbench tests verify that learners see the model, gaps, framework disclaimers, hints, and gated review without answer leakage. Browser checks verify rendering and keyboard access; they do not prove security semantics.

## Security principle transfer

MCP authorization has analogues in API middleware, IAM, network policy, admission controls, and database privileges. RAG and memory have analogues in document ingestion, queues, caches, and pipelines. Evidence design transfers directly to incident response and forensics.

## What I should now be able to explain

1. Why does influence not create authority?
2. What assets beyond data can an agentic system contain?
3. How do actors differ from identities?
4. Why does a boundary crossing not prove compromise?
5. Who authorizes an AgentSec tool request?
6. Where should an authorization control operate?
7. What evidence separates decision, invocation, completion, and outcome?
8. How should a missing capability or event be labeled?
9. Why does a scanner finding not prove exploitation?
10. What assumptions and residual risk remain after a control is implemented?
