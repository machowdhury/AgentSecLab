# Visual guide

Eight diagrams (1 to 3 are the overview: application architecture, data flow, trust boundaries) and the product screenshots. The diagrams are [Mermaid](https://mermaid.js.org/) and render on GitHub; each is drawn from the repository (compose files, gateway configuration, the controls in the code and the MAESTRO model), not from a design wish. Where something is optional or untested, the diagram says so.

## 1. Application architecture

The components and what each one does, as deployed by the installer in gateway mode (`docker-compose.gateway.yml`). Solid arrows are used on every run; dashed arrows are optional, run by a script, or off by default.

```mermaid
flowchart LR
  B["Learner's browser"]
  subgraph GWB["Gateway: the authentication boundary"]
    GW["HTTPS gateway (nginx)<br/>TLS, basic auth, learner and operator roles,<br/>attack quota, route allowlist"]
  end
  subgraph APP["Application network 'agentsec_mesh' (no host ports)"]
    direction TB
    AS["Attack Service<br/>Academy UI (33 workshops), Attack UI,<br/>launch API and allowlist, CTF engine,<br/>evidence verification"]
    AB["AcmeBank<br/>agent pipeline, in-process MCP tools,<br/>RAG, memory, Loan Desk,<br/>deterministic controls"]
    OL["Ollama<br/>llama3.2:1b, llama3.2:latest"]
  end
  subgraph TOOLS["Security tool integrations (separate, pinned)"]
    MS["Cisco MCP Scanner<br/>static scan, isolated environment"]
    GK["garak<br/>recorded evaluation pack"]
  end
  OT["OpenTelemetry collector"]
  subgraph SPL["Splunk Enterprise (bundled by default; separate login, not behind the gateway)"]
    HEC["HEC ingestion (TLS)<br/>index agentsec_telemetry"]
    SW["Splunk Web: investigation searches,<br/>5 AI Security Assurance dashboards<br/>and the finding page"]
  end
  MAE["MAESTRO workbench<br/>(runs in the browser)"]
  CTF["CTF challenges<br/>(simulated; routed through the gateway<br/>only with the CTF overlay)"]
  B -->|"HTTPS"| GW
  GW -->|"allowlisted routes"| AS
  AS --- MAE
  AS --- CTF
  AS -->|"launches"| AB
  AB -->|"model calls"| OL
  AB -->|"events (OTLP)"| OT
  OT -->|"HEC, token"| HEC
  MS -.->|"evidence pack ingested by script"| HEC
  GK -.->|"evidence pack ingested by script"| HEC
  HEC --> SW
  AS -.->|"optional: REST search (token, CA)<br/>for VERIFIED"| HEC
  B -.->|"http://127.0.0.1:18000<br/>(SSH tunnel when remote)"| SW
```
The language model proposes; deterministic code authorizes and executes; Splunk observes and enforces nothing. Splunk Web is **not** routed through the gateway. The scanner and garak evidence the dashboards show comes from committed packs unless you run the scanner yourself. MAESTRO runs in the browser and the CTF is a scripted simulation.

## 2. Security and telemetry data flow

From a learner's action to an explained, retested finding, and which evidence is real, recorded or simulated.

```mermaid
flowchart LR
  A["Attack<br/>learner launches BASELINE,<br/>ATTACK or RETEST"] --> O["Observe<br/>AcmeBank emits events<br/>with one agentsec.run.id"]
  O --> C["OTel collector"]
  C -->|"HEC over TLS"| S[("Splunk index<br/>agentsec_telemetry")]
  P["Committed packs<br/>(Cisco scanner, garak, recorded runs)"] -.->|"ingest script"| S
  S --> I["Investigate<br/>run search, event sequence,<br/>finding page"]
  S --> D["Assurance dashboards<br/>rules compute status,<br/>evidence class and retest outcome"]
  I --> E["Interpret<br/>what happened, meaning,<br/>why it matters, control, action"]
  D --> E
  E --> R["Defend and retest<br/>defended profile, RETEST run"]
  R -->|"new run, same attack id"| O
  SIM["Simulated packets, CTF, MAESTRO drafts<br/>(never in Splunk)"] -.-> E
```

| Evidence class | Where it comes from | In Splunk and the dashboards |
|---|---|---|
| **LIVE** | A run you launched on this installation | Yes, scored |
| **RECORDED** | Committed specimens and packs captured earlier | Yes, scored, labelled recorded |
| **TEST_FIXTURE** | Synthetic negative-test runs | Only when you ask for them |
| **SIMULATED** | Simulated packets, the CTF, MAESTRO drafts | No |

A run whose telemetry never reaches Splunk cannot appear as a finding; the Academy then reports VERIFICATION UNAVAILABLE for it.

## 3. Deployment and trust boundaries

What listens where on the Ubuntu host in gateway mode (`docker-compose.gateway.yml`), and which connections are authenticated. The base `docker-compose.yml` alone (the older multi-port flow) publishes AcmeBank and the Attack Service on host ports; see the [legacy flow](LEGACY_MULTI_PORT_FLOW.md).

```mermaid
flowchart LR
  L["Learner (remote)"] -->|"SSH tunnel"| H
  subgraph H["Ubuntu host: Docker Compose project 'agentsec'"]
    direction TB
    GW["Gateway, default 127.0.0.1:443 (configurable)<br/>TLS, basic auth (learner, operator)"]
    subgraph NET["Docker network 'agentsec_mesh': not published"]
      AS["Attack Service :5001"]
      AB["AcmeBank :5000"]
      OL["Ollama :11434"]
    end
    OT["OTel collector<br/>on the Docker network; also published to<br/>127.0.0.1:4317, 4318 for the host"]
    SP["Splunk<br/>HEC 127.0.0.1:8088 (TLS, HEC token)<br/>Web 127.0.0.1:18000 (Splunk login)<br/>REST :8089 (inside Docker only; token + CA, optional)"]
  end
  GW -->|"1: authenticated at the gateway"| AS
  AS --> AB
  AB --> OL
  AB -->|"2: unauthenticated, inside the Docker network"| OT
  OT -->|"3: separately credentialed (HEC token)"| SP
  AS -.->|"4: separately credentialed (Splunk token)"| SP
  L -.->|"5: separately authenticated (Splunk login), outside the gateway"| SP
```

| Link | Authentication | Exposure |
|---|---|---|
| Browser to gateway | Basic auth, two roles, TLS | The only address to expose; loopback by default |
| Gateway to Attack Service | The gateway's decision | Inside the Docker network |
| Attack Service to AcmeBank, AcmeBank to Ollama | None (internal) | Not published on a host port |
| AcmeBank to collector | None | Docker network; the collector's host ports are loopback only |
| Collector to Splunk HEC | HEC token over TLS | Loopback only |
| Attack Service to Splunk REST | Splunk token, trusted CA | Optional, off by default |
| Browser to Splunk Web | Splunk's own login | Loopback only; **not routed through the gateway** |

**Not exposed:** AcmeBank, Ollama, the collector and HEC. The Docker bridge is not a security boundary against a hostile local user.

## 4. Agentic workflow and trust boundaries

One AcmeBank request, with the places where untrusted content enters and the two kinds of decision. **Boxes drawn with double side bars (the subroutine shape) are deterministic code.** The language model only proposes.

```mermaid
flowchart TB
  U["Applicant / operator input<br/>(untrusted text)"] -->|"TB-01 HTTP input boundary"| IN
  IN[["CTRL-INPUT-001 input pattern control<br/>deterministic: ENFORCE (defended profile)"]]
  IN --> ORCH["Agent pipeline / orchestrator"]
  RAG[("Retrieved context (RAG)<br/>untrusted data")] -->|"TB-02: classified, OBSERVE"| ORCH
  MEM[("Persistent memory<br/>untrusted data")] -->|"TB-03: classified, OBSERVE"| ORCH
  ORCH <-->|"TB-M01 model service boundary"| LLM["Language model (Ollama)<br/>GENERATES proposals:<br/>text, and which tool to call"]
  ORCH -->|"proposed tool call"| PDP
  PDP[["Tool policy decision point<br/>CTRL-MCP-001: tool, scope, resource<br/>deterministic: ENFORCE; issues an allow ticket"]]
  PDP -->|"ALLOW with ticket"| H["Tool handler executes"]
  PDP -.->|"DENY: nothing executes"| X["Denied call recorded"]
  H -->|"TB-05 downstream system boundary"| D[("Banking records (fixtures)<br/>human underwriter queue")]
  H --> RES["Tool result<br/>CTRL-MCP-RESULT-001 classifies it as data"]
  RES --> ORCH
  CAT["Tool catalog and descriptions<br/>CTRL-MCP-METADATA-001: data, OBSERVE"] --> ORCH
  ORCH -->|"TB-06 observability boundary"| T["Telemetry events"]
```
Three facts stay separate throughout: **what the model proposed**, **what the policy decided** (ALLOW or DENY) and **what actually executed**. An ALLOW is not an execution and a DENY is not an incident. OBSERVE controls record and classify; they do not block.

## 5. Attack execution and telemetry sequence

What happens when you press ATTACK, and where the run id and the evidence come from.

```mermaid
sequenceDiagram
  autonumber
  actor Op as Learner (operator role)
  participant Gw as Gateway
  participant Atk as Attack Service
  participant Bank as AcmeBank
  participant Coll as OTel collector
  participant Spl as Splunk
  Op->>Gw: POST /api/launch {lab_id, specimen_id, mode, execution}
  Gw->>Gw: TLS, basic auth, operator role, same-origin check, quota
  Gw->>Atk: forwarded request
  Atk->>Atk: closed request check against the launch allowlist<br/>(no payload, tool name, SPL or profile accepted from the client)
  Atk->>Atk: choose the profile on the server<br/>(ATTACK = vulnerable, BASELINE and RETEST = defended)
  Atk->>Bank: run the specimen
  Bank-->>Atk: result and local events
  Atk-->>Op: run_id, profile, mode, local event count,<br/>evidence_state WAITING_FOR_EVIDENCE
  Bank-)Coll: events (agentsec.run.id on every event)
  Coll-)Spl: HEC over TLS, index agentsec_telemetry
  Op->>Gw: GET /api/launches/{run_id}/evidence
  Gw->>Atk: forwarded
  Atk->>Spl: REST count for the run id (only if configured)
  Atk-->>Op: VERIFIED, NOT VERIFIED or VERIFICATION UNAVAILABLE
```
The profile is never sent by the browser: the same request produces a different outcome in ATTACK and RETEST because the server changed the profile.

## 6. Splunk investigation workflow

How a learner turns a run id into an explanation. Splunk observes; it enforces nothing.

```mermaid
flowchart LR
  A["Run id from the launch card<br/>(one per BASELINE, ATTACK, RETEST)"] --> B["Search<br/>index=agentsec_telemetry<br/>sourcetype=otel:agentic:json<br/>agentsec.run.id=RUN_ID"]
  B --> C["Reconstruct the sequence<br/>run.started, control decisions,<br/>hops and tool calls, run.completed"]
  C --> D{"Separate the facts"}
  D --> E["Control decision<br/>ALLOW / DENY / OBSERVE + reason"]
  D --> F["Execution<br/>did the handler or the model call start?"]
  D --> G["Observed evidence<br/>what the events show,<br/>and what they cannot show"]
  E --> H["Compare the three runs:<br/>same request, different profile"]
  F --> H
  G --> H
  H --> I["Evidence state<br/>VERIFIED / NOT VERIFIED /<br/>VERIFICATION UNAVAILABLE"]
  I --> J["Explain, then detect:<br/>a search or alert that would have caught it"]
```

## 7. CSA MAESTRO seven-layer architecture applied to AcmeBank

The seven layers of the Cloud Security Alliance's MAESTRO framework and where the AcmeBank elements sit in the lab's worked example. Layer 6 is vertical: it applies to every other layer. (The placement is this lab's analysis, not CSA material.)

```mermaid
flowchart TB
  subgraph L7["Layer 7: Agent Ecosystem"]
    E7["Applicants, operators, tool catalog, tool registry, coded agents and their identity claims, human underwriter queue"]
  end
  subgraph L6["Layer 6: Security and Compliance (vertical, spans all layers)"]
    E6["Tool policy decision point, OBSERVE controls, gateway edge (stand-in), read-only SPL policy"]
  end
  subgraph L5["Layer 5: Evaluation and Observability"]
    E5["OpenTelemetry export, Splunk, Cisco scanner and garak evidence adapters"]
  end
  subgraph L4["Layer 4: Deployment and Infrastructure"]
    E4["HTTPS gateway, application containers, Ollama container, Splunk container and volumes"]
  end
  subgraph L3["Layer 3: Agent Frameworks"]
    E3["AcmeBank application, agent pipeline, in-process MCP server"]
  end
  subgraph L2["Layer 2: Data Operations"]
    E2["RAG retriever, memory store, banking fixtures"]
  end
  subgraph L1["Layer 1: Foundation Models"]
    E1["Ollama-hosted language model"]
  end
  L7 --- L5
  L5 --- L4
  L4 --- L3
  L3 --- L2
  L2 --- L1
  L6 -.->|"applies to every layer"| L3
```
The workbench in the Academy (`/learn/lab/LAB-THREAT-MODELING-001`, Practice tab) walks through decomposition, trust boundaries, a threat on each layer, cross-layer paths, a risk register and a downloadable report. See [Benefits and security architecture](BENEFITS_AND_SECURITY_ARCHITECTURE.md#csa-maestro).

## 8. Workshop learner journey

```mermaid
flowchart TB
  S(["First login: learner credentials"]) --> O["Orientation (L0)<br/>LIVE vs RECORDED vs SIMULATED"]
  O --> L1["L1 Input and tool authority<br/>prompt injection, MCP tool authorization, scope, parameters, Loan Desk"]
  L1 --> L2["L2 Context and evidence are data<br/>tool results and catalog, RAG, memory, scanner evidence"]
  L2 --> L3["L3 Intent and identity<br/>goal integrity, delegation, confused deputy"]
  L3 --> L5["L5 to L6 Capstone and blue team<br/>Lending Assistant, Splunk Defender Bridge, incident, detection"]
  L5 --> L7["L7 to L10 Architecture, privacy, integrated incident, mastery<br/>(includes CSA MAESTRO threat modeling)"]
  subgraph LIVE["Each LIVE workshop"]
    direction LR
    P["Predict"] --> B["BASELINE<br/>defended"] --> A["ATTACK<br/>intentionally vulnerable"] --> R["RETEST<br/>defended"] --> I["Investigate in Splunk<br/>three run ids"] --> X["Explain"]
  end
  L1 -.-> LIVE
  L3 -.-> CTF["CTF challenges (simulated):<br/>Note Smuggler, Poisoned Catalog,<br/>Confused Deputy Relay"]
```

## Screenshots

These are captures of the real Academy and Attack Service interface. **How they were taken:** the Academy's own production bundle served by the product's Flask app on a development machine, driven by headless Chromium at 1366 by 860 pixels, **without a running AcmeBank, Ollama or Splunk behind it**, so launch cards and status panels show their "runtime not connected" state. They show the interface, not a live run. The exceptions are the last seven images: the MAESTRO example was captured through the HTTPS gateway, and the six assurance images from Splunk Web through an SSH tunnel, both on the disposable acceptance host with real data.

| Screenshot | File |
|---|---|
| Academy home | ![Academy home](images/academy-home.png) |
| Your Path (workshop path) | ![Your Path](images/workshop-path.png) |
| A workshop page (LAB-MCP-003, Scope Escalation) | ![Workshop page](images/workshop-page-mcp-003.png) |
| Loan Desk mission | ![Loan Desk mission](images/loan-desk-mission.png) |
| CTF challenges | ![CTF challenges](images/ctf-challenges.png) |
| MAESTRO workbench (blank draft) | ![MAESTRO workbench](images/maestro-workbench.png) |
| Risk Center | ![Risk Center](images/risk-center.png) |
| Attack Service home (the Attack UI) | ![Attack Service](images/attack-service-home.png) |
| MAESTRO workbench with the worked example loaded, through the HTTPS gateway on the acceptance host | ![MAESTRO example through the gateway](images/maestro-example-through-gateway.png) |
| AI Security Assurance: executive overview (Splunk Web, acceptance host) | ![Executive overview](images/assurance-executive.png) |
| AI Security Assurance: Agent, MCP and A2A | ![Agent, MCP and A2A](images/assurance-agent-mcp.png) |
| AI Security Assurance: supply chain and model | ![Supply chain and model](images/assurance-supply-chain.png) |
| AI Security Assurance: threat model coverage | ![Threat model coverage](images/assurance-threat-model.png) |
| AI Security Assurance: compliance and governance | ![Compliance and governance](images/assurance-compliance.png) |
| AI Security Assurance: one finding | ![Finding page](images/assurance-finding.png) |
