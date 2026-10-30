# Workshop catalog

All **33** workshops: the **Orientation** (a reading page, not a lab) and the **32 registered labs** in the Academy registry (`learning/academy/lab_registry_data.json`). This file was assembled from the registry, the curriculum (`learning/academy/curriculum.json`) and the workshop guides (`learning/academy/workshop_guides.json`), so the ids, levels, execution modes and expected results below are the Academy's own. Open any workshop in the Academy at `https://<your host>/learn/lab/<ID>` (for example `https://localhost/learn/lab/LAB-MCP-003` through the gateway).

## Read this first: what each execution mode means

| Mode | Count | What runs | Splunk evidence |
|---|---|---|---|
| **LIVE** | 13 | You launch **BASELINE**, **ATTACK** and **RETEST** runs from the lab page. The Attack Service drives AcmeBank (or the Loan Desk) on this machine. Some launches call the local Ollama model (the acceptance run of LAB-PI-001 produced `llm.*` events from `llama3.2:1b`); the MCP launches use the in-process MCP tool path and do not require the model; the Loan Desk uses `llama3.2:latest`. The ATTACK profile is intentionally vulnerable; RETEST is the defended profile. | Real events indexed in Splunk (`index=agentsec_telemetry`), one set per run id |
| **RECORDED** | 8 | Nothing runs. You analyse evidence captured earlier by the lab and committed to the repository. | Loaded into Splunk at start by the `splunk_hec_init` job; search with `earliest=0` |
| **SIMULATED packet** | 11 | Nothing runs. You analyse a committed, labelled simulated evidence packet. It enforces nothing. | Usually none: follow the recorded searches the page shows; packet content is not in Splunk unless the page says so |
| **Orientation** | 1 | A short reading page | None |

**Where you investigate.** The Academy investigates in-app: in a LIVE workshop the **Investigate** stage is a notebook where you press **Run** and the Attack Service executes an approved, fixed-template search against Splunk, then shows the rows, a chart and a plain-language reading. A LIVE workshop shows eight stages (Learn, Predict, Baseline, Attack, Investigate, Defend, Retest, Explain evidence); the Loan Desk shows its seven mission stages on the same rail. RECORDED and SIMULATED workshops launch nothing. In the per-workshop entries below, the starter searches, dashboards (`ws_...`) and hunt searches named under "Splunk evidence" are an optional **Advanced** view in Splunk Web, never a required step. The notebook was validated on one real Splunk 10.2.7 host (bundled Splunk, 2026-10-30); it was not validated against an external Splunk, Splunk Cloud or an organization certificate.

The three CTF challenges are not part of the 33: see [CTF](CTF.md) and the Academy page `/learn/challenges`. They are simulated (a scripted agent, not a language model).

**Not every workshop is a live LLM exercise.** 20 of 33 (the 19 recorded or simulated workshops and the Orientation) do not run an agent at all. Each page says which kind it is.

## Contents

| # | Workshop | Level | Mode |
|---|---|---|---|
| 1 | [Orientation](#orientation) | L0 | Reading |
| 2 | [Direct Prompt Injection](#lab-pi-001) (`LAB-PI-001`) | L1 | LIVE |
| 3 | [Tool Authorization](#lab-mcp-001) (`LAB-MCP-001`) | L1 | LIVE |
| 4 | [Scope Escalation](#lab-mcp-003) (`LAB-MCP-003`) | L1 | LIVE |
| 5 | [Parameter / Resource Authorization](#lab-mcp-004) (`LAB-MCP-004`) | L1 | LIVE |
| 6 | [Loan Desk: Agent-Authored Content](#lab-loandesk-001) (`LAB-LOANDESK-001`) | L1 | LIVE |
| 7 | [RAG / Retrieved Context](#lab-rag-context) (`LAB-RAG-CONTEXT`) | L2 | LIVE |
| 8 | [Persistent Memory](#lab-memory-001) (`LAB-MEMORY-001`) | L2 | LIVE |
| 9 | [Tool Result Trust](#lab-mcp-005) (`LAB-MCP-005`) | L2 | LIVE |
| 10 | [Tool Catalog](#lab-mcp-catalog) (`LAB-MCP-CATALOG`) | L2 | LIVE |
| 11 | [Scanner + Runtime Evidence](#lab-scanner-runtime-evidence) (`LAB-SCANNER-RUNTIME-EVIDENCE`) | L2 | RECORDED |
| 12 | [External Security Toolbox](#lab-external-evaluation-garak) (`LAB-EXTERNAL-EVALUATION-GARAK`) | L2 | RECORDED |
| 13 | [Goal / Instruction Integrity](#lab-agent-goal-integrity-001) (`LAB-AGENT-GOAL-INTEGRITY-001`) | L3 | LIVE |
| 14 | [Agent Identity / Delegation](#lab-agent-delegation-001) (`LAB-AGENT-DELEGATION-001`) | L3 | LIVE |
| 15 | [Confused Deputy](#lab-mcp-006) (`LAB-MCP-006`) | L3 | LIVE |
| 16 | [Lending Assistant Investigation](#lab-agentsec-capstone-001) (`LAB-AGENTSEC-CAPSTONE-001`) | L5 | LIVE |
| 17 | [Splunk Defender Bridge](#lab-splunk-defender-bridge) (`LAB-SPLUNK-DEFENDER-BRIDGE`) | L5 | RECORDED |
| 18 | [AcmeBank Incident AI-2026-001](#lab-blue-team-incident-001) (`LAB-BLUE-TEAM-INCIDENT-001`) | L6 | RECORDED |
| 19 | [Detection Engineering — Prove Your Coverage](#lab-detection-engineering) (`LAB-DETECTION-ENGINEERING`) | L6 | RECORDED |
| 20 | [AcmeBank Agentic Customer Operations Platform](#lab-threat-modeling-001) (`LAB-THREAT-MODELING-001`) | L7 | SIMULATED packet |
| 21 | [Agent Identity and Non-Human IAM](#lab-agent-identity-nhi) (`LAB-AGENT-IDENTITY-NHI`) | L7 | RECORDED |
| 22 | [A2A Authentication and Delegation](#lab-a2a-auth-delegation) (`LAB-A2A-AUTH-DELEGATION`) | L7 | SIMULATED packet |
| 23 | [Human Approval and Action Binding](#lab-hitl-approval) (`LAB-HITL-APPROVAL`) | L7 | SIMULATED packet |
| 24 | [Short-Lived Credential Lifetime](#lab-credential-lifetime) (`LAB-CREDENTIAL-LIFETIME`) | L7 | SIMULATED packet |
| 25 | [AcmeBank Incident PRIV-2026-001](#lab-privacy-data-governance-001) (`LAB-PRIVACY-DATA-GOVERNANCE-001`) | L8 | SIMULATED packet |
| 26 | [RAG Purpose Authorization](#lab-rag-purpose) (`LAB-RAG-PURPOSE`) | L8 | SIMULATED packet |
| 27 | [Memory Ownership and Isolation](#lab-recall-isolation) (`LAB-RECALL-ISOLATION`) | L8 | SIMULATED packet |
| 28 | [AI Asset Inventory](#lab-asset-inventory) (`LAB-ASSET-INVENTORY`) | L8 | SIMULATED packet |
| 29 | [Component Provenance](#lab-component-provenance) (`LAB-COMPONENT-PROVENANCE`) | L8 | SIMULATED packet |
| 30 | [Code Agent Bounds](#lab-code-agent-bounds) (`LAB-CODE-AGENT-BOUNDS`) | L8 | SIMULATED packet |
| 31 | [Change Bounds](#lab-change-bounds) (`LAB-CHANGE-BOUNDS`) | L8 | SIMULATED packet |
| 32 | [Acme Bank Incident AGENT-2026-009](#lab-multi-stage-incident-001) (`LAB-MULTI-STAGE-INCIDENT-001`) | L9 | RECORDED |
| 33 | [Acme Bank Capstone MASTER-2026-001](#lab-advanced-capstone-mastery-001) (`LAB-ADVANCED-CAPSTONE-MASTERY-001`) | L10 | RECORDED |

## Orientation

- **Level:** L0. **Effort:** 30-45 minutes. **Prerequisites:** Basic cybersecurity. Almost no agentic AI required.
- **What you learn:** What AgentSec is, how LIVE experiments work, and what Splunk does not do.
- **Mode:** reading only; nothing runs.
- **How to start:** open the Academy home (`/learn/`) and choose **Start the beginner route** (Understand, Connect, Recognize, Practice), or read [Getting started](GETTING_STARTED.md).
- **Completion:** you can say what LIVE, RECORDED and SIMULATED mean and why Splunk observes but does not enforce.
- **Reset:** nothing to reset.

## L1. Input and tool authority

*Prerequisites for this level:* L0 orientation. *Typical effort:* LIVE 2.5-3 hours. REPLAY grant anatomy +1.5-2 hours.

### Direct Prompt Injection
<a id="lab-pi-001"></a>
**`LAB-PI-001`** · level L1 · **LIVE** · Academy page `/learn/lab/LAB-PI-001`

- **Objectives:** Draw the trust boundary at acmebank.http_api / acmebank.llm_call.; Predict BASELINE vs VULNERABLE ATTACK vs DEFENDED RETEST before looking at Splunk.; Run the four validated investigation searches against one agentsec.run.id (Search or the WS-001 dashboard).; Distinguish ALLOW (decision) from llm.started (execution began).
- **Prerequisites:** a running lab (`./agentsec status` all OK); L0 orientation.
- **How to start:** open the workshop, read **Learn**, make your prediction on **Practice**, then use the launch card to run **BASELINE**, **ATTACK** and **RETEST** (the launch needs the `operator` role through the gateway).
- **What you do:** (1) Write your prediction before you press ATTACK, then run BASELINE, ATTACK and RETEST from the lab page: you should hold three different run ids. (2) Explain why RETEST differs from ATTACK: the request is the same; only the server-owned profile changed. (3) Find a run in Splunk Search with the starter search on the launch card and say what the events show and what they cannot (Splunk enforced nothing).
- **Expected security outcomes:** BASELINE: testbed.mode=BASELINE, profile=defended, terminal completed_allowed, llm_call_count>0 when Ollama works. ATTACK (intentionally vulnerable): INTENTIONALLY VULNERABLE LAB PROFILE: hop 0 ALLOW, real llm.started, testbed.mode=ATTACK. ALLOW is not proof the model approved the loan. RETEST (defended): hop 0 DENY, reason input_pattern_matched, attempted=false, executed=false, outcome=prevented, zero llm.* on a complete copy, testbed.mode=RETEST.
- **Defensive lesson:** Same adversarial input + different server-owned configuration = different security outcome. Not universal PI resistance.
- **Splunk evidence:** one set of events per run id in `index=agentsec_telemetry sourcetype=otel:agentic:json`, read in the Academy's Investigate notebook (the starter search on the launch card is the optional Splunk Web equivalent; `agentsec.run.id`); optional advanced dashboard `ws_lab_pi_001`; optional hunt search `Q-CONTROL-DECISION`, `Q-LLM-AFTER-DENY-POSITIVE-CONTROL`.
- **Completion:** Answer the 14 knowledge-check questions for this workshop. Knowledge check: see the workshop's `knowledge-check.md`.
- **Reset:** nothing to reset on the server: every launch creates a new run id, and earlier runs stay in Splunk. Your predictions and progress live in this browser only (clear the site data for the Academy to start over).
- **Documentation:** [README](../learning/level_1/LAB-PI-001/README.md) · [workshop guide](../learning/level_1/LAB-PI-001/workshop.md) · [knowledge check](../learning/level_1/LAB-PI-001/knowledge-check.md) · [Academy explainer](../learning/academy/explainers/LAB-PI-001.json) · [Splunk dashboard source](../splunk_app/agentsec/default/data/ui/views/ws_lab_pi_001.xml)

### Tool Authorization
<a id="lab-mcp-001"></a>
**`LAB-MCP-001`** · level L1 · **LIVE** · Academy page `/learn/lab/LAB-MCP-001`

- **Objectives:** Explain what JSON-RPC tools/call represents in this lab (in-process, not a full remote MCP product).; Distinguish tool existence (registered) from authorization (granted).; Explain why known-but-ungranted is DENY and unknown is ERROR.; Explain why ALLOW is not execution, why runtime handler count is authoritative, why indexed mcp.started only corroborates a complete copy, and why mcp.failed…
- **Prerequisites:** a running lab (`./agentsec status` all OK); L0 orientation.
- **How to start:** open the workshop, read **Learn**, make your prediction on **Practice**, then use the launch card to run **BASELINE**, **ATTACK** and **RETEST** (the launch needs the `operator` role through the gateway).
- **What you do:** (1) Write your prediction before you press ATTACK, then run BASELINE, ATTACK and RETEST from the lab page: you should hold three different run ids. (2) Explain why RETEST differs from ATTACK: the request is the same; only the server-owned profile changed. (3) Find a run in Splunk Search with the starter search on the launch card and say what the events show and what they cannot (Splunk enforced nothing).
- **Expected security outcomes:** BASELINE: testbed.mode=BASELINE, profile=defended, ALLOW tool_granted, handler_invoke_count=1, mcp.completed. ATTACK (intentionally vulnerable): INTENTIONALLY VULNERABLE LAB PROFILE: ALLOW with a fail-open reason, mcp.started, handler_invoke_count=1, testbed.mode=ATTACK. ALLOW is not execution by itself — mcp.started is. RETEST (defended): DENY tool_not_granted, attempted=false, executed=false, outcome=prevented, handler_invoke_count=0, no mcp.started on a complete copy, testbed.mode=RETEST.
- **Defensive lesson:** Same adversarial request + different server-owned configuration = different security outcome. Not universal tool-authorization resistance.
- **Splunk evidence:** one set of events per run id in `index=agentsec_telemetry sourcetype=otel:agentic:json`, read in the Academy's Investigate notebook (the starter search on the launch card is the optional Splunk Web equivalent; `agentsec.run.id`); optional advanced dashboard `ws_lab_detection_engineering`; optional hunt search `DET-MCP-001-POSITIVE-CONTROL`, `DET-MCP-001-SCOPE-POSITIVE-CONTROL`.
- **Completion:** Answer the 13 knowledge-check questions for this workshop. Knowledge check: see the workshop's `knowledge-check.md`.
- **Reset:** nothing to reset on the server: every launch creates a new run id, and earlier runs stay in Splunk. Your predictions and progress live in this browser only (clear the site data for the Academy to start over).
- **Documentation:** [README](../learning/level_1/LAB-MCP-001/README.md) · [workshop guide](../learning/level_1/LAB-MCP-001/workshop.md) · [knowledge check](../learning/level_1/LAB-MCP-001/knowledge-check.md) · [Splunk dashboard source](../splunk_app/agentsec/default/data/ui/views/ws_lab_detection_engineering.xml)

### Scope Escalation
<a id="lab-mcp-003"></a>
**`LAB-MCP-003`** · level L1 · **LIVE** · Academy page `/learn/lab/LAB-MCP-003`

- **Objectives:** Distinguish tool grant from scope grant.; Explain three states: granted (policy:read), known-but-ungranted (policy:restricted:read), unknown (policy:write).; Explain why known-but-ungranted is DENY and unknown catalog tokens are ERROR.; Explain why ALLOW is not execution and why fail-open does not rewrite allowed_scope.
- **Prerequisites:** a running lab (`./agentsec status` all OK); L0 orientation.
- **How to start:** open the workshop, read **Learn**, make your prediction on **Practice**, then use the launch card to run **BASELINE**, **ATTACK** and **RETEST** (the launch needs the `operator` role through the gateway).
- **What you do:** (1) Write your prediction before you press ATTACK, then run BASELINE, ATTACK and RETEST from the lab page: you should hold three different run ids. (2) Explain why RETEST differs from ATTACK: the request is the same; only the server-owned profile changed. (3) Find a run in Splunk Search with the starter search on the launch card and say what the events show and what they cannot (Splunk enforced nothing).
- **Expected security outcomes:** BASELINE: testbed.mode=BASELINE, profile=defended, ALLOW tool_granted, handler_invoke_count=1. ATTACK (intentionally vulnerable): INTENTIONALLY VULNERABLE LAB PROFILE: ALLOW with a vulnerable_profile_fail_open reason, mcp.started, handler_invoke_count=1; the allowed scope stays policy:read. ALLOW is not execution by… RETEST (defended): DENY scope_not_granted, attempted=false, executed=false, handler_invoke_count=0; testbed.mode=RETEST.
- **Defensive lesson:** Same request plus different server-owned configuration gives a different outcome. Not universal resistance.
- **Splunk evidence:** one set of events per run id in `index=agentsec_telemetry sourcetype=otel:agentic:json`, read in the Academy's Investigate notebook (the starter search on the launch card is the optional Splunk Web equivalent; `agentsec.run.id`); optional advanced dashboard `ws_lab_mcp_003`.
- **Completion:** Answer the 12 knowledge-check questions for this workshop. Knowledge check: see the workshop's `knowledge-check.md`.
- **Reset:** nothing to reset on the server: every launch creates a new run id, and earlier runs stay in Splunk. Your predictions and progress live in this browser only (clear the site data for the Academy to start over).
- **Documentation:** [README](../learning/level_1/LAB-MCP-003/README.md) · [workshop guide](../learning/level_1/LAB-MCP-003/workshop.md) · [knowledge check](../learning/level_1/LAB-MCP-003/knowledge-check.md) · [Academy explainer](../learning/academy/explainers/LAB-MCP-003.json) · [Splunk dashboard source](../splunk_app/agentsec/default/data/ui/views/ws_lab_mcp_003.xml)

### Parameter / Resource Authorization
<a id="lab-mcp-004"></a>
**`LAB-MCP-004`** · level L1 · **LIVE** · Academy page `/learn/lab/LAB-MCP-004`

- **Objectives:** Distinguish tool grant, scope grant, and resource grant.; Explain three resource states: granted (lending-basics), known-but-ungranted (executive-restricted), unknown (does-not-exist).; Explain why known-but-ungranted is DENY and unknown catalog tokens are ERROR.; Explain why a valid policy_id string is not automatically authorized.
- **Prerequisites:** a running lab (`./agentsec status` all OK); L0 orientation.
- **How to start:** open the workshop, read **Learn**, make your prediction on **Practice**, then use the launch card to run **BASELINE**, **ATTACK** and **RETEST** (the launch needs the `operator` role through the gateway).
- **What you do:** (1) Write your prediction before you press ATTACK, then run BASELINE, ATTACK and RETEST from the lab page: you should hold three different run ids. (2) Explain why RETEST differs from ATTACK: the request is the same; only the server-owned profile changed. (3) Find a run in Splunk Search with the starter search on the launch card and say what the events show and what they cannot (Splunk enforced nothing).
- **Expected security outcomes:** BASELINE: testbed.mode=BASELINE, profile=defended, ALLOW tool_granted, handler_invoke_count=1. ATTACK (intentionally vulnerable): INTENTIONALLY VULNERABLE LAB PROFILE: ALLOW with a vulnerable_profile_fail_open reason, mcp.started, handler_invoke_count=1. ALLOW is not execution by itself; mcp.started is. RETEST (defended): DENY resource_not_granted, attempted=false, executed=false, handler_invoke_count=0; testbed.mode=RETEST.
- **Defensive lesson:** Same request plus different server-owned configuration gives a different outcome. Not universal resistance.
- **Splunk evidence:** one set of events per run id in `index=agentsec_telemetry sourcetype=otel:agentic:json`, read in the Academy's Investigate notebook (the starter search on the launch card is the optional Splunk Web equivalent; `agentsec.run.id`); optional advanced dashboard `ws_lab_mcp_004`; optional hunt search `DET-MCP-001-RESOURCE-POSITIVE-CONTROL`, `Q-MCP-RESOURCE-AUTHZ`.
- **Completion:** Answer the 15 knowledge-check questions for this workshop. Knowledge check: see the workshop's `knowledge-check.md`.
- **Reset:** nothing to reset on the server: every launch creates a new run id, and earlier runs stay in Splunk. Your predictions and progress live in this browser only (clear the site data for the Academy to start over).
- **Documentation:** [README](../learning/level_1/LAB-MCP-004/README.md) · [workshop guide](../learning/level_1/LAB-MCP-004/workshop.md) · [knowledge check](../learning/level_1/LAB-MCP-004/knowledge-check.md) · [Academy explainer](../learning/academy/explainers/LAB-MCP-004.json) · [Splunk dashboard source](../splunk_app/agentsec/default/data/ui/views/ws_lab_mcp_004.xml)

### Loan Desk: Agent-Authored Content
<a id="lab-loandesk-001"></a>
**`LAB-LOANDESK-001`** · level L1 · **LIVE** · Academy page `/learn/lab/LAB-LOANDESK-001`

- **Objectives:** a valid, in-scope action can still carry an attacker's content, so authorization must also constrain what an allowed tool may carry.
- **Prerequisites:** a running lab (`./agentsec status` all OK); the Loan Desk model `llama3.2:latest` installed; L0 orientation.
- **How to start:** open `/learn/loan-desk` (the mission), lock a prediction, then run the Attack stage. The agent is a real model (`llama3.2:latest`) whose every proposal passes a deterministic policy engine.
- **What you do:** (1) Complete the ten steps: Understand through Explain. (2) Show from recorded events that the attack text reached the queue in BASELINE and did not in HARDENED, and say whether the business task completed. (3) Say whether your evidence is local or Splunk-verified.
- **Expected security outcomes:** BASELINE posture: the model files whatever note it is given; an applicant-planted instruction can reach the human underwriter queue (ALLOW: tool, scope and applicant are valid, the note content is not checked). HARDENED retest of the same attack: DENY argument_not_allowed:note and the handler does not run; whether the business task completed is recorded separately.
- **Defensive lesson:** Separate the model's proposal, the policy decision and the executed handler: they are three facts.
- **Splunk evidence:** the mission run's events (its own `agentsec.run.id`), searchable in Splunk by that run id. The mission's Investigate stage is the in-Academy notebook. The older host-side verifier (`scripts/loan_desk_verifier.sh`) is legacy: only the `scripts/lab-up.sh` flow enables it (`AGENTSEC_LEGACY_HOST_VERIFIER=1`), it is ignored behind the gateway, and no default run is Splunk-VERIFIED. Evidence states: [Loan Desk mission](LOAN_DESK_MISSION.md); optional advanced dashboard `ws_lab_loandesk_001`; optional hunt search `Q-LOANDESK-BUSINESS`, `Q-LOANDESK-DECISIONS`.
- **Completion:** Say whether your evidence is local or Splunk-verified. Knowledge check: see the workshop's `knowledge-check.md`.
- **Reset:** nothing to reset on the server: every launch creates a new run id, and earlier runs stay in Splunk. Your predictions and progress live in this browser only (clear the site data for the Academy to start over).
- **Documentation:** [README](../learning/level_1/LAB-LOANDESK-001/README.md) · [knowledge check](../learning/level_1/LAB-LOANDESK-001/knowledge-check.md) · [Splunk dashboard source](../splunk_app/agentsec/default/data/ui/views/ws_lab_loandesk_001.xml)

## L2. Context and evidence are data

*Prerequisites for this level:* L1 LIVE (PI and Tool Authorization). *Typical effort:* LIVE 3-3.5 hours. REPLAY +3-3.5 hours.

### RAG / Retrieved Context
<a id="lab-rag-context"></a>
**`LAB-RAG-CONTEXT`** · level L2 · **LIVE** · Academy page `/learn/lab/LAB-RAG-CONTEXT`

- **Objectives:** Reconstruct retrieve → classify → request → authorize → execute as four evidence planes.; Treat provenance as source identity, not trust.; Explain why untrusted_data is classification, not malice.; Explain why ATTACK follow-on ALLOW is a labeled lab overlay, not a server grant.
- **Prerequisites:** a running lab (`./agentsec status` all OK); L1 LIVE (PI and Tool Authorization).
- **How to start:** open the workshop, read **Learn**, make your prediction on **Practice**, then use the launch card to run **BASELINE**, **ATTACK** and **RETEST** (the launch needs the `operator` role through the gateway).
- **What you do:** (1) Write your prediction before you press ATTACK, then run BASELINE, ATTACK and RETEST from the lab page: you should hold three different run ids. (2) Explain why RETEST differs from ATTACK: the request is the same; only the server-owned profile changed. (3) Find a run in Splunk Search with the starter search on the launch card and say what the events show and what they cannot (Splunk enforced nothing).
- **Expected security outcomes:** BASELINE: testbed.mode=BASELINE, profile=defended, CONTEXT-001 OBSERVE, no follow-on, handler 0. ATTACK (intentionally vulnerable): INTENTIONALLY VULNERABLE LAB PROFILE: CTRL-RAG-CONTEXT-001 OBSERVE retrieved_context_is_data; follow-on ALLOW vulnerable_profile_fail_open:retrieved_context_derived_authority; mcp.started;… RETEST (defended): CONTEXT-001 OBSERVE retrieved_context_is_data; follow-on DENY tool_not_granted; handler_invoke_count=0; no mcp.started on a complete copy; testbed.mode=RETEST.
- **Defensive lesson:** SAME RETRIEVED CONTENT. SAME REQUEST. DIFFERENT AUTHORIZATION. DIFFERENT EXECUTION. Not universal RAG resistance.
- **Splunk evidence:** one set of events per run id in `index=agentsec_telemetry sourcetype=otel:agentic:json`, read in the Academy's Investigate notebook (the starter search on the launch card is the optional Splunk Web equivalent; `agentsec.run.id`); optional advanced dashboard `ws_lab_rag_context`; optional hunt search `Q-RAG-CONTEXT-AUTHORITY`, `catalog`.
- **Completion:** Answer the 20 knowledge-check questions for this workshop. Knowledge check: see the workshop's `knowledge-check.md`.
- **Reset:** nothing to reset on the server: every launch creates a new run id, and earlier runs stay in Splunk. Your predictions and progress live in this browser only (clear the site data for the Academy to start over).
- **Documentation:** [README](../learning/level_1/LAB-RAG-CONTEXT/README.md) · [workshop guide](../learning/level_1/LAB-RAG-CONTEXT/workshop.md) · [knowledge check](../learning/level_1/LAB-RAG-CONTEXT/knowledge-check.md) · [Academy explainer](../learning/academy/explainers/LAB-RAG-CONTEXT.json) · [Splunk dashboard source](../splunk_app/agentsec/default/data/ui/views/ws_lab_rag_context.xml)

### Persistent Memory
<a id="lab-memory-001"></a>
**`LAB-MEMORY-001`** · level L2 · **LIVE** · Academy page `/learn/lab/LAB-MEMORY-001`

- **Objectives:** Reconstruct WRITE RUN → store → later RECALL RUN → classify → request → authorize → execute as five evidence planes.; Treat write run.id and recall run.id as different identities linked by source_run_id.; Treat provenance as source identity, not trust.; Explain why untrusted_data is classification, not malice.
- **Prerequisites:** a running lab (`./agentsec status` all OK); L1 LIVE (PI and Tool Authorization).
- **How to start:** open the workshop, read **Learn**, make your prediction on **Practice**, then use the launch card to run **BASELINE**, **ATTACK** and **RETEST** (the launch needs the `operator` role through the gateway).
- **What you do:** (1) Write your prediction before you press ATTACK, then run BASELINE, ATTACK and RETEST from the lab page: you should hold three different run ids. (2) Explain why RETEST differs from ATTACK: the request is the same; only the server-owned profile changed. (3) Find a run in Splunk Search with the starter search on the launch card and say what the events show and what they cannot (Splunk enforced nothing).
- **Expected security outcomes:** BASELINE: testbed.mode=BASELINE, profile=defended, CONTEXT-001 OBSERVE, no follow-on, handler 0. ATTACK (intentionally vulnerable): INTENTIONALLY VULNERABLE LAB PROFILE: WRITE persists untrusted_data; RECALL CTRL-MEMORY-CONTEXT-001 OBSERVE memory_context_is_data; follow-on ALLOW… RETEST (defended): CONTEXT-001 OBSERVE memory_context_is_data; follow-on DENY tool_not_granted; handler_invoke_count=0; no mcp.started on a complete copy; testbed.mode=RETEST.
- **Defensive lesson:** SAME MEMORY. SAME REQUEST. DIFFERENT AUTHORIZATION. DIFFERENT EXECUTION. Not universal memory-poisoning resistance.
- **Splunk evidence:** one set of events per run id in `index=agentsec_telemetry sourcetype=otel:agentic:json`, read in the Academy's Investigate notebook (the starter search on the launch card is the optional Splunk Web equivalent; `agentsec.run.id`); optional advanced dashboard `ws_lab_memory_security`; optional hunt search `Q-MEMORY-CONTEXT-AUTHORITY`, `catalog`.
- **Completion:** Answer the 30 knowledge-check questions for this workshop. Knowledge check: see the workshop's `knowledge-check.md`.
- **Reset:** nothing to reset on the server: every launch creates a new run id, and earlier runs stay in Splunk. Your predictions and progress live in this browser only (clear the site data for the Academy to start over).
- **Documentation:** [README](../learning/level_1/LAB-MEMORY-001/README.md) · [workshop guide](../learning/level_1/LAB-MEMORY-001/workshop.md) · [knowledge check](../learning/level_1/LAB-MEMORY-001/knowledge-check.md) · [Academy explainer](../learning/academy/explainers/LAB-MEMORY-001.json) · [Splunk dashboard source](../splunk_app/agentsec/default/data/ui/views/ws_lab_memory_security.xml)

### Tool Result Trust
<a id="lab-mcp-005"></a>
**`LAB-MCP-005`** · level L2 · **LIVE** · Academy page `/learn/lab/LAB-MCP-005`

- **Objectives:** Explain why an authorized tool does not make its result authoritative.; Separate provenance, content, and authority.; Name INV-002 as the MCP-005 invariant.; Explain why ATTACK follow-on is labeled ALLOW (overlay, not server grant).
- **Prerequisites:** a running lab (`./agentsec status` all OK); L1 LIVE (PI and Tool Authorization).
- **How to start:** open the workshop, read **Learn**, make your prediction on **Practice**, then use the launch card to run **BASELINE**, **ATTACK** and **RETEST** (the launch needs the `operator` role through the gateway).
- **What you do:** (1) Write your prediction before you press ATTACK, then run BASELINE, ATTACK and RETEST from the lab page: you should hold three different run ids. (2) Explain why RETEST differs from ATTACK: the request is the same; only the server-owned profile changed. (3) Find a run in Splunk Search with the starter search on the launch card and say what the events show and what they cannot (Splunk enforced nothing).
- **Expected security outcomes:** BASELINE: testbed.mode=BASELINE, profile=defended, ALLOW tool_granted, handler_invoke_count=1. ATTACK (intentionally vulnerable): INTENTIONALLY VULNERABLE LAB PROFILE: the first call ALLOW; the result is classified MALICIOUS; the follow-on lookup_customer_tier is ALLOW with… RETEST (defended): the first call ALLOW; the follow-on lookup_customer_tier DENY tool_not_granted with handler_invoke_count=0; testbed.mode=RETEST.
- **Defensive lesson:** Same request plus different server-owned configuration gives a different outcome. Not universal resistance.
- **Splunk evidence:** one set of events per run id in `index=agentsec_telemetry sourcetype=otel:agentic:json`, read in the Academy's Investigate notebook (the starter search on the launch card is the optional Splunk Web equivalent; `agentsec.run.id`); optional advanced dashboard `ws_lab_mcp_005`; optional hunt search `Q-MCP-RESULT-AUTHORITY`, `catalog`.
- **Completion:** Answer the 10 knowledge-check questions for this workshop. Knowledge check: see the workshop's `knowledge-check.md`.
- **Reset:** nothing to reset on the server: every launch creates a new run id, and earlier runs stay in Splunk. Your predictions and progress live in this browser only (clear the site data for the Academy to start over).
- **Documentation:** [README](../learning/level_1/LAB-MCP-005/README.md) · [workshop guide](../learning/level_1/LAB-MCP-005/workshop.md) · [knowledge check](../learning/level_1/LAB-MCP-005/knowledge-check.md) · [Academy explainer](../learning/academy/explainers/LAB-MCP-005.json) · [Splunk dashboard source](../splunk_app/agentsec/default/data/ui/views/ws_lab_mcp_005.xml)

### Tool Catalog
<a id="lab-mcp-catalog"></a>
**`LAB-MCP-CATALOG`** · level L2 · **LIVE** · Academy page `/learn/lab/LAB-MCP-CATALOG`

- **Objectives:** Separate catalog metadata from the tool itself.; Read METADATA-001 OBSERVE as classification, not authorization.; Explain why the first lookup_policy ALLOW is legitimate on A/B/C.; Show ATTACK and RETEST used the same description hash.
- **Prerequisites:** a running lab (`./agentsec status` all OK); L1 LIVE (PI and Tool Authorization).
- **How to start:** open the workshop, read **Learn**, make your prediction on **Practice**, then use the launch card to run **BASELINE**, **ATTACK** and **RETEST** (the launch needs the `operator` role through the gateway).
- **What you do:** (1) Write your prediction before you press ATTACK, then run BASELINE, ATTACK and RETEST from the lab page: you should hold three different run ids. (2) Explain why RETEST differs from ATTACK: the request is the same; only the server-owned profile changed. (3) Find a run in Splunk Search with the starter search on the launch card and say what the events show and what they cannot (Splunk enforced nothing).
- **Expected security outcomes:** BASELINE: testbed.mode=BASELINE, profile=defended, ALLOW tool_granted, handler_invoke_count=1. ATTACK (intentionally vulnerable): INTENTIONALLY VULNERABLE LAB PROFILE: the first call ALLOW; METADATA-001 only OBSERVEs; the follow-on lookup_customer_tier is ALLOW with vulnerable_profile_fail_open:metadata_derived_authority… RETEST (defended): the first call ALLOW; the follow-on lookup_customer_tier DENY tool_not_granted with handler_invoke_count=0; testbed.mode=RETEST.
- **Defensive lesson:** Same request plus different server-owned configuration gives a different outcome. Not universal resistance.
- **Splunk evidence:** one set of events per run id in `index=agentsec_telemetry sourcetype=otel:agentic:json`, read in the Academy's Investigate notebook (the starter search on the launch card is the optional Splunk Web equivalent; `agentsec.run.id`); optional advanced dashboard `ws_lab_mcp_catalog`; optional hunt search `Q-MCP-CATALOG-AUTHORITY`, `Q-SCANNER-ARTIFACT`.
- **Completion:** Answer the 13 knowledge-check questions for this workshop. Knowledge check: see the workshop's `knowledge-check.md`.
- **Reset:** nothing to reset on the server: every launch creates a new run id, and earlier runs stay in Splunk. Your predictions and progress live in this browser only (clear the site data for the Academy to start over).
- **Documentation:** [README](../learning/level_1/LAB-MCP-CATALOG/README.md) · [workshop guide](../learning/level_1/LAB-MCP-CATALOG/workshop.md) · [knowledge check](../learning/level_1/LAB-MCP-CATALOG/knowledge-check.md) · [Academy explainer](../learning/academy/explainers/LAB-MCP-CATALOG.json) · [Splunk dashboard source](../splunk_app/agentsec/default/data/ui/views/ws_lab_mcp_catalog.xml)

### Scanner + Runtime Evidence
<a id="lab-scanner-runtime-evidence"></a>
**`LAB-SCANNER-RUNTIME-EVIDENCE`** · level L2 · **RECORDED (replayed evidence)** · Academy page `/learn/lab/LAB-SCANNER-RUNTIME-EVIDENCE`

- **Objectives:** Name the three evidence planes and what each can prove.; Read ZERO FINDINGS as scan-executed-with-zero-findings, not SAFE.; Keep scanner-native HIGH as scanner-native severity.; Correlate scanner and runtime evidence with description SHA-256, not artifact.sha256.
- **Prerequisites:** none beyond the Academy: L1 LIVE (PI and Tool Authorization).
- **How to start:** open the workshop, read **Learn**, choose your prediction on **Practice**, then reveal the recorded or simulated evidence. Nothing is launched.
- **What you do:** (1) Pick two descriptions and state what the scanner says and what the runtime recorded for each. (2) Say what each kind of evidence can and cannot prove. (3) Answer the 15 knowledge-check questions for this workshop.
- **Expected security outcomes:** Scanner findings and runtime decisions are laid side by side, joined by the tool description's SHA-256. A scanner flag and a runtime ALLOW/DENY are separate facts about the same description.
- **Defensive lesson:** Join evidence on a stable key (the description hash) before drawing a conclusion.
- **Splunk evidence:** committed recorded runs, loaded into Splunk at start (search with `earliest=0`).
- **Completion:** Answer the 15 knowledge-check questions for this workshop. Knowledge check: see the workshop's `knowledge-check.md`.
- **Reset:** nothing to reset on the server and nothing was launched. Your predictions and progress live in this browser only (clear the site data for the Academy to start over).
- **Documentation:** [README](../learning/level_1/LAB-SCANNER-RUNTIME-EVIDENCE/README.md) · [workshop guide](../learning/level_1/LAB-SCANNER-RUNTIME-EVIDENCE/workshop.md) · [knowledge check](../learning/level_1/LAB-SCANNER-RUNTIME-EVIDENCE/knowledge-check.md) · [Academy explainer](../learning/academy/explainers/LAB-SCANNER-RUNTIME-EVIDENCE.json)

### External Security Toolbox
<a id="lab-external-evaluation-garak"></a>
**`LAB-EXTERNAL-EVALUATION-GARAK`** · level L2 · **RECORDED (replayed evidence)** · Academy page `/learn/lab/LAB-EXTERNAL-EVALUATION-GARAK`

- **Objectives:** One adversarial probe, run once against one local model, gave one native PASS. This checkpoint shows exactly what was recorded, where it came from and why that is not a comprehensive evaluation of the model's robustness.
- **Prerequisites:** none beyond the Academy: L1 LIVE (PI and Tool Authorization).
- **How to start:** open the workshop, read **Learn**, choose your prediction on **Practice**, then reveal the recorded or simulated evidence. Nothing is launched.
- **What you do:** (1) State what was run, how many times and against what. (2) Say why a PASS here is not evidence of robustness in general. (3) Answer the 15 knowledge-check questions for this workshop.
- **Expected security outcomes:** One adversarial probe, run once against one local model, recorded one native PASS. The page shows exactly what was recorded and where it came from.
- **Defensive lesson:** Keep external evaluation evidence separate from runtime control evidence.
- **Splunk evidence:** committed recorded runs, loaded into Splunk at start (search with `earliest=0`); optional advanced dashboard `ws_lab_external_evaluation_garak`; optional hunt search `Q-EXTERNAL-EVIDENCE-PLANES`, `Q-GARAK-EVALUATION`.
- **Completion:** Answer the 15 knowledge-check questions for this workshop. Knowledge check: see the workshop's `knowledge-check.md`.
- **Reset:** nothing to reset on the server and nothing was launched. Your predictions and progress live in this browser only (clear the site data for the Academy to start over).
- **Documentation:** [README](../learning/level_1/LAB-EXTERNAL-EVALUATION-GARAK/README.md) · [workshop guide](../learning/level_1/LAB-EXTERNAL-EVALUATION-GARAK/workshop.md) · [knowledge check](../learning/level_1/LAB-EXTERNAL-EVALUATION-GARAK/knowledge-check.md) · [Academy explainer](../learning/academy/explainers/LAB-EXTERNAL-EVALUATION-GARAK.json) · [Splunk dashboard source](../splunk_app/agentsec/default/data/ui/views/ws_lab_external_evaluation_garak.xml)

## L3. Intent and identity

*Prerequisites for this level:* L2 LIVE (RAG and Memory). *Typical effort:* LIVE 2.5-3 hours. Confused Deputy REPLAY +45-60 minutes.

### Goal / Instruction Integrity
<a id="lab-agent-goal-integrity-001"></a>
**`LAB-AGENT-GOAL-INTEGRITY-001`** · level L3 · **LIVE** · Academy page `/learn/lab/LAB-AGENT-GOAL-INTEGRITY-001`

- **Objectives:** Reconstruct TASK → INSTRUCTION → PROPOSED GOAL → GOAL DECISION → TOOL AUTHZ → EXECUTION as five evidence planes.; Explain why CTRL-GOAL-INTEGRITY-001 is not the MCP tool PDP.; Explain why untrusted_instruction is classification, not malice.; Explain why ATTACK overlay OBSERVE is a labeled lab mechanism, not a production IOC.
- **Prerequisites:** a running lab (`./agentsec status` all OK); L2 LIVE (RAG and Memory).
- **How to start:** open the workshop, read **Learn**, make your prediction on **Practice**, then use the launch card to run **BASELINE**, **ATTACK** and **RETEST** (the launch needs the `operator` role through the gateway).
- **What you do:** (1) Write your prediction before you press ATTACK, then run BASELINE, ATTACK and RETEST from the lab page: you should hold three different run ids. (2) Explain why RETEST differs from ATTACK: the request is the same; only the server-owned profile changed. (3) Find a run in Splunk Search with the starter search on the launch card and say what the events show and what they cannot (Splunk enforced nothing).
- **Expected security outcomes:** BASELINE: testbed.mode=BASELINE, profile=defended, GOAL OBSERVE, MCP ALLOW tool_granted, in-task 1, wrong-goal 0. ATTACK (intentionally vulnerable): INTENTIONALLY VULNERABLE LAB PROFILE: CTRL-GOAL-INTEGRITY-001 OBSERVE vulnerable_profile_fail_open:untrusted_instruction_derived_task_authority; proposed extract_full_policy; effective… RETEST (defended): GOAL DENY unauthorized_task_expansion; MCP ALLOW tool_granted; wrong-goal handler 0; in-task handler 1; testbed.mode=RETEST.
- **Defensive lesson:** SAME TASK. SAME MALICIOUS INSTRUCTION. SAME PROPOSED GOAL. SAME AUTHORIZED TOOL. DIFFERENT GOAL-INTEGRITY DECISION. DIFFERENT EFFECTIVE ACTION. Not universal prompt-injection resistance.
- **Splunk evidence:** one set of events per run id in `index=agentsec_telemetry sourcetype=otel:agentic:json`, read in the Academy's Investigate notebook (the starter search on the launch card is the optional Splunk Web equivalent; `agentsec.run.id`); optional advanced dashboard `ws_lab_agent_goal_integrity`; optional hunt search `Q-GOAL-INTEGRITY-AUTHORITY`, `catalog`.
- **Completion:** Answer the 20 knowledge-check questions for this workshop. Knowledge check: see the workshop's `knowledge-check.md`.
- **Reset:** nothing to reset on the server: every launch creates a new run id, and earlier runs stay in Splunk. Your predictions and progress live in this browser only (clear the site data for the Academy to start over).
- **Documentation:** [README](../learning/level_1/LAB-AGENT-GOAL-INTEGRITY-001/README.md) · [workshop guide](../learning/level_1/LAB-AGENT-GOAL-INTEGRITY-001/workshop.md) · [knowledge check](../learning/level_1/LAB-AGENT-GOAL-INTEGRITY-001/knowledge-check.md) · [Academy explainer](../learning/academy/explainers/LAB-AGENT-GOAL-INTEGRITY-001.json) · [Splunk dashboard source](../splunk_app/agentsec/default/data/ui/views/ws_lab_agent_goal_integrity.xml)

### Agent Identity / Delegation
<a id="lab-agent-delegation-001"></a>
**`LAB-AGENT-DELEGATION-001`** · level L3 · **LIVE** · Academy page `/learn/lab/LAB-AGENT-DELEGATION-001`

- **Objectives:** Identify principal applicant-web, caller acme-agent-advisor-005, callee acme-agent-fulfillment-006.; Explain why those identifiers are attribution, not cryptographic authentication.; Identify the privileged delegation claim (customer:read / lookup_customer_tier / cust-001).; Explain why the claim is not a grant.
- **Prerequisites:** a running lab (`./agentsec status` all OK); L2 LIVE (RAG and Memory).
- **How to start:** open the workshop, read **Learn**, make your prediction on **Practice**, then use the launch card to run **BASELINE**, **ATTACK** and **RETEST** (the launch needs the `operator` role through the gateway).
- **What you do:** (1) Write your prediction before you press ATTACK, then run BASELINE, ATTACK and RETEST from the lab page: you should hold three different run ids. (2) Explain why RETEST differs from ATTACK: the request is the same; only the server-owned profile changed. (3) Find a run in Splunk Search with the starter search on the launch card and say what the events show and what they cannot (Splunk enforced nothing).
- **Expected security outcomes:** BASELINE: testbed.mode=BASELINE, profile=defended, IDENTITY OBSERVE, MCP ALLOW tool_granted, lookup_policy 1, lookup_customer_tier 0. ATTACK (intentionally vulnerable): INTENTIONALLY VULNERABLE LAB PROFILE: CTRL-IDENTITY-001 OBSERVE identity_claim_is_not_grant / untrusted_claim; overlay vulnerable_profile_fail_open:caller_identity_derived_authority;… RETEST (defended): IDENTITY OBSERVE identity_claim_is_not_grant; MCP DENY tool_not_granted; lookup_customer_tier handler 0; testbed.mode=RETEST.
- **Defensive lesson:** SAME PRINCIPAL. SAME CALLER. SAME CALLEE. SAME DELEGATION CLAIM. SAME PRIVILEGED REQUEST. DIFFERENT AUTHORIZATION. DIFFERENT EXECUTION.
- **Splunk evidence:** one set of events per run id in `index=agentsec_telemetry sourcetype=otel:agentic:json`, read in the Academy's Investigate notebook (the starter search on the launch card is the optional Splunk Web equivalent; `agentsec.run.id`); optional advanced dashboard `ws_lab_a2a_auth_delegation`; optional hunt search `Q-AGENT-DELEGATION-AUTHORITY`, `catalog`.
- **Completion:** Answer the 10 knowledge-check questions for this workshop. Knowledge check: see the workshop's `knowledge-check.md`.
- **Reset:** nothing to reset on the server: every launch creates a new run id, and earlier runs stay in Splunk. Your predictions and progress live in this browser only (clear the site data for the Academy to start over).
- **Documentation:** [README](../learning/level_1/LAB-AGENT-DELEGATION-001/README.md) · [knowledge check](../learning/level_1/LAB-AGENT-DELEGATION-001/knowledge-check.md) · [Academy explainer](../learning/academy/explainers/LAB-AGENT-DELEGATION-001.json) · [Splunk dashboard source](../splunk_app/agentsec/default/data/ui/views/ws_lab_a2a_auth_delegation.xml)

### Confused Deputy
<a id="lab-mcp-006"></a>
**`LAB-MCP-006`** · level L3 · **LIVE** · Academy page `/learn/lab/LAB-MCP-006`

- **Objectives:** Name the caller, the deputy, and the requested operation from indexed evidence.; Separate delegated authority from ambient deputy authority.; Name INV-001 as the MCP-006 invariant.; Explain why ATTACK CTRL-DELEGATION-001 ALLOW is fail-open, not caller grant.
- **Prerequisites:** a running lab (`./agentsec status` all OK); L2 LIVE (RAG and Memory).
- **How to start:** open the workshop, read **Learn**, make your prediction on **Practice**, then use the launch card to run **BASELINE**, **ATTACK** and **RETEST** (the launch needs the `operator` role through the gateway).
- **What you do:** (1) Write your prediction before you press ATTACK, then run BASELINE, ATTACK and RETEST from the lab page: you should hold three different run ids. (2) Explain why RETEST differs from ATTACK: the request is the same; only the server-owned profile changed. (3) Find a run in Splunk Search with the starter search on the launch card and say what the events show and what they cannot (Splunk enforced nothing).
- **Expected security outcomes:** BASELINE: testbed.mode=BASELINE, profile=defended, authority source delegated, ALLOW delegation_granted, policy handler 1, customer-tier handler 0. ATTACK (intentionally vulnerable): INTENTIONALLY VULNERABLE LAB PROFILE: ALLOW vulnerable_profile_fail_open:ambient_deputy_authority with authority source ambient_deputy and customer-tier handler 1. ALLOW is not execution by… RETEST (defended): DENY delegated_authority_not_granted, handler 0; testbed.mode=RETEST.
- **Defensive lesson:** Same request plus different server-owned configuration gives a different outcome. Not universal resistance.
- **Splunk evidence:** one set of events per run id in `index=agentsec_telemetry sourcetype=otel:agentic:json`, read in the Academy's Investigate notebook (the starter search on the launch card is the optional Splunk Web equivalent; `agentsec.run.id`); optional advanced dashboard `ws_lab_mcp_006`; optional hunt search `Q-MCP-DELEGATION`, `catalog`.
- **Completion:** Answer the 12 knowledge-check questions for this workshop. Knowledge check: see the workshop's `knowledge-check.md`.
- **Reset:** nothing to reset on the server: every launch creates a new run id, and earlier runs stay in Splunk. Your predictions and progress live in this browser only (clear the site data for the Academy to start over).
- **Documentation:** [README](../learning/level_1/LAB-MCP-006/README.md) · [workshop guide](../learning/level_1/LAB-MCP-006/workshop.md) · [knowledge check](../learning/level_1/LAB-MCP-006/knowledge-check.md) · [Academy explainer](../learning/academy/explainers/LAB-MCP-006.json) · [Splunk dashboard source](../splunk_app/agentsec/default/data/ui/views/ws_lab_mcp_006.xml)

## L5. Integrated purple team

*Prerequisites for this level:* L1-L3 LIVE. REPLAY grant and INV-002 workshops recommended. *Typical effort:* 2.5-4 hours

### Lending Assistant Investigation
<a id="lab-agentsec-capstone-001"></a>
**`LAB-AGENTSEC-CAPSTONE-001`** · level L5 · **LIVE** · Academy page `/learn/lab/LAB-AGENTSEC-CAPSTONE-001`

- **Objectives:** A lending assistant read a policy document, saved what it read to memory, and on a later run recalled it and used a customer-tier tool. The lab asks you to work out from the evidence where authority actually came from. Retrieved content and memory only influence; the tool authorization control is…
- **Prerequisites:** a running lab (`./agentsec status` all OK); L1-L3 LIVE. REPLAY grant and INV-002 workshops recommended.
- **How to start:** open the workshop, read **Learn**, make your prediction on **Practice**, then use the launch card to run **BASELINE**, **ATTACK** and **RETEST** (the launch needs the `operator` role through the gateway).
- **What you do:** (1) Write your prediction before you press ATTACK, then run BASELINE, ATTACK and RETEST from the lab page: you should hold three different run ids. (2) Explain why RETEST differs from ATTACK: the request is the same; only the server-owned profile changed. (3) Find a run in Splunk Search with the starter search on the launch card and say what the events show and what they cannot (Splunk enforced nothing).
- **Expected security outcomes:** BASELINE: testbed.mode=BASELINE, profile=defended, RAG OBSERVE, MEMORY OBSERVE, no privileged follow-on, handler 0. ATTACK (intentionally vulnerable): INTENTIONALLY VULNERABLE LAB PROFILE: retrieve CTRL-RAG-CONTEXT-001 OBSERVE; WRITE persists untrusted_data; RECALL CTRL-MEMORY-CONTEXT-001 OBSERVE; follow-on ALLOW… RETEST (defended): RAG OBSERVE; MEMORY OBSERVE memory_context_is_data; follow-on DENY tool_not_granted; handler_invoke_count=0; no mcp.started on a complete copy; testbed.mode=RETEST.
- **Defensive lesson:** SAME ADVERSARIAL INFLUENCE. DIFFERENT AUTHORIZATION. DIFFERENT EXECUTION. Not universal RAG/memory resistance.
- **Splunk evidence:** one set of events per run id in `index=agentsec_telemetry sourcetype=otel:agentic:json`, read in the Academy's Investigate notebook (the starter search on the launch card is the optional Splunk Web equivalent; `agentsec.run.id`); optional advanced dashboard `ws_lab_agentsec_capstone`; optional hunt search `catalog`.
- **Completion:** Answer the 10 knowledge-check questions for this workshop. Knowledge check: see the workshop's `knowledge-check.md`.
- **Reset:** nothing to reset on the server: every launch creates a new run id, and earlier runs stay in Splunk. Your predictions and progress live in this browser only (clear the site data for the Academy to start over).
- **Documentation:** [README](../learning/level_1/LAB-AGENTSEC-CAPSTONE-001/README.md) · [workshop guide](../learning/level_1/LAB-AGENTSEC-CAPSTONE-001/workshop.md) · [knowledge check](../learning/level_1/LAB-AGENTSEC-CAPSTONE-001/knowledge-check.md) · [Academy explainer](../learning/academy/explainers/LAB-AGENTSEC-CAPSTONE-001.json) · [Splunk dashboard source](../splunk_app/agentsec/default/data/ui/views/ws_lab_agentsec_capstone.xml)

### Splunk Defender Bridge
<a id="lab-splunk-defender-bridge"></a>
**`LAB-SPLUNK-DEFENDER-BRIDGE`** · level L5 · **RECORDED (replayed evidence)** · Academy page `/learn/lab/LAB-SPLUNK-DEFENDER-BRIDGE`

- **Objectives:** A good investigation starts from a question, not a run id. This checkpoint replays the lab's ten shipped searches as they were recorded from Splunk, and asks you to discover, narrow, sequence, compare and check duplicates, while keeping track of which results can be traced to committed runs.
- **Prerequisites:** none beyond the Academy: L1-L3 LIVE. REPLAY grant and INV-002 workshops recommended.
- **How to start:** open the workshop, read **Learn**, choose your prediction on **Practice**, then reveal the recorded or simulated evidence. Nothing is launched.
- **What you do:** (1) Work through discover, narrow, sequence, compare and duplicates in order. (2) For two results, say whether they can be traced to a committed run and how you know.
- **Expected security outcomes:** The ten shipped searches replay as recorded: discover, narrow, sequence, compare, check duplicates. Some results trace to committed runs; the page marks which.
- **Defensive lesson:** A search result is evidence about the indexed copy; it enforces nothing and a missing row is not a DENY.
- **Splunk evidence:** committed recorded runs, loaded into Splunk at start (search with `earliest=0`); optional advanced dashboard `ws_lab_splunk_defender_bridge`; optional hunt search `Q-BRIDGE-COMPARE-EXECUTION`, `Q-BRIDGE-COMPARE`.
- **Completion:** For two results, say whether they can be traced to a committed run and how you know.
- **Reset:** nothing to reset on the server and nothing was launched. Your predictions and progress live in this browser only (clear the site data for the Academy to start over).
- **Documentation:** [Academy explainer](../learning/academy/explainers/LAB-SPLUNK-DEFENDER-BRIDGE.json) · [Splunk dashboard source](../splunk_app/agentsec/default/data/ui/views/ws_lab_splunk_defender_bridge.xml)

## L6. Blue-team investigation and threat hunting

*Prerequisites for this level:* L5 Capstone and the Splunk Defender Bridge. Complete the incident without using Path B first. *Typical effort:* REPLAY 2.5-4 hours

### AcmeBank Incident AI-2026-001
<a id="lab-blue-team-incident-001"></a>
**`LAB-BLUE-TEAM-INCIDENT-001`** · level L6 · **RECORDED (replayed evidence)** · Academy page `/learn/lab/LAB-BLUE-TEAM-INCIDENT-001`

- **Objectives:** You are the analyst. A report says an AI-assisted banking workflow may have acted outside its authority. This investigation uses recorded runs: a three-step chain (retrieve, write, recall) in an attack run and a defended retest. You work out what the evidence supports, what it refutes and what it…
- **Prerequisites:** none beyond the Academy: L5 Capstone and the Splunk Defender Bridge. Complete the incident without using Path B first.
- **How to start:** open the workshop, read **Learn**, choose your prediction on **Practice**, then reveal the recorded or simulated evidence. Nothing is launched.
- **What you do:** (1) Produce a timeline of the chain with the run ids and the decision at each step. (2) Fill the incident report template: supported, refuted, open. (3) Answer the 12 knowledge-check questions for this workshop.
- **Expected security outcomes:** The recorded attack run is a three-step chain (retrieve, write, recall) and a defended retest is recorded beside it. Your timeline separates what the evidence supports, what it refutes and what it leaves open.
- **Defensive lesson:** Write NOT PROVEN where the evidence stops; a missing event is not proof of absence.
- **Splunk evidence:** committed recorded runs, loaded into Splunk at start (search with `earliest=0`); optional advanced dashboard `ws_lab_blue_team_incident`; optional hunt search `Q-INCIDENT-CANDIDATES`, `Q-INCIDENT-COMPARE`.
- **Completion:** Answer the 12 knowledge-check questions for this workshop. Knowledge check: see the workshop's `knowledge-check.md`.
- **Reset:** nothing to reset on the server and nothing was launched. Your predictions and progress live in this browser only (clear the site data for the Academy to start over).
- **Documentation:** [README](../learning/level_1/LAB-BLUE-TEAM-INCIDENT-001/README.md) · [workshop guide](../learning/level_1/LAB-BLUE-TEAM-INCIDENT-001/workshop.md) · [knowledge check](../learning/level_1/LAB-BLUE-TEAM-INCIDENT-001/knowledge-check.md) · [Academy explainer](../learning/academy/explainers/LAB-BLUE-TEAM-INCIDENT-001.json) · [Splunk dashboard source](../splunk_app/agentsec/default/data/ui/views/ws_lab_blue_team_incident.xml)

### Detection Engineering — Prove Your Coverage
<a id="lab-detection-engineering"></a>
**`LAB-DETECTION-ENGINEERING`** · level L6 · **RECORDED (replayed evidence)** · Academy page `/learn/lab/LAB-DETECTION-ENGINEERING`

- **Objectives:** Not every suspicious behavior should become an alert. This checkpoint replays three recorded searches, event counts, a broad rule and a tuned rule, and asks what each one shows, and what a zero-row result does and does not mean.
- **Prerequisites:** none beyond the Academy: L5 Capstone and the Splunk Defender Bridge. Complete the incident without using Path B first.
- **How to start:** open the workshop, read **Learn**, choose your prediction on **Practice**, then reveal the recorded or simulated evidence. Nothing is launched.
- **What you do:** (1) Say what each of the three searches shows and what a zero-row result does and does not mean. (2) Explain why the tuned rule is preferable to the broad one, using the recorded counts.
- **Expected security outcomes:** Three recorded searches, their event counts, a broad rule and a tuned rule are replayed. A zero-row result is shown as a result, not as an answer.
- **Defensive lesson:** Zero rows is not safety: it can mean no event, no ingestion or a rule that cannot see the field.
- **Splunk evidence:** committed recorded runs, loaded into Splunk at start (search with `earliest=0`); optional advanced dashboard `ws_lab_detection_engineering`; optional hunt search `Q-DET-BROAD`, `Q-DET-EVENTS`.
- **Completion:** Explain why the tuned rule is preferable to the broad one, using the recorded counts.
- **Reset:** nothing to reset on the server and nothing was launched. Your predictions and progress live in this browser only (clear the site data for the Academy to start over).
- **Documentation:** [Academy explainer](../learning/academy/explainers/LAB-DETECTION-ENGINEERING.json) · [Splunk dashboard source](../splunk_app/agentsec/default/data/ui/views/ws_lab_detection_engineering.xml)

## L7. Threat modeling and security architecture

*Prerequisites for this level:* L6 Blue-Team Investigation, then the Detection Engineering workshop. Draft before opening Path B. *Typical effort:* REPLAY / ARCHITECTURE 3-5 hours

### AcmeBank Agentic Customer Operations Platform
<a id="lab-threat-modeling-001"></a>
**`LAB-THREAT-MODELING-001`** · level L7 · **SIMULATED packet (guided analysis; the MAESTRO workbench runs only in your browser and launches nothing)** · Academy page `/learn/lab/LAB-THREAT-MODELING-001`

- **Objectives:** A threat model starts with what you are protecting and where trust changes, not with a list of attacks. This checkpoint reads the lab's committed architecture and threat catalog and asks you to find the assets, boundaries, threats, controls and residual risks in them.
- **Prerequisites:** none beyond the Academy: L6 Blue-Team Investigation, then the Detection Engineering workshop. Draft before opening Path B. (the MAESTRO workbench needs no running AcmeBank, model or Splunk)
- **How to start:** open the workshop, then the **Practice** tab and the MAESTRO workbench (see [Learner guide, section 9](LEARNER_GUIDE.md#9-csa-maestro-seven-layer-threat-modeling)). Work from scope to report; **Load the worked example** to compare; **Download report (Markdown)** and **Download model (JSON)** when done. CSA's MAESTRO Threat Analyzer is not run and MAESTRO v2 is not implemented.
- **What you do:** (1) Complete the MAESTRO workbench in Practice: decompose, mark boundaries, record threats on every layer, chain two cross-layer paths, judge inherent and residual risk with mitigations, and link scenarios from… (2) Press Check my model: the structure criteria R1 to R5 and R7 are MET. The check cannot judge your reasoning and is not a certification. (3) Download your report and compare your register with the worked example, then with the official MAESTRO Threat Analyzer if you run it yourself (this lab does not run it).
- **Expected security outcomes:** Every AcmeBank element sits on one of the seven MAESTRO layers, and the trust boundaries between layers are named. Each layer has at least one threat, taken from the CSA article's list for that layer or marked custom with a reason (Layer 6's list is about AI security agents, which AcmeBank does not have). At least two cross-layer attack paths chain threats across three or more layers, and your register ranks risks by inherent then residual level.
- **Defensive lesson:** Say how you know: DEMONSTRATED means a lab shows it for its own fixtures, DOCUMENTED means a file says it, ASSUMED means no evidence. A residual rating is a judgment, not a measurement.
- **Splunk evidence:** none sent by this exercise (a committed simulated packet); optional advanced dashboard `ws_lab_threat_modeling`.
- **Completion:** Answer the 22 knowledge-check questions for this workshop. Knowledge check: see the workshop's `knowledge-check.md`.
- **Reset:** press **Clear my draft** in the MAESTRO workbench; the draft lives in this browser only.
- **Documentation:** [README](../learning/level_1/LAB-THREAT-MODELING-001/README.md) · [knowledge check](../learning/level_1/LAB-THREAT-MODELING-001/knowledge-check.md) · [Academy explainer](../learning/academy/explainers/LAB-THREAT-MODELING-001.json) · [Splunk dashboard source](../splunk_app/agentsec/default/data/ui/views/ws_lab_threat_modeling.xml)

### Agent Identity and Non-Human IAM
<a id="lab-agent-identity-nhi"></a>
**`LAB-AGENT-IDENTITY-NHI`** · level L7 · **RECORDED (replayed evidence)** · Academy page `/learn/lab/LAB-AGENT-IDENTITY-NHI`

- **Objectives:** An agent's identity claim is a label, not a grant. This checkpoint reads what the lab's three shipped searches recorded about claims, control decisions and handler starts, and keeps three kinds of evidence apart: committed packs, the current Splunk observation and the September documentation.
- **Prerequisites:** none beyond the Academy: L6 Blue-Team Investigation, then the Detection Engineering workshop. Draft before opening Path B.
- **How to start:** open the workshop, read **Learn**, choose your prediction on **Practice**, then reveal the recorded or simulated evidence. Nothing is launched.
- **What you do:** (1) For each of the three searches, say what it shows and what it cannot show. (2) Say which of the three evidence kinds each claim in your notes rests on.
- **Expected security outcomes:** The three shipped searches return what was recorded about claims, control decisions and handler starts. An identity claim appears as a label; the control observes it and the tool decision is separate.
- **Defensive lesson:** Keep three kinds of evidence apart: committed packs, the current Splunk observation and the September documentation.
- **Splunk evidence:** committed recorded runs, loaded into Splunk at start (search with `earliest=0`); optional advanced dashboard `ws_lab_agent_identity_nhi`; optional hunt search `Q-ID-CONTROLS`, `Q-ID-MODES`.
- **Completion:** Say which of the three evidence kinds each claim in your notes rests on.
- **Reset:** nothing to reset on the server and nothing was launched. Your predictions and progress live in this browser only (clear the site data for the Academy to start over).
- **Documentation:** [Academy explainer](../learning/academy/explainers/LAB-AGENT-IDENTITY-NHI.json) · [Splunk dashboard source](../splunk_app/agentsec/default/data/ui/views/ws_lab_agent_identity_nhi.xml)

### A2A Authentication and Delegation
<a id="lab-a2a-auth-delegation"></a>
**`LAB-A2A-AUTH-DELEGATION`** · level L7 · **SIMULATED packet (guided analysis)** · Academy page `/learn/lab/LAB-A2A-AUTH-DELEGATION`

- **Objectives:** Two agents are named in a request. Being authenticated does not mean the request is authorized. This checkpoint walks three simulated cases through authentication, a bounded delegation and the tool control, and asks you to decide each one before the packet shows its record.
- **Prerequisites:** none beyond the Academy: L6 Blue-Team Investigation, then the Detection Engineering workshop. Draft before opening Path B.
- **How to start:** open the workshop, read **Learn**, choose your prediction on **Practice**, then reveal the recorded or simulated evidence. Nothing is launched.
- **What you do:** (1) Read the packet's BASELINE, ATTACK and RETEST cases and say, for each, what the control decided and why. (2) State what the evidence cannot prove (the packet's own 'not proven' fields) before you state what it shows.
- **Expected security outcomes:** BASELINE: ALLOW tool_granted, and a separate simulated mcp.started. ATTACK: ALLOW with vulnerable_profile_fail_open:caller_identity_derived_authority, a teaching fault, with execution. RETEST: DENY tool_not_granted, and no execution to infer.
- **Defensive lesson:** Authenticating an agent (here simulated) answers who is calling; it never answers what it may do.
- **Splunk evidence:** none sent by this exercise (a committed simulated packet); optional advanced dashboard `ws_lab_a2a_auth_delegation`; optional hunt search `Q-AUTH-DELEGATION-HISTORICAL`.
- **Completion:** State what the evidence cannot prove (the packet's own 'not proven' fields) before you state what it shows.
- **Reset:** nothing to reset on the server and nothing was launched. Your predictions and progress live in this browser only (clear the site data for the Academy to start over).
- **Documentation:** [Academy explainer](../learning/academy/explainers/LAB-A2A-AUTH-DELEGATION.json) · [Splunk dashboard source](../splunk_app/agentsec/default/data/ui/views/ws_lab_a2a_auth_delegation.xml)

### Human Approval and Action Binding
<a id="lab-hitl-approval"></a>
**`LAB-HITL-APPROVAL`** · level L7 · **SIMULATED packet (guided analysis)** · Academy page `/learn/lab/LAB-HITL-APPROVAL`

- **Objectives:** An approval exists for one action. A second action arrives inside the approval's window. This checkpoint asks whether the approval still covers what was actually submitted, using three simulated cases.
- **Prerequisites:** none beyond the Academy: L6 Blue-Team Investigation, then the Detection Engineering workshop. Draft before opening Path B.
- **How to start:** open the workshop, read **Learn**, choose your prediction on **Practice**, then reveal the recorded or simulated evidence. Nothing is launched.
- **What you do:** (1) Read the packet's BASELINE, ATTACK and RETEST cases and say, for each, what the control decided and why. (2) State what the evidence cannot prove (the packet's own 'not proven' fields) before you state what it shows. (3) Explain why an approval inside its window can still be the wrong approval.
- **Expected security outcomes:** BASELINE: the submitted tool, resource and action reference match the approval (binding MATCH): ALLOW tool_granted. ATTACK: the approval is inside its time window but the action is a different resource (executive-restricted); binding MISMATCH, yet ALLOW vulnerable_profile_fail_open:stale_approval_accepted. RETEST: the same mismatched action is DENY approval_binding_mismatch and nothing executes.
- **Defensive lesson:** The approval authority here is NOT PROVEN: the packet never shows who approved, only a simulated record.
- **Splunk evidence:** none sent by this exercise (a committed simulated packet); optional advanced dashboard `ws_lab_hitl_approval`; optional hunt search `Q-APPROVAL-CONTRAST`.
- **Completion:** Explain why an approval inside its window can still be the wrong approval.
- **Reset:** nothing to reset on the server and nothing was launched. Your predictions and progress live in this browser only (clear the site data for the Academy to start over).
- **Documentation:** [Academy explainer](../learning/academy/explainers/LAB-HITL-APPROVAL.json) · [Splunk dashboard source](../splunk_app/agentsec/default/data/ui/views/ws_lab_hitl_approval.xml)

### Short-Lived Credential Lifetime
<a id="lab-credential-lifetime"></a>
**`LAB-CREDENTIAL-LIFETIME`** · level L7 · **SIMULATED packet (guided analysis)** · Academy page `/learn/lab/LAB-CREDENTIAL-LIFETIME`

- **Objectives:** A credential has a lifetime, and a request arrives carrying one. Does the credential's lifetime decide the tool, or does the tool control? This checkpoint works through three simulated cases and separates the credential's clock from the approval's clock.
- **Prerequisites:** none beyond the Academy: L6 Blue-Team Investigation, then the Detection Engineering workshop. Draft before opening Path B.
- **How to start:** open the workshop, read **Learn**, choose your prediction on **Practice**, then reveal the recorded or simulated evidence. Nothing is launched.
- **What you do:** (1) Read the packet's BASELINE, ATTACK and RETEST cases and say, for each, what the control decided and why. (2) State what the evidence cannot prove (the packet's own 'not proven' fields) before you state what it shows. (3) Say which clock the packet's approval uses and why it is not the credential clock.
- **Expected security outcomes:** BASELINE: a current credential: ALLOW tool_granted. ATTACK: an expired credential is accepted by a teaching fault: ALLOW vulnerable_profile_fail_open:expired_credential_accepted. RETEST: DENY expired_credential and no execution to infer.
- **Defensive lesson:** A credential that was valid when issued is not valid forever: lifetime is part of authorization.
- **Splunk evidence:** none sent by this exercise (a committed simulated packet); optional advanced dashboard `ws_lab_credential_lifetime`; optional hunt search `Q-CREDENTIAL-ABSENCE`.
- **Completion:** Say which clock the packet's approval uses and why it is not the credential clock.
- **Reset:** nothing to reset on the server and nothing was launched. Your predictions and progress live in this browser only (clear the site data for the Academy to start over).
- **Documentation:** [Academy explainer](../learning/academy/explainers/LAB-CREDENTIAL-LIFETIME.json) · [Splunk dashboard source](../splunk_app/agentsec/default/data/ui/views/ws_lab_credential_lifetime.xml)

## L8. Privacy, data protection and agentic data governance

*Prerequisites for this level:* L7 Threat Modeling & Security Architecture, then the Agent Identity and Non-Human IAM workshop, then the A2A Authentication and Delegation workshop, then the Human Approval workshop, then the Credential Lifetime workshop. Investigate before opening Path B. *Typical effort:* REPLAY / PRIVACY INVESTIGATION 3-5 hours

### AcmeBank Incident PRIV-2026-001
<a id="lab-privacy-data-governance-001"></a>
**`LAB-PRIVACY-DATA-GOVERNANCE-001`** · level L8 · **SIMULATED packet (guided analysis)** · Academy page `/learn/lab/LAB-PRIVACY-DATA-GOVERNANCE-001`

- **Objectives:** Authorizing a tool call is not the same as authorizing the data it receives. This checkpoint compares the lab's full synthetic record with its minimized record and asks you to separate what the task needed, what the control decided and what stays unproven.
- **Prerequisites:** none beyond the Academy: L7 Threat Modeling & Security Architecture, then the Agent Identity and Non-Human IAM workshop, then the A2A Authentication and Delegation workshop, then the Human Approval workshop, then the Credential Lifetime workshop. Investigate before opening Path B.
- **How to start:** open the workshop, read **Learn**, choose your prediction on **Practice**, then reveal the recorded or simulated evidence. Nothing is launched.
- **What you do:** (1) List the fields the task needed and the fields it did not. (2) State what remains unproven about the minimized record. (3) Answer the 15 knowledge-check questions for this workshop.
- **Expected security outcomes:** The full synthetic record and the minimized record are compared field by field. You can say what the task needed, what the control decided and what stays unproven.
- **Defensive lesson:** All data here is synthetic; the exercise says nothing about a real privacy program.
- **Splunk evidence:** none sent by this exercise (a committed simulated packet); optional advanced dashboard `ws_lab_privacy_data_governance`; optional hunt search `Q-PRIVACY-CANDIDATES`, `Q-PRIVACY-COMPARE`.
- **Completion:** Answer the 15 knowledge-check questions for this workshop. Knowledge check: see the workshop's `knowledge-check.md`.
- **Reset:** nothing to reset on the server and nothing was launched. Your predictions and progress live in this browser only (clear the site data for the Academy to start over).
- **Documentation:** [README](../learning/level_1/LAB-PRIVACY-DATA-GOVERNANCE-001/README.md) · [knowledge check](../learning/level_1/LAB-PRIVACY-DATA-GOVERNANCE-001/knowledge-check.md) · [Academy explainer](../learning/academy/explainers/LAB-PRIVACY-DATA-GOVERNANCE-001.json) · [Splunk dashboard source](../splunk_app/agentsec/default/data/ui/views/ws_lab_privacy_data_governance.xml)

### RAG Purpose Authorization
<a id="lab-rag-purpose"></a>
**`LAB-RAG-PURPOSE`** · level L8 · **SIMULATED packet (guided analysis)** · Academy page `/learn/lab/LAB-RAG-PURPOSE`

- **Objectives:** A document can be retrieved and still be unauthorized for the purpose in front of you. This checkpoint takes one retrieved object through three simulated purposes and asks whether each use is allowed.
- **Prerequisites:** none beyond the Academy: L7 Threat Modeling & Security Architecture, then the Agent Identity and Non-Human IAM workshop, then the A2A Authentication and Delegation workshop, then the Human Approval workshop, then the Credential Lifetime workshop. Investigate before opening Path B.
- **How to start:** open the workshop, read **Learn**, choose your prediction on **Practice**, then reveal the recorded or simulated evidence. Nothing is launched.
- **What you do:** (1) Read the packet's BASELINE, ATTACK and RETEST cases and say, for each, what the control decided and why. (2) State what the evidence cannot prove (the packet's own 'not proven' fields) before you state what it shows. (3) Explain why vector similarity cannot stand in for a purpose check.
- **Expected security outcomes:** BASELINE: purpose allowed (applicant-education): ALLOW purpose_allowed. ATTACK: the purpose is not checked and the retrieval goes through: FAIL_OPEN vulnerable_profile_fail_open:purpose_not_checked. RETEST: DENY purpose_not_allowed.
- **Defensive lesson:** A retrieval decision is not a tool decision: CTRL-MCP-001 is not invoked by retrieval.
- **Splunk evidence:** none sent by this exercise (a committed simulated packet); optional advanced dashboard `ws_lab_purpose_authorization`; optional hunt search `Q-PURPOSE-CONTRAST`.
- **Completion:** Explain why vector similarity cannot stand in for a purpose check.
- **Reset:** nothing to reset on the server and nothing was launched. Your predictions and progress live in this browser only (clear the site data for the Academy to start over).
- **Documentation:** [Academy explainer](../learning/academy/explainers/LAB-RAG-PURPOSE.json) · [Splunk dashboard source](../splunk_app/agentsec/default/data/ui/views/ws_lab_purpose_authorization.xml)

### Memory Ownership and Isolation
<a id="lab-recall-isolation"></a>
**`LAB-RECALL-ISOLATION`** · level L8 · **SIMULATED packet (guided analysis)** · Academy page `/learn/lab/LAB-RECALL-ISOLATION`

- **Objectives:** A memory is written by one agent for one user. This checkpoint asks what happens when a different user tries to recall it, using three simulated cases, and keeps deletion and retention clearly unmeasured.
- **Prerequisites:** none beyond the Academy: L7 Threat Modeling & Security Architecture, then the Agent Identity and Non-Human IAM workshop, then the A2A Authentication and Delegation workshop, then the Human Approval workshop, then the Credential Lifetime workshop. Investigate before opening Path B.
- **How to start:** open the workshop, read **Learn**, choose your prediction on **Practice**, then reveal the recorded or simulated evidence. Nothing is launched.
- **What you do:** (1) Read the packet's BASELINE, ATTACK and RETEST cases and say, for each, what the control decided and why. (2) State what the evidence cannot prove (the packet's own 'not proven' fields) before you state what it shows. (3) Say what the packet does not measure about deletion and retention.
- **Expected security outcomes:** BASELINE: the owner recalls their own memory: owner_recall. ATTACK: another user recalls it: vulnerable_profile_fail_open:cross_user_recall. RETEST: the cross-user recall is refused: cross_user_recall_denied.
- **Defensive lesson:** Deletion and retention are NOT MEASURED in this packet; do not infer either from the recall result.
- **Splunk evidence:** none sent by this exercise (a committed simulated packet); optional advanced dashboard `ws_lab_recall_isolation`; optional hunt search `Q-RECALL-CONTRAST`.
- **Completion:** Say what the packet does not measure about deletion and retention.
- **Reset:** nothing to reset on the server and nothing was launched. Your predictions and progress live in this browser only (clear the site data for the Academy to start over).
- **Documentation:** [Academy explainer](../learning/academy/explainers/LAB-RECALL-ISOLATION.json) · [Splunk dashboard source](../splunk_app/agentsec/default/data/ui/views/ws_lab_recall_isolation.xml)

### AI Asset Inventory
<a id="lab-asset-inventory"></a>
**`LAB-ASSET-INVENTORY`** · level L8 · **SIMULATED packet (guided analysis)** · Academy page `/learn/lab/LAB-ASSET-INVENTORY`

- **Objectives:** You cannot govern what you cannot inventory, and an inventory is not trust. This checkpoint reads the documented component list and asks what the list does and does not record.
- **Prerequisites:** none beyond the Academy: L7 Threat Modeling & Security Architecture, then the Agent Identity and Non-Human IAM workshop, then the A2A Authentication and Delegation workshop, then the Human Approval workshop, then the Credential Lifetime workshop. Investigate before opening Path B.
- **How to start:** open the workshop, read **Learn**, choose your prediction on **Practice**, then reveal the recorded or simulated evidence. Nothing is launched.
- **What you do:** (1) Pick three components and say where each is named and what the inventory does not say about it. (2) Explain the difference between inventory and authorization.
- **Expected security outcomes:** The packet lists the repository's components with the files that name them, bounded to repository files. Cisco AI BOM compatibility is NOT CLAIMED: the packet does not run that CLI.
- **Defensive lesson:** Presence of a component in the list says nothing about whether it is safe to grant.
- **Splunk evidence:** none sent by this exercise (a committed simulated packet); optional advanced dashboard `ws_lab_asset_inventory`.
- **Completion:** Explain the difference between inventory and authorization.
- **Reset:** nothing to reset on the server and nothing was launched. Your predictions and progress live in this browser only (clear the site data for the Academy to start over).
- **Documentation:** [Academy explainer](../learning/academy/explainers/LAB-ASSET-INVENTORY.json) · [Splunk dashboard source](../splunk_app/agentsec/default/data/ui/views/ws_lab_asset_inventory.xml)

### Component Provenance
<a id="lab-component-provenance"></a>
**`LAB-COMPONENT-PROVENANCE`** · level L8 · **SIMULATED packet (guided analysis)** · Academy page `/learn/lab/LAB-COMPONENT-PROVENANCE`

- **Objectives:** A known component is not a trusted component. This checkpoint presents a privileged tool request beside an unpinned and a pinned component, in three simulated cases, and asks whether provenance changes the decision.
- **Prerequisites:** none beyond the Academy: L7 Threat Modeling & Security Architecture, then the Agent Identity and Non-Human IAM workshop, then the A2A Authentication and Delegation workshop, then the Human Approval workshop, then the Credential Lifetime workshop. Investigate before opening Path B.
- **How to start:** open the workshop, read **Learn**, choose your prediction on **Practice**, then reveal the recorded or simulated evidence. Nothing is launched.
- **What you do:** (1) Read the packet's BASELINE, ATTACK and RETEST cases and say, for each, what the control decided and why. (2) State what the evidence cannot prove (the packet's own 'not proven' fields) before you state what it shows. (3) Name one component in the packet that is pinned and one that is not, and why the difference matters.
- **Expected security outcomes:** BASELINE: ALLOW tool_granted. ATTACK: ALLOW vulnerable_profile_fail_open:known_component_treated_as_grant. RETEST: DENY provenance_is_not_a_grant. The Ollama image pin is NOT RESOLVED: docker-compose.yml still says ollama/ollama:latest and no digest was measured.
- **Defensive lesson:** A scanner finding is not authorization and an evaluation pass is not safety; pin what you can measure and say what you could not.
- **Splunk evidence:** none sent by this exercise (a committed simulated packet); optional advanced dashboard `ws_lab_component_provenance`.
- **Completion:** Name one component in the packet that is pinned and one that is not, and why the difference matters.
- **Reset:** nothing to reset on the server and nothing was launched. Your predictions and progress live in this browser only (clear the site data for the Academy to start over).
- **Documentation:** [Academy explainer](../learning/academy/explainers/LAB-COMPONENT-PROVENANCE.json) · [Splunk dashboard source](../splunk_app/agentsec/default/data/ui/views/ws_lab_component_provenance.xml)

### Code Agent Bounds
<a id="lab-code-agent-bounds"></a>
**`LAB-CODE-AGENT-BOUNDS`** · level L8 · **SIMULATED packet (guided analysis)** · Academy page `/learn/lab/LAB-CODE-AGENT-BOUNDS`

- **Objectives:** A code-generation agent was delegated and approved to read a repository. This checkpoint looks at what happens when it submits a different operation, using three simulated cases and no real repository.
- **Prerequisites:** none beyond the Academy: L7 Threat Modeling & Security Architecture, then the Agent Identity and Non-Human IAM workshop, then the A2A Authentication and Delegation workshop, then the Human Approval workshop, then the Credential Lifetime workshop. Investigate before opening Path B.
- **How to start:** open the workshop, read **Learn**, choose your prediction on **Practice**, then reveal the recorded or simulated evidence. Nothing is launched.
- **What you do:** (1) Read the packet's BASELINE, ATTACK and RETEST cases and say, for each, what the control decided and why. (2) State what the evidence cannot prove (the packet's own 'not proven' fields) before you state what it shows. (3) Explain why a CURRENT credential does not make install_dependency allowed.
- **Expected security outcomes:** BASELINE: read_repository matches the grant: ALLOW tool_granted. ATTACK: install_dependency is not granted but is let through by a teaching fault: ALLOW vulnerable_profile_fail_open:code_agent_scope_not_checked. RETEST: DENY operation_not_granted; nothing executes.
- **Defensive lesson:** A current credential and a valid delegation still do not authorize an operation outside the grant.
- **Splunk evidence:** none sent by this exercise (a committed simulated packet); optional advanced dashboard `ws_lab_code_agent_bounds`.
- **Completion:** Explain why a CURRENT credential does not make install_dependency allowed.
- **Reset:** nothing to reset on the server and nothing was launched. Your predictions and progress live in this browser only (clear the site data for the Academy to start over).
- **Documentation:** [Academy explainer](../learning/academy/explainers/LAB-CODE-AGENT-BOUNDS.json) · [Splunk dashboard source](../splunk_app/agentsec/default/data/ui/views/ws_lab_code_agent_bounds.xml)

### Change Bounds
<a id="lab-change-bounds"></a>
**`LAB-CHANGE-BOUNDS`** · level L8 · **SIMULATED packet (guided analysis)** · Academy page `/learn/lab/LAB-CHANGE-BOUNDS`

- **Objectives:** An agent holds authority to inspect a resource. This checkpoint asks what happens when it submits a delete instead, and what a started action does and does not prove, using three simulated cases and no real cloud account.
- **Prerequisites:** none beyond the Academy: L7 Threat Modeling & Security Architecture, then the Agent Identity and Non-Human IAM workshop, then the A2A Authentication and Delegation workshop, then the Human Approval workshop, then the Credential Lifetime workshop. Investigate before opening Path B.
- **How to start:** open the workshop, read **Learn**, choose your prediction on **Practice**, then reveal the recorded or simulated evidence. Nothing is launched.
- **What you do:** (1) Read the packet's BASELINE, ATTACK and RETEST cases and say, for each, what the control decided and why. (2) State what the evidence cannot prove (the packet's own 'not proven' fields) before you state what it shows. (3) State the scope of the credential and the operation that was submitted, and why they differ.
- **Expected security outcomes:** BASELINE: inspect_resource matches the delegated operation: ALLOW tool_granted. ATTACK: delete_resource is submitted against an inspect-only credential and let through by a teaching fault: ALLOW vulnerable_profile_fail_open:change_scope_not_checked. RETEST: DENY change_not_granted; nothing executes.
- **Defensive lesson:** This is not a cloud account: the packet simulates the check and measures no real resource change.
- **Splunk evidence:** none sent by this exercise (a committed simulated packet); optional advanced dashboard `ws_lab_change_bounds`.
- **Completion:** State the scope of the credential and the operation that was submitted, and why they differ.
- **Reset:** nothing to reset on the server and nothing was launched. Your predictions and progress live in this browser only (clear the site data for the Academy to start over).
- **Documentation:** [Academy explainer](../learning/academy/explainers/LAB-CHANGE-BOUNDS.json) · [Splunk dashboard source](../splunk_app/agentsec/default/data/ui/views/ws_lab_change_bounds.xml)

## L9. Multi-stage agentic attack, investigation and defense

*Prerequisites for this level:* L6-L8, then the identity, A2A, approval, credential, purpose, memory, inventory, provenance, code-agent, and change-bounds workshops. Draft before opening Path B. *Typical effort:* REPLAY / INTEGRATED INCIDENT 4-6 hours

### Acme Bank Incident AGENT-2026-009
<a id="lab-multi-stage-incident-001"></a>
**`LAB-MULTI-STAGE-INCIDENT-001`** · level L9 · **RECORDED (replayed evidence)** · Academy page `/learn/lab/LAB-MULTI-STAGE-INCIDENT-001`

- **Objectives:** A longer investigation over recorded evidence: an attack chain, a defended retest, a baseline chain and a benign comparison. You separate what each evidence plane shows, name the controls that held or did not, and say what is still unproven.
- **Prerequisites:** none beyond the Academy: L6-L8, then the identity, A2A, approval, credential, purpose, memory, inventory, provenance, code-agent, and change-bounds workshops. Draft before opening Path B.
- **How to start:** open the workshop, read **Learn**, choose your prediction on **Practice**, then reveal the recorded or simulated evidence. Nothing is launched.
- **What you do:** (1) Name the controls that held and the ones that did not, with the run id for each. (2) State what is still unproven and what evidence would settle it. (3) Answer the 14 knowledge-check questions for this workshop.
- **Expected security outcomes:** An attack chain, a defended retest, a baseline chain and a benign comparison are all available as recorded evidence. You can name which control held and which did not at each stage.
- **Defensive lesson:** A held control is shown by a DENY before the handler plus handler count 0, not by silence in Splunk.
- **Splunk evidence:** committed recorded runs, loaded into Splunk at start (search with `earliest=0`); optional advanced dashboard `ws_lab_multi_stage_incident`; optional hunt search `Q-L9-COMPARE`, `Q-L9-DETECTION-CANDIDATE`.
- **Completion:** Answer the 14 knowledge-check questions for this workshop. Knowledge check: see the workshop's `knowledge-check.md`.
- **Reset:** nothing to reset on the server and nothing was launched. Your predictions and progress live in this browser only (clear the site data for the Academy to start over).
- **Documentation:** [README](../learning/level_1/LAB-MULTI-STAGE-INCIDENT-001/README.md) · [knowledge check](../learning/level_1/LAB-MULTI-STAGE-INCIDENT-001/knowledge-check.md) · [Academy explainer](../learning/academy/explainers/LAB-MULTI-STAGE-INCIDENT-001.json) · [Splunk dashboard source](../splunk_app/agentsec/default/data/ui/views/ws_lab_multi_stage_incident.xml)

## L10. Advanced capstone and mastery

*Prerequisites for this level:* L6-L9 investigation, architecture, privacy, and integrated incident reasoning. Draft before opening Path B. *Typical effort:* REPLAY / MASTERY CAPSTONE 4-6 hours

### Acme Bank Capstone MASTER-2026-001
<a id="lab-advanced-capstone-mastery-001"></a>
**`LAB-ADVANCED-CAPSTONE-MASTERY-001`** · level L10 · **RECORDED (replayed evidence)** · Academy page `/learn/lab/LAB-ADVANCED-CAPSTONE-MASTERY-001`

- **Objectives:** The mastery capstone. You get a business workflow, a time window and the recorded evidence, not a run id. Work out what you can prove, write NOT PROVEN where the evidence stops, and check yourself against the lab's own list of steps. This is self-assessed and is not a certification.
- **Prerequisites:** none beyond the Academy: L6-L9 investigation, architecture, privacy, and integrated incident reasoning. Draft before opening Path B.
- **How to start:** open the workshop, read **Learn**, choose your prediction on **Practice**, then reveal the recorded or simulated evidence. Nothing is launched.
- **What you do:** (1) Complete the self-check against the lab's own list of steps. (2) Record, for each claim, the evidence it rests on. This is self-assessed and is not a certification. (3) Answer the 7 knowledge-check questions for this workshop.
- **Expected security outcomes:** You receive a business workflow, a time window and recorded evidence, not a run id. Your answer states what you can prove and writes NOT PROVEN where the evidence stops.
- **Defensive lesson:** Do not generalise from one lab profile to production.
- **Splunk evidence:** committed recorded runs, loaded into Splunk at start (search with `earliest=0`); optional advanced dashboard `ws_lab_advanced_capstone`; optional hunt search `Q-L10-COMPARE`, `Q-L10-DETECTION-CANDIDATE`.
- **Completion:** Answer the 7 knowledge-check questions for this workshop. Knowledge check: see the workshop's `knowledge-check.md`.
- **Reset:** nothing to reset on the server and nothing was launched. Your predictions and progress live in this browser only (clear the site data for the Academy to start over).
- **Documentation:** [README](../learning/level_1/LAB-ADVANCED-CAPSTONE-MASTERY-001/README.md) · [knowledge check](../learning/level_1/LAB-ADVANCED-CAPSTONE-MASTERY-001/knowledge-check.md) · [Academy explainer](../learning/academy/explainers/LAB-ADVANCED-CAPSTONE-MASTERY-001.json) · [Splunk dashboard source](../splunk_app/agentsec/default/data/ui/views/ws_lab_advanced_capstone.xml)

