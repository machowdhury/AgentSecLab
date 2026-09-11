# Agentic Architecture 101

**Status:** PLANNED (Phase 1A architecture). There is EXPERIMENTAL runtime code under `src/agentsec/`; this note teaches the **design contract**, not a production product. Live Ollama and live Splunk are not claimed here.

---

## WHAT IS IT?

An **agentic system** is software where an LLM takes steps: read a request, maybe call a model, maybe later call tools or other agents, and produce an outcome. In AgentSec the outcome is a lab loan-style decision.

AgentSec is a **range**: a tiny bank (AcmeBank), an attack door (Attack Service), a live local model (Ollama), an evidence bus (OpenTelemetry), and a SOC workbench (Splunk).

## WHY DOES IT EXIST?

If you only chat with one model, you miss failures on **surfaces**: tools, memory, retrieved documents, agent identity, and workflow order.

If you only draw slides, you never see a control decision or a Splunk event.

AgentWatch proved the loop and also proved how the loop lies: simulated telemetry, post-inference “DENY,” and regex labeled as MCP/A2A/RAG.

AgentSec exists so you can run a normal request, run an attack, and **prove** what happened — without manufacturing the story in telemetry.

## HOW DOES IT WORK?

Four agents run **one after another in one process** (not four microservices, not A2A):

1. Intake — accept the application  
2. Credit — financial profile  
3. Risk — score  
4. Compliance — lab policy check  

Each step:

**inspect input → maybe call Ollama → record the actual outcome with the same `run.id`.**

If the input control DENYs, Ollama is **not** called.

The Attack Service only HTTP-calls AcmeBank. Splunk only reads events. Neither is a secret backdoor.

Truth flow:

USER / ATTACKER → APPLICATION → SECURITY DECISION → ACTION → ACTUAL OUTCOME → TELEMETRY → SPLUNK → EVIDENCE

## WHERE DOES IT SIT IN AGENTSEC?

This is the **core**. Workshops, detections, MLTK, Cisco, MCP, A2A, RAG, and memory sit **later**. They are extension points, not required to understand the picture.

## WHAT IS THE TRUST BOUNDARY?

The AcmeBank HTTP API (`acmebank.http_api`). Everything the browser or Attack Service sends is untrusted. Ollama’s text is also untrusted. Splunk cannot approve a loan.

Handoff between agents is still untrusted **data** inside one process.

## WHAT COULD AN ATTACKER CONTROL?

The message. In the defended lab they cannot choose `run.id`, turn controls off, or write `control.decision` into the event.

## WHAT CAN GO WRONG?

- Injection that should have been DENY **before** the model.  
- Calling post-LLM cleanup “DENY” after the model already ran.  
- Mixing SIMULATED OTel with live proof.  
- Four “trust zones” on a slide when it is still one process pasting text between prompts.  
- `run.id` missing or a new incident id per agent (AgentWatch live pipeline).  
- Fail-open with no label.

## WHAT TELEMETRY SHOULD EXIST?

Enough to reconstruct: `run.id`, profile, `testbed_mode`, control decision, control reason, whether the LLM actually ran, which agent hopped.

Exact field names are the **event model** phase, not this note. Architecture rule: telemetry matches runtime truth.

## HOW WILL SPLUNK SHOW IT?

Search by `run.id` on index `agentsec_telemetry`. Splunk explains; it does not enforce.

Validated SPL comes after real events exist. Do not assume queries work.

## WHAT CONTROL COULD CHANGE THE RESULT?

Input DENY stops Ollama. Splunk detections do not stop the call. Changing `vulnerable` → `defended` changes whether the same payload is ALLOW or DENY.

## WHAT TEST PROVES THE LOGIC?

A stubbed LLM: malicious input → DENY → **zero** stub calls. Live model wording is nondeterministic and is not that proof.

---

## Major decisions (short)

| Decision | Why you should care |
|----------|---------------------|
| Not forking AgentWatch | Old lab mixed SIMULATED proof and unwired flags |
| Two processes | You can see the trust boundary |
| Sequential four agents | Privilege increases without fake A2A |
| One input control first | Honest check-before-use |
| `run.id` | One hunt key |
| Two profiles | Fail-open is a labeled lesson |
| Thin first slice | You can explain the whole loop |

---

## What I should now be able to explain

1. What “agentic” means here versus a single chatbot.  
2. Why AcmeBank and Attack Service are separate.  
3. Why sequential agents are not A2A.  
4. Where the trust boundary is, and what the attacker controls.  
5. Why Ollama output cannot grant authority.  
6. Why Splunk is not a control.  
7. What DENY means, and why it cannot apply after a successful LLM call.  
8. What `run.id` is for, and why per-hop incident ids are a problem.  
9. Why SIMULATED events cannot prove a live control.  
10. What the first implementation includes (one baseline, one attack, one input control, two profiles) — and what it explicitly is not (MCP, A2A, RAG, memory, chains, MLTK, Cisco, 51 techniques).
