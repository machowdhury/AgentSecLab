# Agentic Architecture 101

AgentSec Phase 1 architecture is **PLANNED**. There is no running AgentSec app yet. This note teaches the design you will build against.

---

## WHAT IS IT?

An **agentic system** is software where an LLM can take steps: read a request, call a model, maybe call tools, maybe hand work to another agent, and produce an outcome (here, a loan-style decision).

AgentSec’s design is a **range**: a tiny bank (AcmeBank), an attack door (Attack Service), a live local model (Ollama), an evidence bus (OpenTelemetry), and a SOC (Splunk).

## WHY DOES IT EXIST?

If you only chat with one model, you miss the failures that happen on **surfaces**: tools, memory, retrieved documents, agent identity, and workflow order.

If you only draw architecture slides, you never see a control decision or a Splunk event.

AgentSec exists so you can run a normal request, run an attack, and **prove** what happened.

## HOW DOES IT WORK?

Four agents run **one after another in one process** (not four microservices):

1. Intake — customer-facing  
2. Document ingest  
3. Credit risk  
4. Compliance  

Each step: **check input → maybe call Ollama → inspect output → emit telemetry with the same `run.id`**.

The Attack Service only HTTP-calls AcmeBank. Splunk only reads events. Neither is a secret backdoor.

## WHERE DOES IT SIT IN AGENTSEC?

This is the **core**. Workshops, detections, MLTK, Cisco, and adapters sit **on top** later. They are not required to understand the picture.

## WHAT IS THE TRUST BOUNDARY?

The AcmeBank HTTP API. Everything the browser or Attack Service sends is untrusted. Ollama’s text is also untrusted. Splunk cannot approve a loan.

## WHAT COULD AN ATTACKER CONTROL?

The message, and which agent endpoint they hit. In the defended lab they cannot choose `run.id` or turn controls off.

## WHAT CAN GO WRONG?

- Injection that should have been DENY **before** the model.  
- Calling post-LLM cleanup “DENY” after the model already ran.  
- Mixing SIMULATED OTel with live proof.  
- Four “trust zones” on a slide when it is still one process pasting text between prompts.

## WHAT TELEMETRY SHOULD EXIST?

See `docs/SECURITY_EVENT_MODEL.md`: `run.id`, profile, `testbed_mode`, `control.decision`, `control.reason`, `operation.executed`.

## HOW WILL SPLUNK SHOW IT?

Phase 1: Search. `` `agentsec_index` run.id=<id> ``  
Later: workshop dashboards that quote those events, not invented stories.

## WHAT CONTROL COULD CHANGE THE RESULT?

Input DENY stops Ollama. Output SANITIZE/OBSERVE does not un-call Ollama. Splunk detections do not stop the call either.

## WHAT TEST PROVES THE LOGIC?

A stubbed LLM: malicious input → DENY → **zero** stub calls. That test does not exist until Phase 1 code exists. Architecture requires it.

---

## Major decisions (short)

| Decision | Why you should care |
|----------|---------------------|
| Not forking AgentWatch | Old lab mixed SIMULATED proof and unwired flags |
| Two processes | You can see the trust boundary |
| Sequential four agents | Privilege increases without fake A2A |
| `run.id` | One hunt key |
| Two profiles | Fail-open is a labeled lesson |
| Thin Phase 1 | You can explain the whole loop |

---

## What I should now be able to explain

1. What “agentic” means here versus a single chatbot.  
2. Why AcmeBank and Attack Service are separate.  
3. Why sequential agents are not A2A.  
4. Where the trust boundary is, and what the attacker controls.  
5. Why Ollama output cannot grant authority.  
6. Why Splunk is not a control.  
7. The difference between DENY and SANITIZE/OBSERVE.  
8. What `run.id` is for.  
9. Why SIMULATED events cannot prove a live control.  
10. What Phase 1 done means (one baseline, one attack, telemetry, artifacts, tests) — and what it explicitly is not (51 techniques, Cisco, MLTK).
