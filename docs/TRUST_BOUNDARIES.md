# Trust Boundaries

**Status:** PLANNED  
**Applies to:** AgentSec architecture (`ARCHITECTURE.md`)

A trust boundary is where data or identity from a less-trusted side is used by a more-trusted side. Security checks belong **on the trusted side, before** the dangerous operation.

---

## Picture

```text
UNTRUSTED                          BOUNDARY              LAB-TRUSTED (not production)
─────────                          ────────              ───────────────────────────
Learner browser
Attack Service payloads  ──HTTP──► AcmeBank API ──► reference controls
Unknown JSON fields                  │                      │
                                     │                      ├── DENY/ERROR: stop
                                     │                      └── ALLOW: Ollama (UNTRUSTED MODEL)
Retrieved docs (later)               │                              │
SIMULATED content (later)            │                              ▼
                                     │                      model output is DATA, not authority
                                     ▼
                              OTel Collector / Splunk     OBSERVE ONLY
                              (cannot grant ALLOW)
```

---

## Zones

| Zone | Members | May authorize a loan/tool/LLM call? |
|------|---------|-------------------------------------|
| Untrusted client | Browser, Attack Service, any HTTP client | No |
| Enforcement | AcmeBank reference controls | Yes (lab policy only) |
| Untrusted model | Ollama | No |
| Observability | OTel Collector, Splunk, `artifacts/` | No |
| Optional overlay | Cisco scanners (later) | Only if a tested caller runs **before** the dangerous op |

“Lab-trusted” means AgentSec operators wrote the control code. It does **not** mean production-grade assurance.

---

## Major decisions

### Decision: The authorization boundary is the AcmeBank HTTP API

**DECISION:** Every legitimate request and every attack enters AcmeBank the same way. Controls run inside AcmeBank.

**ALTERNATIVES:** Controls in Attack Service; controls in Splunk; controls in Ollama system prompt only.

**WHY CHOSEN:** If Attack Service “helps” by skipping controls, learners never see a real boundary. Splunk and prompts are not enforcement.

**SECURITY CONSEQUENCE:** There is no second, privileged attack path. Bypass attempts must hit the same checks.

**LEARNING VALUE:** Same door, different intent — baseline vs attack.

### Decision: Attack Service is untrusted relative to AcmeBank

**DECISION:** Separate process. No shared in-memory bypass. No “god mode” header that disables controls unless the lab profile is `vulnerable` and that fact is in telemetry.

**ALTERNATIVES:** One process; shared Python import of `call_ollama` from the Attack Service.

**WHY CHOSEN:** A shared import makes the boundary fictional.

**SECURITY CONSEQUENCE:** INV-001/INV-006 cannot be silently skipped by the red-team UI.

**LEARNING VALUE:** Red team tooling is just another client.

### Decision: Ollama output cannot grant authority

**DECISION:** Model text is untrusted data (INV-002). It cannot flip a prior DENY, mint a `run.id`, or approve a tool.

**ALTERNATIVES:** “The model refused, so we are safe”; parse model JSON as a policy decision.

**WHY CHOSEN:** Small live models are inconsistent. Policy must be code.

**SECURITY CONSEQUENCE:** Jailbreak success is INJECTED/ALLOW/OBSERVE with telemetry, not a secret second policy engine.

**LEARNING VALUE:** LLMs are not security oracles.

### Decision: Splunk and OTel are outside the authorization boundary

**DECISION:** Telemetry may record ALLOW/DENY. It may not create them.

**ALTERNATIVES:** Saved searches that “quarantine” by writing back to the app; SOAR-as-control (dropped from AgentWatch).

**WHY CHOSEN:** Observation vs enforcement is the point of the SOC track.

**SECURITY CONSEQUENCE:** A detection firing is not a blocked call. Attestation UIs must not imply otherwise.

**LEARNING VALUE:** Detect, then defend, then retest.

### Decision: Phase 1 bind is localhost; no Attack Service auth

**DECISION:** Publish lab ports on localhost. Authentication for shared/cloud classrooms is PLANNED, not Phase 1.

**ALTERNATIVES:** API keys now; OAuth; expose `0.0.0.0/0`.

**WHY CHOSEN:** Smallest useful scope. AgentWatch cloud docs already showed public expose is dangerous.

**SECURITY CONSEQUENCE:** Anyone who can reach the port is an attacker. That is acceptable only on localhost.

**LEARNING VALUE:** Lab != production exposure model.

---

## What an attacker can and cannot control

**Can (untrusted):** payload text, target agent vs full pipeline, optional `technique_id` (allow-listed or ignored), extra JSON (rejected).

**Cannot (defended profile):** `run.id`, `security.profile`, model name, control allowlists, HEC token, Splunk admin.

**Vulnerable profile:** may omit checks; every fail-open must be labeled in telemetry (`security.profile=vulnerable`, reason set).

---

## Agent-to-agent handoff (Phase 1 residual)

Handoff is string concatenation of the previous agent’s output into the next prompt. That is **not** a new trust zone with cryptographic identity. It is still inside AcmeBank, still untrusted model text feeding the next LLM call.

Later A2A (PLANNED) would add an identity check at a new boundary. Until then, do not draw four network enclaves on a slide.
