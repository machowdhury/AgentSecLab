# Framework Mapping Model

**Status:** PLANNED  
**Rule:** Verified mappings only. Mapping is not certification or compliance.

Do **not** use NIST SP 800-17. It is the wrong publication for this lab.

---

## Allowed frameworks

| Framework | Use in AgentSec |
|-----------|-----------------|
| NIST AI RMF | Functions (GOVERN, MAP, MEASURE, MANAGE) as educational tags |
| NIST SP 800-171 Rev. 3 | CUI-style requirement ids where a lab control truly maps |
| NIST SP 800-171A Rev. 3 | Assessment objectives for the same, when used |
| NIST SP 800-53 | Only where relevant and verified |
| MITRE ATLAS | Technique ids for attacks |
| OWASP LLM Top 10 | LLM risk categories |
| OWASP Agentic Security guidance | Agentic categories |
| CSA MAESTRO | Layer tags; optional later workshop with official tooling |

If a mapping cannot cite an official title and a reason, do not publish it.

---

## Mapping record (required fields)

Every published mapping document or lookup row:

| Field | Meaning |
|-------|---------|
| framework | From the allow-list |
| requirement/control identifier | Official id |
| official title | From the framework text |
| why it applies | One paragraph, lab-specific |
| AgentSec invariant | INV-00x |
| AgentSec test | Test path or “NOT YET TESTED” |
| evidence | OBSERVED / MEASURED / … |
| reference | Link or citation |

Lookups must not imply “pass = certified.”

---

## Phase 1 mappings

Phase 1 may ship **zero** Splunk framework dashboards.

A single markdown mapping is enough, for example:

| Attack | Invariant | OWASP LLM (educational) | ATLAS (if verified) |
|--------|-----------|-------------------------|---------------------|
| ATK-002 input DENY | INV-008 | LLM01-style injection teaching | Only if id verified against ATLAS |
| ATK-003 output inspect | honest placement | Output handling teaching | Only if verified |

Do not copy AgentWatch’s full NIST pass-rate fields until control tags exist and SPL is validated. AgentWatch `control.pass_rate_pct` was post-hoc scoring, not enforcement.

---

## Coverage vs mapping

| Idea | Meaning |
|------|---------|
| Technique coverage | Did we **attempt** a LIVE (or labeled SIMULATED) technique? |
| Detection | Did a **validated** search fire? |
| Control attestation | Did telemetry show a **control decision** with placement honesty? |
| Framework mapping | Educational crosswalk |

These four numbers must not be collapsed into one “compliance %.”

---

## Major decisions

### Decision: Allow-listed frameworks only; no 800-17

**DECISION:** List above. Explicit ban on NIST SP 800-17.

**ALTERNATIVES:** Map to every NIST SP that sounds security-related.

**WHY CHOSEN:** Project documentation rule. 800-17 is not an AI/CUI control catalog for this range.

**SECURITY CONSEQUENCE:** Stops bogus audit language.

**LEARNING VALUE:** Citation discipline.

### Decision: Mapping is a document + optional lookup, not a certificate

**DECISION:** UI copy must say educational / not certified.

**ALTERNATIVES:** “NIST AI RMF compliant” banners (AgentWatch risk).

**WHY CHOSEN:** Research integrity. Framework mapping ≠ compliance.

**SECURITY CONSEQUENCE:** Learners will not export a fake ATO.

**LEARNING VALUE:** GRC vs engineering evidence.

### Decision: No mapping row without an invariant and a test field

**DECISION:** Empty test ⇒ `NOT YET TESTED`, never a green pass.

**ALTERNATIVES:** Tag-only OTel like AgentWatch control_validator YAML.

**WHY CHOSEN:** Post-hoc tags are measurement, not proof.

**SECURITY CONSEQUENCE:** Attestation cannot go green on SIMULATED-only tags.

**LEARNING VALUE:** PROVE means a test or a MEASURED run.
