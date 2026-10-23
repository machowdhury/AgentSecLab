# AgentSecLab — Security Framework Annotation Standard

**Status: requirement recorded, not implemented.** Nothing in the Academy, the SPL notebook or the tests implements it yet.
Implementation is gated: inventory first, define the metadata, annotate one Loan Desk detection, then **wait for owner approval before expanding**.

## Requirement
Every **detection-oriented** SPL must carry applicable, verified annotations from these frameworks, each with an official reference, the framework version, the mapping rationale and the detection limitations:

- MITRE ATLAS
- MITRE ATT&CK
- OWASP LLM Top 10 and OWASP Agentic AI threats
- NIST AI RMF and the NIST Generative AI Profile

Rules:
1. **No forced mappings.** If a framework has no honest fit, record "no applicable mapping" with the reason. Never pick the nearest label to fill a field.
2. **Verified.** Each mapping is checked against the framework's official publication (ID, name and version recorded, with a date checked). A mapping that cannot be verified is not shown.
3. **Exploratory SPL is exempt.** Searches that only look at data (counts, field discovery, timelines) need no detection annotation.
4. **Three different claims, never merged:**
   - **Attack mapping:** which framework technique or risk the lab's *attack* demonstrates.
   - **Detection coverage:** what the SPL *actually detects* in the recorded telemetry, and what it cannot (blind spots, evasions, assumptions about the schema).
   - **Risk and control alignment:** how the lab's *control* (for example CTRL-LOANDESK-001) relates to a framework risk or function. Alignment is not a claim that the risk is mitigated.
5. A detection that fires proves only that the recorded events matched the logic. It never implies the attack is impossible, and it never turns an indexed count into SPLUNK-VERIFIED.

## Where annotations must be visible in the Academy
- **At attack launch:** the attack mapping for the scenario being launched.
- **In the relevant SPL Workbench cells:** attack mapping, detection coverage with limitations, and control alignment, shown separately and only for detection-oriented cells.
- **In the Explain record:** the annotations for every detection cell the learner ran, next to the run IDs, the exact SPL and the verification status.

## Reusable metadata (to be defined in the first increment)
One record per detection, stored beside the template so the UI and the server read one source. Proposed fields (subject to the owner's review):

| Field | Meaning |
|---|---|
| `detection_id`, `template_id` | Stable identifiers; the template is a fixed server-side search |
| `kind` | `detection` or `exploratory` (exploratory carries no annotation) |
| `attack_mappings[]` | `framework`, `id`, `name`, `version`, `url`, `rationale` |
| `coverage` | `detects`, `limitations[]`, `telemetry_assumptions[]` |
| `control_alignments[]` | `framework`, `id`, `name`, `version`, `url`, `rationale`, `not_a_claim_of_mitigation: true` |
| `no_mapping[]` | `framework`, `reason` (the explicit "no honest fit" record) |
| `verified_on`, `verified_by` | Date and person who checked the official sources |

## Implementation sequence (approval required between steps 3 and 4)
1. Inventory every existing detection-oriented SPL (Academy notebook templates, Splunk app saved searches and dashboards, classic Academy searches).
2. Define the metadata schema above and where it lives.
3. Annotate **one** Loan Desk detection end to end (launch, cell, Explain record), with sources verified.
4. **Owner reviews. Only then** expand to other detections or exercises.

## Out of scope for now
Changing the UI, adding tests, annotating more than one detection, or expanding to other exercises.
