# AgentSec Splunk engineering governance

**Status:** IMPLEMENTED (process). Does not change runtime authorization, schema, validated SPL semantics, or workshop security conclusions.  
**Catalog:** https://splunkbase.splunk.com/skills

This is the discoverable entry point for future Cursor sessions.

---

## For Splunk knowledge-object work

Read:

`.cursor/rules/33-splunk-agent-skills.mdc`

then use:

`.cursor/skills/splunk-ko-review/SKILL.md`

and consult the applicable official Splunk Agent Skills (mapping in `.cursor/skills/splunk-ko-review/reference.md`).

Inventory:

`docs/SPLUNK_KNOWLEDGE_OBJECT_INVENTORY.md`

Companion SPL gate (still required):

`.cursor/rules/31-spl-validation.mdc`  
`.cursor/skills/spl-validate/SKILL.md`

## For learner-facing UI

Also read:

`.cursor/rules/32-ui-design-system.mdc`

and run:

`/ui-review`

## For evidence / security reasoning

Run:

`/logic-proof`

---

## Required method

Do **not** write SPL first and make the evidence fit later.

```text
SECURITY / OPERATIONAL QUESTION
→ EVIDENCE REQUIREMENT
→ VALIDATED TELEMETRY
→ INDEXED FIELD DISCOVERY
→ FIELD CONTRACT
→ KNOWLEDGE OBJECT DESIGN
→ SPL
→ SPL CORRECTNESS REVIEW
→ PERFORMANCE REVIEW
→ LIVE SPLUNK VALIDATION
→ DASHBOARD / DETECTION / WORKSHOP CONSUMER
```

Dashboard implementation order:

```text
FIELD CONTRACT
→ SPL REVIEW
→ SPLUNK KO REVIEW
→ LIVE VALIDATION
→ DASHBOARD IMPLEMENTATION
→ /ui-review
→ /logic-proof
```

---

## Future phase requirement

Every phase that creates or materially modifies SPL, saved searches, detections, alerts, field extractions, CIM mappings, data models, lookups, macros, Dashboard Studio data sources, or Splunk application configuration **must** include a **SPLUNK KNOWLEDGE OBJECT REVIEW** in its acceptance criteria.

Future phase prompts should explicitly say:

> Apply the AgentSec Splunk engineering rule and run splunk-ko-review for all new or materially changed Splunk knowledge objects.

Do not begin MCP-007, A2A, Cisco, MLTK, or another workshop from this document.
