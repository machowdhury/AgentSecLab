---
name: spl-validate
description: Validate AgentSec SPL against actual fields, representative data and expected results before publication or Dashboard Studio use.
disable-model-invocation: true
paths:
  - "splunk_app/**"
  - "detections/**"
  - "learning/**"
  - "research/**"
---

# SPL Validation

For the target SPL:

1. State the security question.
2. Identify raw fields available.
3. Verify required fields exist.
4. Show the SPL.
5. Explain every major command.
6. Explain why each command is necessary.
7. Run against representative data if available.
8. Show actual output.
9. Compare actual output to expected result.
10. Identify false positives.
11. Identify false negatives.
12. Identify performance issues.
13. Suggest a simpler/scalable alternative if appropriate.

Do not approve a search that was not tested.

If not tested label:

NOT YET VALIDATED.

Companion: for knowledge-object classification, CIM honesty, detection readiness, and official Splunk Agent Skills, also run `/splunk-ko-review` (`.cursor/skills/splunk-ko-review/SKILL.md`) after reading `.cursor/rules/33-splunk-agent-skills.mdc`. `/spl-validate` remains the SPL correctness gate; it does not replace KO review.
