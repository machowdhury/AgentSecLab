---
name: dashboard-studio-review
description: Review AgentSec Splunk Dashboard Studio dashboards for technical correctness, usability, readability and teaching quality.
disable-model-invocation: true
paths:
  - "splunk_app/**"
---

# Dashboard Studio Review

Do not modify initially.

Review from four roles:

SPLUNK ARCHITECT
SOC ANALYST
UX DESIGNER
TECHNICAL INSTRUCTOR

Check:

1. Purpose obvious within 5 seconds.
2. Reading order obvious.
3. Grid alignment consistent.
4. Typography readable.
5. Professional color theme followed.
6. Severity not communicated by color alone.
7. Visualizations answer useful questions.
8. Every dataSource exists.
9. Every token exists.
10. JSON is valid.
11. Every SPL query is validated.
12. Every learner query has an explanation.
13. "What happened?" is derived from actual telemetry.
14. Empty/no-data states make sense.
15. Attack state works.
16. Defended state works.
17. A novice can follow the workflow.
18. An experienced practitioner still gains technical value.
19. Navigation is logical.
20. Terminology is consistent.

Classify findings:

BLOCKER
HIGH
MEDIUM
LOW

Create a review report.

Do not fix until findings are reviewed.
