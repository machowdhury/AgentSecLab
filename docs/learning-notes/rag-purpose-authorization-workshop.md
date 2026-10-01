# RAG purpose authorization

Retrieved content can be available and still be the wrong purpose. `doc.lending-policy.normal` is an existing fixture. This workshop does not add a vector database.

ATTACK and RETEST request purpose `executive-decision`. The allowed purpose is `applicant-education`. ATTACK uses the document anyway, as a labeled fail-open. RETEST does not use it. BASELINE requests the allowed purpose. None of those rows invoke CTRL-MCP-001.

Historical CTRL-RAG-CONTEXT-001 rows stay retrieved-context observations. They are not this purpose decision.

## What I should now be able to explain

1. Why is retrieved not authorized?
2. Why is an allowed purpose not a tool grant?
3. What is the same request in ATTACK and RETEST?
4. Why is similarity not authorization?
5. Why is CTRL-RAG-CONTEXT-001 a different plane?
6. Why is an empty purpose field not a denial?
7. Why is resource impact NOT PROVEN?
