# LAB-LOANDESK-001 knowledge check

## Questions

1. Which control decided whether the review note could be filed?
2. In the BASELINE attack policy said ALLOW. What does that tell you, and what does it not tell you?
3. What did the HARDENED posture change?
4. Which recorded event proves that a handler actually began?

## Answers

1. CTRL-LOANDESK-001, the policy engine inside AcmeBank. The model proposes and Splunk observes; neither decides.
2. The tool, scope and applicant were valid. It does not say the content was safe: BASELINE never checked the note.
3. The note must be exactly one reason code, otherwise the call is denied (`argument_not_allowed:note`) before its handler runs.
4. `agentsec.mcp.started`. A control decision of ALLOW only says the call was permitted.
