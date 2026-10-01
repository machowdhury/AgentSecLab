# Security semantics audit — new workshops

Checked the packets added after `8272c03`. CTRL-MCP-001 remains the only tool PDP in `authorize.py`. Schema stays 1.9.0. ExternalEvidence stays 1.0.0. None of the new reasons were added to the runtime authorizer.

Distinctions that the packets keep separate:

- identity claim and authentication
- authentication and authority
- delegation and authorization
- approval and authorization
- retrieval and authorization
- recall and authorization
- scanner finding and authorization
- evaluation result and authorization
- authorization and execution
- execution and completion
- completion and impact
- inventory and trust
- provenance and trust

Historical MCP resource decisions, CTRL-RAG-CONTEXT-001 observations, and CTRL-MEMORY-CONTEXT-001 observations are labeled as different planes. Empty Splunk results are labeled as not safety.

Not measured in this audit: browser layout, screen reader, clean-room install, and a repeated flake run of the full suite.
